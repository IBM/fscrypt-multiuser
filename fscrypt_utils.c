/*
Copyright 2023 IBM

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <syslog.h>
#include <stdio.h>

#include "fscrypt_utils.h"

#define DATA_FILE_HEADER_VALUE ("FSCRYPT_MULTIUSR")
#define DATA_FILE_HEADER_LENGTH (16)
#define DATA_FILE_SOR_VALUE ("SOR ")
#define DATA_FILE_SOR_LENGTH (4)
#define USER_ID_BYTES (MAX_USERNAME_BYTES)
#define DATA_FILE_FORMAT_VERSION (1)

#define ENTER_FUNCTION() fscrypt_utils_log(LOG_DEBUG, "Enter %s\n", __FUNCTION__)
#define EXIT_FUNCTION() fscrypt_utils_log(LOG_DEBUG, "Exit %s on line %d\n", __FUNCTION__, __LINE__)

char g_stored_data_path[PATH_MAX] = FSCRYPT_DEFAULT_DATA_PATH;
const char GLOBAL_DATA_LOCK[] = "/run/lock/fscrypt-multiuser.lock";


struct stored_user_data_t {
    uint8_t start_of_record[DATA_FILE_SOR_LENGTH];
    uint8_t identifier[USER_ID_BYTES];
    uint32_t iv_length;
    uint8_t iv[FSCRYPT_USER_KEK_BYTES];
    uint32_t wrapped_keylength;
    uint8_t wrapped_key[OPENSSL_KEK_UPDATE_MIN_BYTES];
};
struct stored_crypto_data_t {
    uint8_t file_header[DATA_FILE_HEADER_LENGTH];
    uint32_t version;
    uint32_t size;
    struct stored_user_data_t data[];
};

const size_t STORED_HEADER_SIZE = sizeof(struct stored_crypto_data_t);
const size_t STORED_ENTRY_SIZE = sizeof(struct stored_user_data_t);

void secure_free(void *ptr, size_t size)
{
    memset(*(uint8_t**)ptr, 0, size);
    free(*(void**)ptr);
    *(void**)ptr = NULL;
}

// Returns number of bytes decoded (expect FSCRYPT_KEY_BYTES on success)
size_t get_fscrypt_key(uint8_t fscrypt_key_out[FSCRYPT_KEY_BYTES], struct user_key_data_t *user_data);
void get_user_identifier(uint8_t result[USER_ID_BYTES], struct user_key_data_t *user_data);
struct stored_crypto_data_t *read_stored_data();
struct stored_user_data_t *locate_matching_user(struct stored_crypto_data_t *buffer, struct user_key_data_t *user_data);
int openssl_print_error(const char *str, size_t len, void *userdata);

enum fscrypt_utils_status_t lock_unlock_data_file(int lock);


enum fscrypt_utils_status_t fscrypt_utils_string_to_bytes(unsigned char *outbuf, char *in_string)
{
    for (size_t idx = 0; idx < strlen(in_string); idx += 2)
    {
        char nextdata[3] = "\0";
        memcpy(nextdata, &in_string[idx], 2);
        nextdata[2] = '\0';

        char *endptr = NULL;
        long next_byte = strtol(nextdata, &endptr, 16);
        if (*endptr != '\0')
        {
            fscrypt_utils_log(LOG_ERR, "error: %s is not a valid hexidecimal number\n", in_string);
            return FSCRYPT_UTILS_STATUS_ERROR;
        }
        outbuf[idx / 2] = next_byte & 0xff;
    }
    return FSCRYPT_UTILS_STATUS_OK;
}

char* fscrypt_utils_bytes_to_string(unsigned char *inbuf, size_t insize)
{
    char *result = (char*)calloc(insize * 2 + 1, 1);
    for (size_t idx = 0; idx < insize; idx++)
    {
        char this_byte[3] = "";
        snprintf(this_byte, 3, "%02x", inbuf[idx]);
        strcat(result, this_byte);
    }
    return result;
}

char *fscrypt_util_stored_data_path()
{
    char *env = getenv(FSCRYPT_SET_DATA_PATH_ENVVAR);
    {
        if (env != NULL)
        {
            strncpy(g_stored_data_path, env, sizeof(g_stored_data_path));
            g_stored_data_path[sizeof(g_stored_data_path) - 1] = '\0';
        }
    }
    return g_stored_data_path;
}

enum fscrypt_utils_status_t lock_unlock_data_file(int lock)
{
    ENTER_FUNCTION();

    const char *lock_path = GLOBAL_DATA_LOCK;

    int MAX_RETIRES = 10;
    int retries = 0;
    if (lock)
    {
        retries = MAX_RETIRES;
    }

    enum fscrypt_utils_status_t result = FSCRYPT_UTILS_STATUS_ERROR;
    do
    {
        if (retries != MAX_RETIRES && lock)
        {
            const struct timespec nsleep = {
                .tv_sec = 0,
                .tv_nsec = 100 * 1000 * 1000,
            };
            nanosleep(&nsleep, NULL);
        }
        FILE *fd = fopen(lock_path, "r");
        pid_t locked_pid = -1;
        if (fd != NULL)
        {
            char read_buf[32] = "";
            fread(read_buf, 1, sizeof(read_buf), fd);
            fclose(fd);
            locked_pid = atoi(read_buf);
            fscrypt_utils_log(LOG_INFO, "fscrypt database is locked by %d\n", locked_pid);
        }

        pid_t this_pid = getpid();
        if (lock)
        {
            if (locked_pid == this_pid)
            {
                fscrypt_utils_log(LOG_ERR, "error: %s Multiple calls to lock data file\n", lock_path);
                continue;
            }
            if (locked_pid != -1)
            {
                fscrypt_utils_log(LOG_ERR, "error: %s Data file is LOCKED by pid %d\n", lock_path, locked_pid);
                continue;
            }

            int fd_create = open(lock_path, O_WRONLY | O_CREAT | O_EXCL, 0);
            if (fd_create < 0)
            {
                fscrypt_utils_log(LOG_ERR, "error: %s Failed to open for writing\n", lock_path);
                continue;
            }
            fchmod(fd_create, 0666);
            dprintf(fd_create, "%d", this_pid);
            close(fd_create);
            fscrypt_utils_log(LOG_INFO, "created database lock for pid %d\n", this_pid);
        }
        else
        {
            if (locked_pid != this_pid)
            {
                fscrypt_utils_log(LOG_ERR, "error: %s Cannot unlock data file, locked by pid %d\n", lock_path, locked_pid);
                continue;
            }
        
            if (locked_pid == -1)
            {
                fscrypt_utils_log(LOG_ERR, "error: %s Attempted to unlock data file when not locked\n", lock_path);
                continue;
            }
            if (0 != unlink(lock_path))
            {
                fscrypt_utils_log(LOG_ERR, "error: %s Failed to remove lock\n", lock_path);
                continue;
            }
            fscrypt_utils_log(LOG_INFO, "successfully released database lock for pid %d\n", this_pid);
        }
        result = FSCRYPT_UTILS_STATUS_OK;
        break;
    } while (retries-- > 0);

    EXIT_FUNCTION();
    return result;
}


int syslog_flags = LOG_PID;
void fscrypt_utils_set_log_stderr(int is_stderr_enabled)
{
    if (is_stderr_enabled)
    {
        syslog_flags |= LOG_PERROR;
    }
    else
    {
        syslog_flags &= ~LOG_PERROR;
    }
}

void fscrypt_utils_set_log_min_priority(int min_priority)
{
    if (min_priority < LOG_EMERG || min_priority > LOG_DEBUG)
    {
        return;
    }
    int logmask = (1 << (min_priority + 1)) - 1;
    setlogmask(logmask);
}

void fscrypt_utils_log(int priority, const char *fmt, ...)
{
    openlog(FSCRYPT_UTILS_SYSLOG_ID, syslog_flags, LOG_USER);

    va_list argptr;
    va_start(argptr, fmt);
    vsyslog(priority, fmt, argptr);
    va_end(argptr);

    closelog();
}

int openssl_print_error(const char *str, size_t len, void *userdata)
{
    fscrypt_utils_log(LOG_ERR, str);
    return 0;
}


size_t fscrypt_utils_generate_random_key(uint8_t *keyout, size_t size)
{
    ENTER_FUNCTION();
    int rc = RAND_priv_bytes(keyout, size);
    if (rc != 1)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to generate random data\n", __LINE__);
        ERR_print_errors_cb(openssl_print_error, NULL);
        EXIT_FUNCTION(); return 0;
    }
    EXIT_FUNCTION(); return size;
}


size_t wrap_unwrap_key(struct crypto_context_t *crypto_context, uint8_t *outbuf, const uint8_t *indata, const size_t inlength, int encrypt)
{
    ENTER_FUNCTION();
    int rc;
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    if (context == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to create cipher context\n", __LINE__);
        ERR_print_errors_cb(openssl_print_error, NULL);
        EXIT_FUNCTION(); return 0;
    }

    EVP_CIPHER_CTX_set_flags(context, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    size_t data_length = 0;

    uint8_t wrap_unwrap_buffer[OPENSSL_KEK_UPDATE_MIN_BYTES] = {0};
    int outl = 0;

    rc = EVP_CipherInit_ex(context, EVP_aes_256_wrap(), NULL, crypto_context->unlock_key, crypto_context->iv, encrypt);
    if (rc != 1)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to initialize cipher context\n", __LINE__);
        ERR_print_errors_cb(openssl_print_error, NULL);
        goto end_crypto;
    }

    rc = EVP_CipherUpdate(context, wrap_unwrap_buffer, &outl, indata, inlength);
    data_length += outl;
    if (rc != 1)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to transform data\n", __LINE__);
        ERR_print_errors_cb(openssl_print_error, NULL);
        goto end_crypto;
    }

    rc = EVP_CipherFinal_ex(context, wrap_unwrap_buffer + outl, &outl);
    data_length += outl;
    if (rc != 1)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to finalize data transformation\n", __LINE__);
        ERR_print_errors_cb(openssl_print_error, NULL);
        goto end_crypto;
    }

end_crypto:
    EVP_CIPHER_CTX_free(context);
    context = NULL;

    memcpy(outbuf, wrap_unwrap_buffer, fscrypt_util_min(data_length, sizeof(wrap_unwrap_buffer)));
    memset(wrap_unwrap_buffer, 0, sizeof(wrap_unwrap_buffer));

    EXIT_FUNCTION(); return data_length;
}


void get_user_identifier(uint8_t result[USER_ID_BYTES], struct user_key_data_t *user_data)
{
    memset(result, 0, USER_ID_BYTES);
    memcpy(result, user_data->username, fscrypt_util_min(strlen(user_data->username), USER_ID_BYTES));
}


enum fscrypt_utils_status_t wrap_fscrypt_key(struct user_key_data_t *known_user, struct user_key_data_t *new_user, enum wrap_key_mode_t mode)
{
    ENTER_FUNCTION();
    uint8_t *fscrypt_key = (uint8_t*)calloc(FSCRYPT_KEY_BYTES, 1);
    if (known_user == NULL)
    {
        if (mode != KEY_MODE_DROP_TABLE)
        {
            secure_free(&fscrypt_key, FSCRYPT_KEY_BYTES);
            fscrypt_utils_log(LOG_ERR, "error: If a known_user is not supplied, you must use mode=KEY_MODE_DROP_TABLE\n");
            EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
        }
        if (FSCRYPT_KEY_BYTES != fscrypt_utils_generate_random_key(fscrypt_key, FSCRYPT_KEY_BYTES))
        {
            secure_free(&fscrypt_key, FSCRYPT_KEY_BYTES);
            EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
        }

    }
    else
    {
        if (FSCRYPT_KEY_BYTES != get_fscrypt_key(fscrypt_key, known_user))
        {
            secure_free(&fscrypt_key, FSCRYPT_KEY_BYTES);
            EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
        }
    }

    struct crypto_context_t *context = (struct crypto_context_t*)calloc(sizeof(struct crypto_context_t), 1);
    fscrypt_utils_generate_random_key(context->iv, sizeof(context->iv));
    memcpy(context->unlock_key, new_user->user_kek, FSCRYPT_USER_KEK_BYTES);

    uint8_t wrapped_key[OPENSSL_KEK_UPDATE_MIN_BYTES] = {0};
    size_t wrapped_size = wrap_unwrap_key(context, wrapped_key, fscrypt_key, FSCRYPT_KEY_BYTES, 1);

    secure_free(&fscrypt_key, FSCRYPT_KEY_BYTES);

    struct stored_crypto_data_t *data_buffer = NULL;
    struct stored_user_data_t *entry_buffer = NULL;

    if (FSCRYPT_UTILS_STATUS_OK != lock_unlock_data_file(1))
    {
        secure_free(&context, sizeof(*context));
        EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
    }

    switch (mode)
    {
        case KEY_MODE_DROP_TABLE:
            data_buffer = (struct stored_crypto_data_t*)calloc(STORED_HEADER_SIZE + STORED_ENTRY_SIZE, 1);
            if (data_buffer != NULL)
            {
                entry_buffer = data_buffer->data;
                data_buffer->size = 1;
            }
            break;
        case KEY_MODE_REPLACE_USER:
            data_buffer = read_stored_data();
            if (data_buffer != NULL)
            {
                entry_buffer = locate_matching_user(data_buffer, known_user);
            }
            break;
        case KEY_MODE_APPEND_USER:
            data_buffer = read_stored_data();
            if (data_buffer != NULL)
            {
                if (NULL != locate_matching_user(data_buffer, new_user))
                {
                    fscrypt_utils_log(LOG_ERR, "error: User %s already has a stored key\n", new_user->username);
                }
                else
                {
                    entry_buffer = &data_buffer->data[data_buffer->size];
                    data_buffer->size += 1;
                }
            }
            break;
    }

    if (data_buffer == NULL || entry_buffer == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to create/get data buffer\n", __LINE__);
        secure_free(&context, sizeof(*context));
        lock_unlock_data_file(0);
        EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
    }

    memcpy(data_buffer->file_header, DATA_FILE_HEADER_VALUE, DATA_FILE_HEADER_LENGTH);
    data_buffer->version = DATA_FILE_FORMAT_VERSION;
    get_user_identifier(entry_buffer->identifier, new_user);
    memcpy(entry_buffer->start_of_record, DATA_FILE_SOR_VALUE, DATA_FILE_SOR_LENGTH);
    entry_buffer->iv_length = sizeof(context->iv);
    memcpy(entry_buffer->iv, context->iv, sizeof(context->iv));
    entry_buffer->wrapped_keylength = wrapped_size;
    memcpy(entry_buffer->wrapped_key, wrapped_key, sizeof(wrapped_key));

    secure_free(&context, sizeof(*context));

    FILE *fd = fopen(fscrypt_util_stored_data_path(), "w");
    if (fd == NULL) {
        fscrypt_utils_log(LOG_ERR, "error: Failed to open for writing %s\n", fscrypt_util_stored_data_path());
        lock_unlock_data_file(0);
        EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
    }
    size_t data_size = STORED_HEADER_SIZE + STORED_ENTRY_SIZE * data_buffer->size;
    size_t bytes_written = fwrite(data_buffer, 1, data_size, fd);
    fclose(fd);

    free(data_buffer);

    lock_unlock_data_file(0);

    if (bytes_written != data_size)
    {
        fscrypt_utils_log(LOG_ERR, "error: Write failed n=%lu\n", bytes_written);
        EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
    }

    EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_OK;
}


struct stored_crypto_data_t *read_stored_data()
{
    ENTER_FUNCTION();
    FILE *fd = fopen(fscrypt_util_stored_data_path(), "r");
    if (fd == NULL) {
        fscrypt_utils_log(LOG_ERR, "error: Failed to open %s\n", fscrypt_util_stored_data_path());
        EXIT_FUNCTION(); return NULL;
    }

    struct stat filestat;
    if (0 != fstat(fileno(fd), &filestat))
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to get stat for %s\n", fscrypt_util_stored_data_path());
        fclose(fd);
        EXIT_FUNCTION(); return NULL;
    }
    size_t file_size = filestat.st_size;

    if ((file_size - STORED_HEADER_SIZE) % STORED_ENTRY_SIZE != 0)
    {
        fscrypt_utils_log(LOG_ERR, "error: Invalid file size %lu\n", file_size);
        fclose(fd);
        EXIT_FUNCTION(); return NULL;
    }

    size_t alloc_size = file_size + STORED_ENTRY_SIZE;
    uint8_t *data_buffer = (uint8_t*)calloc(alloc_size, 1);
    if (data_buffer == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "error: Allocate memory\n", __LINE__);
        EXIT_FUNCTION(); return NULL;
    }
    size_t read_size = fread(data_buffer, 1, file_size, fd);
    fclose(fd);

    if (read_size != file_size)
    {
        free(data_buffer);
        fscrypt_utils_log(LOG_ERR, "error: File read failed read_size=%lu, file_size=%lu\n", read_size, file_size);
        EXIT_FUNCTION(); return NULL;
    }

    struct stored_crypto_data_t* result = (struct stored_crypto_data_t*)data_buffer;
    if (memcmp(result->file_header, DATA_FILE_HEADER_VALUE, DATA_FILE_HEADER_LENGTH) != 0)
    {
        free(data_buffer);
        fscrypt_utils_log(LOG_ERR, "error: Invalid file header\n", __LINE__);
        EXIT_FUNCTION(); return NULL;
    }

    EXIT_FUNCTION(); return result;
}


struct stored_user_data_t *locate_matching_user(struct stored_crypto_data_t *buffer, struct user_key_data_t *user_data)
{
    ENTER_FUNCTION();
    struct stored_user_data_t *matching_user = NULL;
    uint8_t user_id[USER_ID_BYTES] = {0};
    get_user_identifier(user_id, user_data);
    for (size_t buf_idx = 0; buf_idx < buffer->size; buf_idx++)
    {
        struct stored_user_data_t *current_entry = &buffer->data[buf_idx];
        if (memcmp(current_entry->start_of_record, DATA_FILE_SOR_VALUE, DATA_FILE_SOR_LENGTH) != 0)
        {
            fscrypt_utils_log(LOG_ERR, "error: failed to find Start of Record in %s at offset=%lu\n", fscrypt_util_stored_data_path(), buf_idx);
            break;
        }
        if (0 == memcmp(current_entry->identifier, user_id, USER_ID_BYTES))
        {
            matching_user = current_entry;
            break;
        }
    }
    if (matching_user == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "error: No existing key found for user '%s'\n", user_data->username);
    }
    EXIT_FUNCTION(); return matching_user;

}


size_t get_fscrypt_key(uint8_t fscrypt_key_out[FSCRYPT_KEY_BYTES], struct user_key_data_t *user_data)
{
    ENTER_FUNCTION();
    if (FSCRYPT_UTILS_STATUS_OK != lock_unlock_data_file(1))
    {
        EXIT_FUNCTION(); return 0;
    }

    struct stored_crypto_data_t *data_buffer = read_stored_data();
    lock_unlock_data_file(0);
    if (data_buffer == NULL)
    {
        EXIT_FUNCTION(); return 0;
    }
    struct stored_user_data_t *stored_data = locate_matching_user(data_buffer, user_data);
    if (stored_data == NULL)
    {
        free(data_buffer);
        EXIT_FUNCTION(); return 0;
    }

    struct crypto_context_t *context = (struct crypto_context_t*)calloc(sizeof(struct crypto_context_t), 1);
    memcpy(context->unlock_key, user_data->user_kek, FSCRYPT_USER_KEK_BYTES);
    memcpy(context->iv, stored_data->iv, FSCRYPT_USER_KEK_BYTES);
    size_t outsize = wrap_unwrap_key(context, fscrypt_key_out, stored_data->wrapped_key, stored_data->wrapped_keylength, 0);

    memset(context, 0, sizeof(*context));
    free(context);
    free(data_buffer);
    context = NULL;
    data_buffer = NULL;

    EXIT_FUNCTION(); return outsize;
}


enum fscrypt_utils_status_t fscrypt_add_key(uint8_t fscrypt_key_id_out[FSCRYPT_KEY_ID_BYTES], const char *mountpoint, struct user_key_data_t *known_user)
{
    ENTER_FUNCTION();
    uint8_t *fscrypt_key = (uint8_t*)calloc(FSCRYPT_KEY_BYTES, 1);
    if (FSCRYPT_KEY_BYTES != get_fscrypt_key(fscrypt_key, known_user))
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to get fscrypt key\n", __LINE__);
        EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
    }

    int fd = open(mountpoint, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to open mountpoint %s\n", mountpoint);
        EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
    }

    struct fscrypt_add_key_arg *add_key_args = (struct fscrypt_add_key_arg*)calloc(sizeof(*add_key_args) + FSCRYPT_KEY_BYTES, 1);
    add_key_args->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    add_key_args->raw_size = FSCRYPT_KEY_BYTES;
    memcpy(add_key_args->raw, fscrypt_key, FSCRYPT_KEY_BYTES);

    memset(fscrypt_key, 0, FSCRYPT_KEY_BYTES);
    free(fscrypt_key);
    fscrypt_key = NULL;

    int rc = ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, add_key_args);
    close(fd);
    enum fscrypt_utils_status_t func_return_code;
    if (rc != 0)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to add key errno=%d\n", errno);
        func_return_code = FSCRYPT_UTILS_STATUS_ERROR;
    }
    else if (fscrypt_key_id_out != NULL)
    {
        memcpy(fscrypt_key_id_out, add_key_args->key_spec.u.identifier, FSCRYPT_KEY_ID_BYTES);
        func_return_code = FSCRYPT_UTILS_STATUS_OK;
    }

    memset(add_key_args, 0, sizeof(*add_key_args));
    free(add_key_args);
    EXIT_FUNCTION(); return func_return_code;
}

enum fscrypt_utils_status_t fscrypt_set_policy(const char *mountpoint, const char *directory, struct user_key_data_t *known_user)
{
    ENTER_FUNCTION();
    uint8_t key_id[FSCRYPT_KEY_ID_BYTES] = {0};
    if (FSCRYPT_UTILS_STATUS_OK != fscrypt_add_key(key_id, mountpoint, known_user))
    {
        EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
    }

    int fd = open(directory, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to open directory %s\n", directory);
        EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
    }

    struct fscrypt_policy_v2 policy;
    memset(&policy, 0, sizeof(policy));
    policy.version = FSCRYPT_POLICY_V2;
    policy.contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS;
    policy.filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS;
    policy.flags = FSCRYPT_POLICY_FLAGS_PAD_32;
    memcpy(policy.master_key_identifier, key_id, FSCRYPT_KEY_ID_BYTES);

    int rc = ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy);
    close(fd);
    if (rc != 0)
    {
        fscrypt_utils_log(LOG_ERR, "error: Failed to set policy errno=%d\n", errno);
        EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_ERROR;
    }

    EXIT_FUNCTION(); return FSCRYPT_UTILS_STATUS_OK;
}