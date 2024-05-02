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

#ifndef __FSCRYPT_UTILS_H__
#define __FSCRYPT_UTILS_H__

#include <stdint.h>
#include "fscrypt_defines.h"
#include "constants.h"
#include "hasher.h"

struct crypto_context_t {
    uint8_t unlock_key[FSCRYPT_USER_KEK_BYTES];
    uint8_t iv[FSCRYPT_USER_KEK_BYTES];
};

struct user_key_data_t {
    uint8_t user_kek[FSCRYPT_USER_KEK_BYTES];
    char username[MAX_USERNAME_BYTES];
};

enum wrap_key_mode_t {
    KEY_MODE_DROP_TABLE,
    KEY_MODE_REPLACE_USER,
    KEY_MODE_APPEND_USER,
};

enum fscrypt_utils_status_t {
    FSCRYPT_UTILS_STATUS_OK = 0,
    FSCRYPT_UTILS_STATUS_ERROR = 1
};

char *fscrypt_util_stored_data_path(void);

enum fscrypt_utils_status_t fscrypt_utils_string_to_bytes(unsigned char *outbuf, char *hash_string);
// Result must be free()'d when done
char* fscrypt_utils_bytes_to_string(unsigned char *inbuf, size_t insize);

void fscrypt_utils_log(int priority, const char *fmt, ...);
void fscrypt_utils_set_log_stderr(int is_stderr_enabled);
void fscrypt_utils_set_log_min_priority(int min_priority);

enum fscrypt_utils_status_t wrap_fscrypt_key(struct user_key_data_t *known_user, struct user_key_data_t *new_user, enum wrap_key_mode_t mode);
enum fscrypt_utils_status_t fscrypt_add_key(uint8_t fscrypt_key_id_out[FSCRYPT_KEY_ID_BYTES], const char *mountpoint, struct user_key_data_t *known_user);
enum fscrypt_utils_status_t fscrypt_set_policy(const char *mountpoint, const char *directory, struct user_key_data_t *known_user);

// Returns number of bytes in keyout
size_t fscrypt_utils_generate_random_key(uint8_t *keyout, size_t size);

// Returns number of bytes in outbuf
size_t wrap_unwrap_key(struct crypto_context_t *crypto_context, uint8_t *outbuf, const uint8_t *indata, const size_t inlength, int encrypt);

#endif  // __FSCRYPT_UTILS_H__