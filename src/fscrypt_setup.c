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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "fscrypt_utils.h"
#include "BUILD_PARAMS.h"

const char *HELP_MESSAGE = ""
    "Build version: " BUILD_FULL_VERSION_STR "\n"
    "Usage: fscrypt_setup [storage_target] [action] [action_options]\n"
    "\n"
    "fscrypt_setup create_key [storage_target] [new_user] [new_kek]\n"
    "    Discard any existing keys and create a new fscrypt key with the specified kek.\n"
    "fscrypt_setup rewrap_init [storage_target] [known_user] [known_kek] [new_user] [new_kek]\n"
    "    Rewrap the fscrypt key with the user's credentials. Discards all other wrapped keys,\n"
    "    including known_user if new_user and known_user are different.\n"
    "fscrypt_setup add_key [storage_target] [known_user] [known_kek] [new_user] [new_kek]\n"
    "    Append a new user by rewrapping an existing user's key.\n"
    "    This operation will fail if new_user is already present in the database.\n"
    "fscrypt_setup change_key [storage_target] [known_user] [known_kek] [change_user] [change_kek]\n"
    "    Replace new_user's key in-place. known_user and new_user can optionally be the same.\n"
    "    This operation will fail if new_user is absent from the database.\n"
    "fscrypt_setup encrypt [storage_target] [known_user] [known_kek] [directory]\n"
    "    Encrypt the specified directory. This directory must be empty.\n"
    "fscrypt_setup unlock [directory_path] [known_user] [known_kek]\n"
    "    Unlock the specified user's key for all encrypted directories under mount_point.\n"
    "    mount_point can optionally be any subdirectory, provided it is on the same fs as the target mount point.\n"
    "\n"
    "\n"
    "Where 'storage_target' is specified, either the path to a database file, or a path to a directory can\n"
    " be provided. If a database file is provided, it will be used directly. If a directory is provided,\n"
    " the matching database will be looked up on the fscrypt-multiuser configuration file.\n"
    " In the case of 'unlock', if a database is provided, the filesystem key will be added to \n"
    " all associated mount points.\n"
    "VERBOSE LOGGING:\n"
    "    To enable verbose logging, set the VERBOSE environment variable to any non-empty string\n"
;

enum actions_t {
    ACTION_INVALID,
    ACTION_INIT_NEW_KEY,
    ACTION_INIT_WITH_REWRAP,
    ACTION_REWRAP_ONE,
    ACTION_ADD_KEY,
    ACTION_UNLOCK,
    ACTION_ENCRYPT,
};

struct args_struct_t {
    const char *exe;
    const char *action;
    const char *mount_or_db;
    const char *user1;
    const char *kek1;
    const char *user2;
    const char *kek2;
};
#define arg_idx(arg) ()


#define FSCRYPT_SET_DATA_PATH_ENVVAR "FSCRYPT_MULTIUSER_DATA_PATH"

int main(int argc, char **argv)
{
    fscrypt_utils_set_log_stderr(1);
    fscrypt_utils_set_log_min_priority(4);  // LOG_WARNING

    char *env_verbose = getenv("VERBOSE");
    if (env_verbose != NULL && env_verbose[0] != '\0')
    {
        fscrypt_utils_set_log_min_priority(7);
    }

    enum actions_t action = ACTION_INVALID;
    const struct args_struct_t *args = (const struct args_struct_t*)argv;
    int expect_argc = 0;

    int has_user2 = 0;

    if (argc < 2) {}
    else if (0 == strcmp("create_key", args->action))
    {
        action = ACTION_INIT_NEW_KEY;
        expect_argc = 1 + offsetof(struct args_struct_t, kek1) / sizeof(void*);
    }
    else if (0 == strcmp("rewrap_init", args->action))
    {
        action = ACTION_INIT_WITH_REWRAP;
        expect_argc = 1 + offsetof(struct args_struct_t, kek2) / sizeof(void*);
        has_user2 = 1;
    }
    else if (0 == strcmp("add_key", args->action))
    {
        action = ACTION_ADD_KEY;
        expect_argc = 1 + offsetof(struct args_struct_t, kek2) / sizeof(void*);
        has_user2 = 1;
    }
    else if (0 == strcmp("change_key", args->action))
    {
        action = ACTION_REWRAP_ONE;
        expect_argc = 1 + offsetof(struct args_struct_t, kek2) / sizeof(void*);
        has_user2 = 1;
    }
    else if (0 == strcmp("encrypt", args->action))
    {
        action = ACTION_ENCRYPT;
        expect_argc = 1 + offsetof(struct args_struct_t, kek1) / sizeof(void*);
    }
    else if (0 == strcmp("unlock", args->action))
    {
        action = ACTION_UNLOCK;
        expect_argc = 1 + offsetof(struct args_struct_t, kek1) / sizeof(void*);
    }

    if ((action == ACTION_INVALID) || (expect_argc != argc)) {
        fprintf(stderr, "ERROR: Invalid action, or incorrect number of arguments\n\n%s", HELP_MESSAGE);
        return 1;
    }

    const char *cryptdata_path = args->mount_or_db;
    struct stat db_stat;
    if (stat(args->mount_or_db, &db_stat) == 0)
    {
        if (db_stat.st_mode & S_IFDIR)
        {
            // Input is a directory
            cryptdata_path = fscrypt_utils_get_cryptdata_path(args->mount_or_db);
        }
    }
    else if (args->mount_or_db[0] != '/')
    {
        fprintf(stderr, "ERROR: mount_or_db must be a path\n\n%s", HELP_MESSAGE);
        return 1;
    }

    struct user_key_data_t userdata_1;
    struct user_key_data_t userdata_2;
    memset(&userdata_1, 0, sizeof(userdata_1));
    memset(&userdata_2, 0, sizeof(userdata_2));
    strcpy(userdata_1.username, args->user1);
    size_t convert_rc;
    convert_rc = fscrypt_utils_string_to_bytes(userdata_1.user_kek, sizeof(userdata_1.user_kek), args->kek1);
    if (convert_rc == 0)
    {
        fprintf(stderr, "ERROR: (kek1) Failed to convert argument to bytes: %s\n", args->kek1);
        return 1;
    }
    else if (convert_rc != FSCRYPT_USER_KEK_BYTES)
    {
        fprintf(stderr, "ERROR: (kek1) Expected argument to be %d bytes long (has: %lu) %s\n", FSCRYPT_USER_KEK_BYTES, convert_rc, args->kek1);
        return 1;
    }

    if (has_user2)
    {
        strcpy(userdata_2.username, args->user2);
        convert_rc = fscrypt_utils_string_to_bytes(userdata_2.user_kek, sizeof(userdata_2.user_kek), args->kek2);
        if (convert_rc == 0)
        {
            fprintf(stderr, "ERROR: (kek2) Failed to convert argument to bytes: %s\n", args->kek1);
            return 1;
        }
        else if (convert_rc != FSCRYPT_USER_KEK_BYTES)
        {
            fprintf(stderr, "ERROR: (kek2) Expected argument to be %d bytes long (has: %lu) %s\n", FSCRYPT_USER_KEK_BYTES, convert_rc, args->kek1);
            return 1;
        }
    }

    enum fscrypt_utils_status_t rc = FSCRYPT_UTILS_STATUS_ERROR;
    switch(action)
    {
        case ACTION_INIT_NEW_KEY:
        {
            if (access(cryptdata_path, F_OK) == 0)
            {
                fprintf(stderr, "ERROR: data file already exists: %s\n", cryptdata_path);
                fprintf(stderr, "This operation would destroy the file's existing data.\n");
                fprintf(stderr, "Backup or remove it before running this operation.\n");
            }
            else
            {
                rc = wrap_fscrypt_key(NULL, &userdata_1, KEY_MODE_DROP_TABLE, cryptdata_path);
            }
            break;
        }
        case ACTION_INIT_WITH_REWRAP:
        {
            rc = wrap_fscrypt_key(&userdata_1, &userdata_2, KEY_MODE_DROP_TABLE, cryptdata_path);
            break;
        }
        case ACTION_REWRAP_ONE:
        {
            rc = wrap_fscrypt_key(&userdata_1, &userdata_2, KEY_MODE_REPLACE_USER, cryptdata_path);
            break;
        }
        case ACTION_ADD_KEY:
        {
            rc = wrap_fscrypt_key(&userdata_1, &userdata_2, KEY_MODE_APPEND_USER, cryptdata_path);
            break;
        }
        case ACTION_UNLOCK:
        {
            const char *mounts_to_unlock[FSCRYPT_UTILS_MAX_MOUNTPOINTS+1] = {NULL};
            if (cryptdata_path == args->mount_or_db)
            {
                // User provided database path
                struct fscrypt_util_config_t *config = fscrypt_utils_load_config();
                if (config == NULL)
                {
                    fprintf(stderr, "Failed to load fscrypt-multiuser configuration file\n");
                    return 1;
                }
                const char **current = &mounts_to_unlock[0];
                for (size_t idx = 0; idx < config->mountpoint_count; idx++)
                {
                    if (0 == strcmp(config->datafiles[idx], args->mount_or_db))
                    {
                        *current = config->mountpoints[idx];
                        current++;
                    }
                }
            }
            else
            {
                // User provided mount point
                mounts_to_unlock[0] = args->mount_or_db;
            }
            const char **next_mount = &mounts_to_unlock[0];
            do
            {
                uint8_t key_id[FSCRYPT_KEY_ID_BYTES] = {0};
                rc = fscrypt_add_key(key_id, *next_mount, &userdata_1);
                printf("mount=%s, key_id=", *next_mount);
                for (size_t idx = 0; idx < sizeof(key_id); idx++)
                {
                    printf("%02x", key_id[idx]);
                }
                printf("\n");
                next_mount++;
            } while (*next_mount != NULL);
            break;
        }
        case ACTION_ENCRYPT:
        {
            rc = fscrypt_set_policy(args->mount_or_db, &userdata_1);
        }
        case ACTION_INVALID:
            break;
    }

    memset(&userdata_1, 0, sizeof(userdata_1));
    memset(&userdata_2, 0, sizeof(userdata_2));

    return (rc != FSCRYPT_UTILS_STATUS_OK);
}