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

#include "fscrypt_utils.h"

enum actions_t {
    ACTION_INVALID,
    ACTION_INIT_NEW_KEY,
    ACTION_INIT_WITH_REWRAP,
    ACTION_REWRAP_ONE,
    ACTION_ADD_KEY,
    ACTION_UNLOCK,
    ACTION_ENCRYPT,
};

void string_to_bytes(unsigned char *outbuf, char *hash_string)
{
    for (size_t idx = 0; idx < strlen(hash_string); idx += 2)
    {
        char nextdata[3] = "\0";
        memcpy(nextdata, &hash_string[idx], 2);
        nextdata[2] = '\0';
        long next_byte = strtol(nextdata, NULL, 16);
        outbuf[idx / 2] = next_byte & 0xff;
    }
}

int main(int argc, char **argv)
{
    fscrypt_utils_set_log_stderr(1);

    enum actions_t action = ACTION_INVALID;

    if (argc < 2) { }
    else if (0 == strcmp("create_key", argv[1]) && argc == 4) { action = ACTION_INIT_NEW_KEY;}
    else if (0 == strcmp("rewrap_init", argv[1]) && argc == 6) { action = ACTION_INIT_WITH_REWRAP;}
    else if (0 == strcmp("change_key", argv[1]) && argc == 6) { action = ACTION_REWRAP_ONE;}
    else if (0 == strcmp("add_key", argv[1]) && argc == 6) { action = ACTION_ADD_KEY;}
    else if (0 == strcmp("encrypt", argv[1]) && argc == 5) { action = ACTION_ENCRYPT;}
    else if (0 == strcmp("unlock", argv[1]) && argc == 4) { action = ACTION_UNLOCK;}

    if (action == ACTION_INVALID) {
        fprintf(stderr,
            "ERROR: Invalid action, or incorrect number of arguments\n"
            "\n"
            "Usage: fscrypt_setup [action] [action_options]\n"
            "\n"
            "fscrypt_setup create_key [new_user] [new_hash]\n"
            "    Discard any existing keys and create a new fscrypt key with the specified hash.\n"
            "fscrypt_setup rewrap_init [known_user] [known_hash] [new_user] [new_hash]\n"
            "    Rewrap the fscrypt key with the user's credentials. Discard all other wrapped keys.\n"
            "fscrypt_setup change_key [known_user] [known_hash] [new_user] [new_hash]\n"
            "    Replace new_user's key in-place.\n"
            "fscrypt_setup add_key [known_user] [known_hash] [new_user] [new_hash]\n"
            "    Append a new user by rewrapping an existing user's key.\n"
            "fscrypt_setup encrypt [known_user] [known_hash] [directory]\n"
            "    Encrypt the specified directory. This directory must be empty.\n"
            "fscrypt_setup unlock [known_user] [known_hash]\n"
            "    Unlock the specified user's key.\n"
            "\n"
            "DATABASE FILE:\n"
            "    To configure the database file, set the environment variable " FSCRYPT_SET_DATA_PATH_ENVVAR "\n"
            "    Default value: " FSCRYPT_DEFAULT_DATA_PATH "\n"
        );
        return 1;
    }

    if (strlen(argv[3]) != (2 * FSCRYPT_USER_KEK_BYTES))
    {
        fprintf(stderr, "Argument 2 expected length %d\n", 2 * FSCRYPT_USER_KEK_BYTES);
        return 1;
    }

    struct user_key_data_t userdata_a;
    struct user_key_data_t userdata_b;
    memset(&userdata_a, 0, sizeof(userdata_a));
    memset(&userdata_b, 0, sizeof(userdata_b));
    char *encrypt_dir = NULL;
    strcpy(userdata_a.username, argv[2]);
    string_to_bytes(userdata_a.user_kek, argv[3]);

    if (action == ACTION_INIT_WITH_REWRAP || action == ACTION_ADD_KEY)
    {
        if (strlen(argv[5]) != (2 * FSCRYPT_USER_KEK_BYTES))
        {
            fprintf(stderr, "Argument 2 expected length %d\n", 2 * FSCRYPT_USER_KEK_BYTES);
            return 1;
        }
        strcpy(userdata_b.username, argv[4]);
        string_to_bytes(userdata_b.user_kek, argv[5]);
    }
    if (action == ACTION_ENCRYPT)
    {
        encrypt_dir = argv[4];
    }


    int rc = 1;
    switch(action)
    {
        case ACTION_INIT_NEW_KEY:
        {
            char *data_path = fscrypt_util_stored_data_path();
            if (access(data_path, F_OK) == 0)
            {
                fprintf(stderr, "ERROR: data file already exists: %s\n", data_path);
                fprintf(stderr, "This operation would destroy the file's existing data.\n");
                fprintf(stderr, "Backup or remove it before running this operation.\n");
            }
            else
            {
                rc = wrap_fscrypt_key(NULL, &userdata_a, KEY_MODE_DROP_TABLE);
            }
            break;
        }
        case ACTION_INIT_WITH_REWRAP:
        {
            rc = wrap_fscrypt_key(&userdata_a, &userdata_b, KEY_MODE_DROP_TABLE);
            break;
        }
        case ACTION_REWRAP_ONE:
        {
            rc = wrap_fscrypt_key(&userdata_a, &userdata_b, KEY_MODE_REPLACE_USER);
            break;
        }
        case ACTION_ADD_KEY:
        {
            rc = wrap_fscrypt_key(&userdata_a, &userdata_b, KEY_MODE_APPEND_USER);
            break;
        }
        case ACTION_UNLOCK:
        {
            uint8_t key_id[FSCRYPT_KEY_ID_BYTES] = {0};
            rc = fscrypt_add_key(key_id, "/", &userdata_a);
            printf("key_id=");
            for (size_t idx = 0; idx < sizeof(key_id); idx++)
            {
                printf("%02x", key_id[idx]);
            }
            printf("\n");
            break;
        }
        case ACTION_ENCRYPT:
        {
            rc = fscrypt_set_policy("/", encrypt_dir, &userdata_a);
        }
        case ACTION_INVALID:
            break;
    }

    memset(&userdata_a, 0, sizeof(userdata_a));
    memset(&userdata_b, 0, sizeof(userdata_b));

    return rc;
}