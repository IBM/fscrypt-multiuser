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

// #define PAM_SM_AUTH

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "fscrypt_utils.h"
#include "fscrypt_pam_hook.h"
#include "BUILD_PARAMS.h"

#define MAX_MOUNTPOINTS (32)
#define MAX_DATAFILES (32)


enum pam_fscrypt_source_func {
    SOURCE_FUNCTION_AUTH = 0x1,
    SOURCE_FUNCTION_PASSWORD = 0x2,
    SOURCE_FUNCTION_ALL = 0x3,
};

struct pam_fscrypt_parameters {
    int loglevel;
    const char* system_mountpoints[MAX_MOUNTPOINTS];
    size_t system_mount_count;
    const char* datapaths[MAX_DATAFILES];
    size_t datapath_count;
    const char* post_hook;
    const char* hook_userarg;
};

void pam_fscrypt_parse_arguments(enum pam_fscrypt_source_func source, int argc, const char **argv, struct pam_fscrypt_parameters *result);


void pam_fscrypt_parse_arguments(enum pam_fscrypt_source_func source, int argc, const char **argv, struct pam_fscrypt_parameters *result)
{
    const char* const DEFAULT_MOUNTPOINT = "/";

    fscrypt_utils_set_log_stderr(0);
    int default_loglevel;
#ifdef DEBUG_BUILD
    default_loglevel = 6;  // LOG_INFO
#else
    default_loglevel = 4;  // LOG_WARNING
#endif
    fscrypt_utils_set_log_min_priority(default_loglevel);

    result->loglevel = default_loglevel;
    result->system_mountpoints[0] = NULL;
    result->system_mount_count = 0;
    result->datapaths[0] = NULL;
    result->datapath_count = 0;
    result->post_hook = NULL;
    result->hook_userarg = NULL;

    for (int idx = 0; idx < argc; idx++)
    {
        fscrypt_utils_log(LOG_DEBUG, "argv[%d] = %s\n", idx, argv[idx]);
        const char *value = strchr(argv[idx], '=');
        if (value == NULL)
        {
            fscrypt_utils_log(LOG_WARNING, "Invalid paramter %s\n", argv[idx]);
            continue;
        }
        value++;  // Increment past the '=' character

        if ((source & SOURCE_FUNCTION_ALL) && argv[idx] == strstr(argv[idx], "loglevel="))
        {
            char *endptr = NULL;
            long loglevel = strtol(value, &endptr, 0);
            if (*endptr == '\0' && loglevel >= LOG_EMERG && loglevel <= LOG_DEBUG)
            {
                result->loglevel = (int)loglevel;
                fscrypt_utils_set_log_min_priority(result->loglevel);
                fscrypt_utils_log(LOG_NOTICE, "syslog level set to %d\n", result->loglevel);
            }
            else
            {
                fscrypt_utils_log(LOG_WARNING, "Invalid value for loglevel: %s\n", value);
            }
        }
        else if ((source & SOURCE_FUNCTION_ALL) && argv[idx] == strstr(argv[idx], "data-path="))
        {
            if (result->datapath_count >= MAX_DATAFILES)
            {
                fscrypt_utils_log(LOG_ERR, "Exceeded max number of data paths. Ignoring %s\n", value);
            }
            else
            {
                result->datapaths[result->datapath_count] = value;
                fscrypt_utils_log(LOG_NOTICE, "Using datapath[%d] = %s\n", result->datapath_count, value);
                result->datapath_count++;
            }
        }
        else if ((source & SOURCE_FUNCTION_AUTH) && argv[idx] == strstr(argv[idx], "post-hook="))
        {
            result->post_hook = value;
            fscrypt_utils_log(LOG_NOTICE, "Using post-hook module %s\n", result->post_hook);
        }
        else if ((source & SOURCE_FUNCTION_AUTH) && argv[idx] == strstr(argv[idx], "hook-arg="))
        {
            result->hook_userarg = value;
            fscrypt_utils_log(LOG_NOTICE, "Using hook parameter %s\n", result->hook_userarg);
        }
        else if ((source & SOURCE_FUNCTION_AUTH) && argv[idx] == strstr(argv[idx], "mount="))
        {
            if (result->system_mount_count >= MAX_MOUNTPOINTS)
            {
                fscrypt_utils_log(LOG_ERR, "Exceeded max number of mountpoints. Ignoring %s\n", value);
            }
            else
            {
                result->system_mountpoints[result->system_mount_count] = value;
                fscrypt_utils_log(LOG_NOTICE, "Using mountpoint[%d] = %s\n", result->system_mount_count, value);
                result->system_mount_count++;
            }
        }
        else
        {
            fscrypt_utils_log(LOG_WARNING, "Got extra unused parameter: %s\n", argv[idx]);
        }
    }

    if (result->system_mount_count == 0)
    {
        fscrypt_utils_log(LOG_NOTICE, "No mountpoints specified. Using default: %s\n", DEFAULT_MOUNTPOINT);
        result->system_mountpoints[0] = DEFAULT_MOUNTPOINT;
        result->system_mount_count = 1;
    }

    if (result->datapath_count == 0)
    {
        fscrypt_utils_log(LOG_NOTICE, "No datapaths specified. Using: %s\n", fscrypt_util_stored_data_get_path());
    }

    fscrypt_utils_log(LOG_INFO, "Build version %s\n", BUILD_FULL_VERSION_STR);
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct pam_fscrypt_parameters args;
    pam_fscrypt_parse_arguments(SOURCE_FUNCTION_AUTH, argc, argv, &args);
    fprintf(stderr, "args.loglevel=%d\n", args.loglevel);

    fscrypt_utils_log(LOG_DEBUG, "Starting pam_sm_authenticate flags=%d\n", flags);

    // List of services which authenticate for non-login purposes.
    // It doesn't strictly hurt to add keys during these operations
    // but it's a minor optimazation to skip since unlocking during a
    // 'sudo' or similar serves no purpose.
    // Considering removing this section and instead checking if a key
    // is already present in the fs or not.
    const char NON_LOGIN_SERVICES[][32] = {
        "polkit-1",
        "sudo",
    };

    char *service;
    pam_get_item(pamh, PAM_SERVICE, (const void**)&service);
    if (service != NULL)
    {
        fscrypt_utils_log(LOG_INFO, "executing service is %s\n", service);
        int ignore_service = 0;
        for (size_t service_idx = 0; service_idx < sizeof(NON_LOGIN_SERVICES) / sizeof(*NON_LOGIN_SERVICES); service_idx++)
        {
            if (0 == strcmp(service, NON_LOGIN_SERVICES[service_idx]))
            {
                ignore_service = 1;
                break;
            }
        }
        if (ignore_service)
        {
            // No need to unlock if this was just a sudo request
            fscrypt_utils_log(LOG_NOTICE, "skipping unlock for service %s\n", service);
            return PAM_IGNORE;
        }
    }
    else
    {
        fscrypt_utils_log(LOG_INFO, "executing service is UNDEFINED\n");
    }

    char *username;
    pam_get_item(pamh, PAM_USER, (const void**)&username);
    if (username == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "pam_sm_authenticate failed to get username\n");
        return PAM_IGNORE;
    }

    char *password;
    pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password);
    if (password == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "pam_sm_authenticate failed to get password\n");
        return PAM_IGNORE;
    }

    struct user_key_data_t userdata;
    memset(&userdata, 0, sizeof(userdata));
    fscrypt_utils_hash_password(userdata.user_kek, username, password);
    strcpy(userdata.username, username);

    int successful_unlock_count = 0;
    for (size_t mount_idx = 0; mount_idx < args.system_mount_count; mount_idx++)
    {
        for (size_t datapath_idx = 0; datapath_idx < fscrypt_util_max(1, args.datapath_count); datapath_idx++)
        {
            if (args.datapaths[datapath_idx] != NULL)
            {
                if (FSCRYPT_UTILS_STATUS_OK != fscrypt_util_stored_data_set_path(args.datapaths[datapath_idx]))
                {
                    fscrypt_utils_log(LOG_ERR, "Failed to use datapath %s\n", args.datapaths[datapath_idx]);
                    continue;
                }
            }
            if (FSCRYPT_UTILS_STATUS_OK != fscrypt_add_key(NULL, args.system_mountpoints[mount_idx], &userdata))
            {
                fscrypt_utils_log(LOG_ERR,
                    "Failed to add fscrypt key for user=%s mount=%s datapath=%s\n",
                    username, args.system_mountpoints[mount_idx], fscrypt_util_stored_data_get_path()
                );
            }
            else
            {
                successful_unlock_count++;
                fscrypt_utils_log(LOG_NOTICE,
                    "Successfully added key for user=%s mount=%s datapath=%s\n",
                    username, args.system_mountpoints[mount_idx], fscrypt_util_stored_data_get_path()
                );
            }
        }
    }

    if (args.post_hook != NULL)
    {
        fscrypt_utils_log(LOG_DEBUG, "Starting post-hook execution %s\n", args.post_hook);
        void *handle = dlopen(args.post_hook, RTLD_NOW);
        if (handle == NULL)
        {
            fscrypt_utils_log(LOG_ERR, "%s\n", dlerror());
        }
        else
        {
            fscrypt_multiuser_hook_v1_f hook_function = (fscrypt_multiuser_hook_v1_f)dlsym(handle, "fscrypt_multiuser_hook_v1");
            if (hook_function == NULL)
            {
                fscrypt_utils_log(LOG_ERR, "%s\n", dlerror());
            }
            else
            {
                // v1 hook
                struct hook_data_structure_t hook_params;
                hook_params.userarg = args.hook_userarg;
                hook_params.unlock_ok_count = successful_unlock_count;
                hook_params.username = username;
                hook_params.password = password;
                hook_params.user_kek_data = userdata.user_kek;
                hook_params.user_kek_bytes = FSCRYPT_USER_KEK_BYTES;
                hook_function(&hook_params);
                fscrypt_utils_log(LOG_DEBUG, "post-hook execution completed\n");
            }
            dlclose(handle);
        }
    }
    memset(&userdata, 0, sizeof(userdata));

    return PAM_IGNORE;
}


int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    struct pam_fscrypt_parameters args;
    pam_fscrypt_parse_arguments(SOURCE_FUNCTION_PASSWORD, argc, argv, &args);

    fscrypt_utils_log(LOG_DEBUG, "Starting pam_sm_chauthtok flags=%d\n", flags);

    if (!(flags & PAM_UPDATE_AUTHTOK))
    {
        fscrypt_utils_log(LOG_INFO, "Auth update not requested, exiting");
        return PAM_IGNORE;
    }

    char *username;
    pam_get_item(pamh, PAM_USER, (const void**)&username);
    if (username == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "pam_sm_chauthtok failed to get username\n");
        return PAM_IGNORE;
    }

    char *password_old;
    pam_get_item(pamh, PAM_OLDAUTHTOK, (const void**)&password_old);

    char *password_new;
    pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password_new);

    if (password_new == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "pam_sm_chauthtok failed to get new password\n");
        return PAM_IGNORE;
    }
    
    if (password_old == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "pam_sm_chauthtok failed to get old password\n");
        return PAM_IGNORE;
    }

    struct user_key_data_t userdata_old;
    memset(&userdata_old, 0, sizeof(userdata_old));
    fscrypt_utils_hash_password(userdata_old.user_kek, username, password_old);
    strcpy(userdata_old.username, username);

    struct user_key_data_t userdata_new;
    memset(&userdata_new, 0, sizeof(userdata_new));
    fscrypt_utils_hash_password(userdata_new.user_kek, username, password_new);
    strcpy(userdata_new.username, username);

    int rc;
    if (FSCRYPT_UTILS_STATUS_OK != wrap_fscrypt_key(&userdata_old, &userdata_new, KEY_MODE_REPLACE_USER))
    {
        fscrypt_utils_log(LOG_ERR, "failed to rewrap user key during password change for %s\n", username);
        rc = PAM_IGNORE;
    }
    else
    {
        fscrypt_utils_log(LOG_WARNING, "Successfully rewrapped key for user '%s'\n", username);
        rc = PAM_SUCCESS;
    }

    memset(&userdata_old, 0, sizeof(userdata_old));
    memset(&userdata_new, 0, sizeof(userdata_new));

    return rc;
}