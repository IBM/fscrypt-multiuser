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

#include "fscrypt_utils.h"


int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    fscrypt_utils_set_log_stderr(0);

    char *service;
    pam_get_item(pamh, PAM_SERVICE, (const void**)&service);
    if (service != NULL && 0 == strcmp(service, "sudo"))
    {
        // No need to unlock if this was just a sudo request
        return PAM_IGNORE;
    }

    char *username;
    pam_get_item(pamh, PAM_USER, (const void**)&username);
    if (username == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "pam_fscrypt_multiuser: pam_sm_authenticate failed to get username\n");
    }

    char *password;
    pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password);
    if (password == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "pam_fscrypt_multiuser: pam_sm_authenticate failed to get password\n");
        return PAM_IGNORE;
    }

    struct user_key_data_t userdata;
    memset(&userdata, 0, sizeof(userdata));
    fscrypt_utils_hash_password(userdata.user_kek, username, password);
    strcpy(userdata.username, username);

    if (0 != fscrypt_add_key(NULL, "/", &userdata))
    {
        fscrypt_utils_log(LOG_ERR, "pam_fscrypt_multiuser: Failed to unlock fscrypt key for user '%s'\n", username);
    }
    else
    {
        fscrypt_utils_log(LOG_WARNING, "pam_fscrypt_multiuser: Successfully unlocked key for user '%s'\n", username);
    }

    memset(&userdata, 0, sizeof(userdata));

    return PAM_IGNORE;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    fscrypt_utils_set_log_stderr(0);

    char *username;
    pam_get_item(pamh, PAM_USER, (const void**)&username);
    if (username == NULL)
    {
        fscrypt_utils_log(LOG_ERR, "pam_fscrypt_multiuser: pam_sm_chauthtok failed to get username\n");
        return PAM_IGNORE;
    }

    char *password_old;
    pam_get_item(pamh, PAM_OLDAUTHTOK, (const void**)&password_old);

    char *password_new;
    pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password_new);

    if (password_new == NULL || password_old == NULL)
    {
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
    if (0 != wrap_fscrypt_key(&userdata_old, &userdata_new, KEY_MODE_REPLACE_USER))
    {
        fscrypt_utils_log(LOG_ERR, "pam_fscrypt_multiuser: failed to rewrap user key during password change for %s\n", username);
        rc = PAM_IGNORE;
    }
    else
    {
        fscrypt_utils_log(LOG_WARNING, "pam_fscrypt_multiuser: Successfully rewrapped key for user '%s'\n", username);
        rc = PAM_SUCCESS;
    }

    memset(&userdata_old, 0, sizeof(userdata_old));
    memset(&userdata_new, 0, sizeof(userdata_new));

    return rc;
}