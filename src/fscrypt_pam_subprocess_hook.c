#include "fscrypt_pam_hook.h"
#include "BUILD_PARAMS.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


void fscrypt_multiuser_hook_v1(struct hook_data_structure_t *parameters)
{
    if (parameters->userarg == NULL)
    {
        fprintf(stderr, "fscrypt_pam_subprocess_hook: hook-arg is not specified, nothing will be done\n");
        return;
    }

    pid_t pid = fork();

    if (pid == 0)
    {
        const size_t KEK_DATA_STR_SIZE = parameters->user_kek_bytes * 2 + 1;
        char *param_user_kek_data = calloc(KEK_DATA_STR_SIZE, 1);
        for (unsigned int idx = 0; idx < parameters->user_kek_bytes; idx++)
        {
            char ch[3] = "";
            snprintf(ch, sizeof(ch), "%02x", parameters->user_kek_data[idx]);
            strcat(param_user_kek_data, ch);
        }

        char unlock_ok_count_str[32] = "";
        snprintf(unlock_ok_count_str, sizeof(unlock_ok_count_str) - 1, "%d", parameters->unlock_ok_count);
        setenv("HOOKPARAM_VERSION", BUILD_VESRION, 1);
        setenv("HOOKPARAM_UNLOCK_OK_COUNT", unlock_ok_count_str, 1);
        setenv("HOOKPARAM_USERNAME", parameters->username, 1);
        setenv("HOOKPARAM_PASSWORD", parameters->password, 1);
        setenv("HOOKPARAM_USER_KEK_DATA", param_user_kek_data, 1);

        memset(param_user_kek_data, 0, KEK_DATA_STR_SIZE);
        free(param_user_kek_data);

        execl(
            "/bin/sh",
            "sh",
            "-c",
            parameters->userarg,
            (char*)NULL
        );
        // exec only returns if an error occurred
    }
}