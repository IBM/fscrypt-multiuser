#include "fscrypt_pam_hook.h"

#include <stdio.h>

/*
How to build this example file
------------------------------
If fscrypt_pam_hook.h is not installed globally into /usr/include or similar, it must be located locally.

gcc -shared -fPIC -o fscrypt_pam_example_hook.so fscrypt_pam_example_hook.c
*/

void fscrypt_multiuser_hook_v1(struct hook_data_structure_t *parameters)
{
    fprintf(stderr, "fscrypt_pam_test_hook is running for username = %s\n", parameters->username);
}