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

#include "fscrypt_utils.h"
#include "BUILD_PARAMS.h"

// int main(int argc, char **argv)
int main(void)
{
    fscrypt_utils_set_log_stderr(1);

    printf("Build version: %s\n", BUILD_FULL_VERSION_STR);

    size_t idx;
    char myuser[] = "test";
    char mypassword[] = "hello world";
    printf("Password = %s\n", mypassword);

    struct crypto_context_t context;
    fscrypt_utils_generate_random_key(context.unlock_key, sizeof(context.unlock_key));
    fscrypt_utils_generate_random_key(context.iv, sizeof(context.iv));

    unsigned char fscrypt_key[FSCRYPT_KEY_BYTES];
    fscrypt_utils_generate_random_key(fscrypt_key, sizeof(fscrypt_key));

    printf("fscrypt_key = "); for (idx = 0; idx < sizeof(fscrypt_key); idx++){ printf("%02x ", fscrypt_key[idx]); } printf("\n");
    printf("context.unlock_key = "); for (idx = 0; idx < sizeof(context.unlock_key); idx++){ printf("%02x ", context.unlock_key[idx]); } printf("\n");
    printf("context.iv = "); for (idx = 0; idx < sizeof(context.iv); idx++){ printf("%02x ", context.iv[idx]); } printf("\n");

    unsigned char hashed[FSCRYPT_USER_KEK_BYTES] = {0};
    size_t hash_size = fscrypt_utils_hash_password(hashed, myuser, mypassword);
    printf("hashed n=%lu = ", hash_size);
    for (idx = 0; idx < sizeof(hashed); idx++){ printf("%02x ", hashed[idx]); } printf("\n");

    unsigned char wrapped_key[OPENSSL_KEK_UPDATE_MIN_BYTES] = {0};
    size_t wrapped_size = wrap_unwrap_key(&context, wrapped_key, fscrypt_key, sizeof(fscrypt_key), 1);
    printf("wrapped n=%lu = ", wrapped_size);
    for (idx = 0; idx < sizeof(wrapped_key); idx++){ printf("%02x ", wrapped_key[idx]); } printf("\n");

    unsigned char unwrapped_key[FSCRYPT_KEY_BYTES] = {0};
    size_t unwrapped_size = wrap_unwrap_key(&context, unwrapped_key, wrapped_key, wrapped_size, 0);
    printf("unwrapped_key n=%lu = ", unwrapped_size);
    for (idx = 0; idx < sizeof(unwrapped_key); idx++){ printf("%02x ", unwrapped_key[idx]); } printf("\n");

    if (memcmp(fscrypt_key, unwrapped_key, FSCRYPT_KEY_BYTES) != 0)
    {
        printf("DATA MISMATCH\n");
    }
    else
    {
        printf("DATA OK\n");
    }

    return 0;
}