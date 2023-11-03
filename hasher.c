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

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string.h>

#include "hasher.h"
#include "constants.h"

size_t fscrypt_utils_hash_password(uint8_t *hashout, const char *username, const char *password)
{
    uint8_t salt[32] = {0};
    SHA256((uint8_t*)username, fscrypt_util_min(strlen(username), MAX_USERNAME_BYTES), salt);

    const int ITERATIONS = 4096;
    int rc = PKCS5_PBKDF2_HMAC(
        password, -1,
        salt, sizeof(salt),
        ITERATIONS,
        EVP_sha256(),
        FSCRYPT_USER_KEK_BYTES, hashout
    );
    if (rc != 1)
    {
        return 0;
    }
    return FSCRYPT_USER_KEK_BYTES;
}