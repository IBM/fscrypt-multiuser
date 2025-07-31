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


#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__

#define DATA_FILE_FORMAT_VERSION (2)

#define OPENSSL_KEK_UPDATE_MIN_BYTES (FSCRYPT_KEY_BYTES + 8)

#define FSCRYPT_USER_KEK_BYTES (32)

#define MAX_USERNAME_BYTES (32)

#define FSCRYPT_UTILS_SYSLOG_ID "fscrypt_multiuser"

#define fscrypt_util_min(a, b) ((a) < (b) ? (a) : (b))
#define fscrypt_util_max(a, b) ((a) > (b) ? (a) : (b))

#endif  // __CONSTANTS_H__