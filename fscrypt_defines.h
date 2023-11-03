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

#ifndef __FSCRYPT_TYPES_H__
#define __FSCRYPT_TYPES_H__

#include <linux/types.h>
#include <linux/ioctl.h>

#define FSCRYPT_MODE_AES_256_XTS (1)
#define FSCRYPT_MODE_AES_256_CTS (4)
#define FSCRYPT_KEY_DESCRIPTOR_SIZE (8)
#define FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER (2)


#define FSCRYPT_POLICY_FLAGS_PAD_4 (0x00)
#define FSCRYPT_POLICY_FLAGS_PAD_8 (0x01)
#define FSCRYPT_POLICY_FLAGS_PAD_16 (0x02)
#define FSCRYPT_POLICY_FLAGS_PAD_32 (0x03)
#define FSCRYPT_POLICY_FLAGS_PAD_MASK (0x03)
#define FSCRYPT_POLICY_FLAG_DIRECT_KEY (0x04)
#define FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 (0x08)
#define FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 (0x10)

#define FSCRYPT_KEY_BYTES (64)
#define FSCRYPT_KEY_ID_BYTES (16)

struct fscrypt_key_specifier {
    __u32 type;  // one of FSCRYPT_KEY_SPEC_TYPE_*
    __u32 __reserved;
    union {
        __u8 __reserved[32];
        __u8 descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
        __u8 identifier[FSCRYPT_KEY_ID_BYTES];
    } u;
};

struct fscrypt_add_key_arg {
    struct fscrypt_key_specifier key_spec;
    __u32 raw_size;
    __u32 key_id;
    __u32 __reserved[8];
    __u8 raw[];
};

#define FSCRYPT_POLICY_V2 (2)
struct fscrypt_policy_v1 {
    __u8 version;
    __u8 contents_encryption_mode;
    __u8 filenames_encryption_mode;
    __u8 flags;
    __u8 master_key_identifier[FSCRYPT_KEY_DESCRIPTOR_SIZE];
};
struct fscrypt_policy_v2 {
    __u8 version;
    __u8 contents_encryption_mode;
    __u8 filenames_encryption_mode;
    __u8 flags;
    __u8 __reserved[4];
    __u8 master_key_identifier[FSCRYPT_KEY_ID_BYTES];
};

#define FS_IOC_SET_ENCRYPTION_POLICY _IOR('f', 19, struct fscrypt_policy_v1)
#define FS_IOC_ADD_ENCRYPTION_KEY _IOWR('f', 23, struct fscrypt_add_key_arg)

#endif  // __FSCRYPT_TYPES_H__