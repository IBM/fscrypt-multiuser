#ifndef __FSCRYPT_PAM_HOOK_H__
#define __FSCRYPT_PAM_HOOK_H__

struct hook_data_structure_t {
    const char *userarg;
    int unlock_ok_count;
    const char *username;
    const char *password;
    const unsigned char *user_kek_data;
    unsigned int user_kek_bytes;
};

typedef void (*fscrypt_multiuser_hook_v1_f)(struct hook_data_structure_t *parameters);
void fscrypt_multiuser_hook_v1(struct hook_data_structure_t *parameters);

#endif  // __FSCRYPT_PAM_HOOK_H__