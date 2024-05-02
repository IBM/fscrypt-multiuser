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
#include <termios.h>
#include <string.h>
#include <unistd.h>

#include "hasher.h"
#include "constants.h"

#define PW_MAX_LENGTH 128


void get_password(const char *prompt, char *result, int hide_input)
{
    printf("%s", prompt);

    struct termios oldterm;
    if (hide_input)
    {
        tcgetattr(STDIN_FILENO, &oldterm);
        struct termios newterm;
        newterm = oldterm;
        newterm.c_lflag &= ~(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newterm);
    }

    int next_ch;
    size_t pw_idx = 0;
    while((next_ch = getchar()) != '\n' && next_ch != EOF && pw_idx < PW_MAX_LENGTH)
    {
        result[pw_idx] = next_ch;
        pw_idx++;
    }
    result[pw_idx] = '\0';
    if (hide_input)
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldterm);
        printf("\n");
    }
}

// int main(int argc, char **argv)
int main(void)
{
    char user1[PW_MAX_LENGTH];
    char pw1[PW_MAX_LENGTH];

    get_password("Username: ", user1, 0);
    get_password("Password: ", pw1, 1);

    unsigned char key[FSCRYPT_USER_KEK_BYTES] = "";
    fscrypt_utils_hash_password(key, user1, pw1);

    char result_ascii[1024] = "";
    char result_escapes[1024] = "";
    for (size_t idx = 0; idx < FSCRYPT_USER_KEK_BYTES; idx++)
    {
        char hexbyte[3];
        sprintf(hexbyte, "%02x", key[idx]);
        strcat(result_ascii, hexbyte);
        strcat(result_escapes, "\\x");
        strcat(result_escapes, hexbyte);
    }

    printf("hash_ascii=%s\n", result_ascii);
    printf("hash_escaped=%s\n", result_escapes);

    return 0;
}