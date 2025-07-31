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
#include "BUILD_PARAMS.h"

#define INPUT_MAX_LENGTH 256


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
    while((next_ch = getchar()) != '\n' && next_ch != EOF && pw_idx < INPUT_MAX_LENGTH)
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

int main(int argc, char **argv)
{
    int verbose = 0;
    int help = 0;
    char *username = NULL;
    for (int arg_idx = 1; arg_idx < argc; arg_idx++)
    {
        if (0 == strcmp(argv[arg_idx], "-h") || 0 == strcmp(argv[arg_idx], "--help"))
        {
            help = 1;
        }
        else if ((0 == strcmp(argv[arg_idx], "-v")) || (0 == strcmp(argv[arg_idx], "--verbose")))
        {
            verbose = 1;
        }
        else if (username != NULL)
        {
            help = 1;
            fprintf(stderr, "More than one username was provided!\n");
        }
        else
        {
            username = argv[arg_idx];
        }
    }
    if (help)
    {
        fprintf(stderr,
            "Build version: " BUILD_FULL_VERSION_STR "\n"
            "Usage:\n"
            "    fscrypt_generate_kek\n"
            "    fscrypt_generate_kek [user]\n"
            "\n"
            "If the user is not provided on the command line, it will be read from stdin\n"
            "\n"
            "The password may be provided via FSCRYPT_GENERATE_KEK_PASSWORD environment variable.\n"
            "If not provided via environment, it will be also be read from stdin\n"
            "\n"
            "If both user and password are passed via stdin, they must be separated by a newline\n"
        );
        return 1;
    }

    char user1[INPUT_MAX_LENGTH];
    char pw1[INPUT_MAX_LENGTH];

    if (username != NULL)
    {
        strncpy(user1, username, INPUT_MAX_LENGTH);
        user1[INPUT_MAX_LENGTH - 1] = '\0';
    }
    else
    {
        get_password("Username: ", user1, 0);
    }

    char *pw_env = getenv("FSCRYPT_GENERATE_KEK_PASSWORD");
    if (pw_env != NULL)
    {
        strncpy(pw1, pw_env, INPUT_MAX_LENGTH);
        pw1[INPUT_MAX_LENGTH - 1] = '\0';
    }
    else
    {
        get_password("Password: ", pw1, 1);
    }

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

    if (verbose)
    {
        printf("hash_ascii = %s\n", result_ascii);
        printf("hash_escaped = %s\n", result_escapes);
    }
    else
    {
        printf("%s\n", result_ascii);
    }

    return 0;
}