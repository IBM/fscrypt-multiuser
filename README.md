# fscrypt-multiuser
Linux filesystem encryption utilities for managing shared resources in multiuser environments.

**This project is a work-in-progress. Until properly released, bugs are likely and backwards compatibility is certain to break.**

## Purpose
In brief, this is a tool for IT automation in shared lab environments where you wish to encrypt data at rest, but also need to allow an arbitrary number of authorized users to access that data on-demand.

Similar projects like [google/fscrypt](https://github.com/google/fscrypt) are generally designed with the assumption that encrypted resources belong to a particular user and that these resources are exclusive to that user. While it is possible in google/fscrypt to add multiple protectors to a single policy (and thus, assign protectors to multiple users), doing so is cumbersome and difficult to automate.

[google/fscryptctl](https://github.com/google/fscryptctl) is a related project which provides more direct access to linux's filesystem encryption API, but again does not implement multiple-wrapping of the encryption key so it's useless in this application.

LUKS for full disk encryption is unsuitable for this environment because they require physical access to the system during reboots, which may be difficult in a remote-work environment. It also allows for only 8 key slots (or 32 for LUKS2), which is too few for this use-case.

The other principal issue with other filesystem encryption tools is that unix/PAM auth integration often accept the user's password directly as a key encrypting key (KEK) for the filesystem's primary key. In a shared lab environment, it is not feasible for a user to enter their password to set up every PC. And at the same time, IT administrators cannot be asking for and distributing plaintext user passwords in order to set up PCs. In a corporate environment, that password may authenticate against a unified access control service, and revealing it could grant access to much more than just a lab PC.

This project attempts to address these issues like so:
- The key database is designed from the start to allow decryption of the filesystem's primary key by any number of users.
- KEKs are generated from a secure hash of the user's login password. This allows IT administrators to set up encryption keys across multiple devices without needing to store or distribute the user's original password.

## Usage

TODO

### Logging

All logs are sent to syslog (`/var/log/syslog`) with ID `fscrypt_multiuser`.

PAM module logging can be adjusted by adding the `loglevel=` parameter to the PAM configuration in `/usr/share/pam-configs` or `/etc/pam.d`. The minimum is `loglevel=0`, to disable logging. The maximum is `loglevel=7` to enable debug trace logging.

## Dependencies
This project is built using cmake.

Build dependencies are the PAM and openssl development headers.

For ubuntu:
```
sudo apt install cmake libpam0g-dev libssl-dev
```

## Build and Install
```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DINSTALL_HEADERS=OFF
make all
sudo make install
```

For ubuntu and similar debian-based distros, installation of the pam-configs rule is set by the cmake options `PAM_RULE_INSTALL` and `PAM_AUTH_FORCE_UPDATE`.

To install this package into a fakeroot, use `-DPAM_AUTH_FORCE_UPDATE=OFF` and set `DESTDIR` during installation.

```
make DESTDIR=fakeroot install
```

### Build Options

The following options can be passed to `cmake` via `-D` option.

| Option | Default | Description |
| - | - | - |
| `CMAKE_BUILD_TYPE` | `Debug` | Typically "Debug" or "Release" |
| `PAM_RULE_INSTALL` | `OFF` | Enable installation of pam-configs rule |
| `PAM_AUTH_FORCE_UPDATE` | `OFF` | Update pam rules after pam-configs file is installed |
| `INSTALL_HEADERS` | `ON` | Enable installation of development headers |
| `CMAKE_INSTALL_PREFIX` | `/usr` | Installation prefix |


## PAM Module Hooks

PAM can load and execute a hook following a user's successful login. Module hooks are shared objects implementing the API specified by [fscrypt_pam_hook.h](inc/fscrypt_pam_hook.h). The goal of this implementation is to provide a method for administrators to dynamically reconfigure security parameters when a user successfully authenticates but they password is unable to unlock local system resources.

An example module is provided at [fscrypt_pam_example_hook.c](src/fscrypt_pam_example_hook.c).