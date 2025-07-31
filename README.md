# fscrypt-multiuser
Linux filesystem encryption utilities for managing shared resources in multiuser environments.

**This project is a work-in-progress. Until properly released, bugs are likely and backwards compatibility is certain to break.**

## Purpose
In brief, this is a tool for IT automation in shared lab environments where you wish to encrypt data at rest, but also need to allow an arbitrary number of authorized users to access that data on-demand.

Similar projects like [google/fscrypt](https://github.com/google/fscrypt) are generally designed with the assumption that encrypted resources belong to a particular user and that these resources are exclusive to that user. While it is possible to add multiple protectors to a single policy in fscrypt (and thus, assign protectors to multiple users), doing so is cumbersome and difficult to automate because of the tool's focus on single-user usage.

The other principal issue with fscrypt is that unix/PAM auth integration accepts the user's password directly as a key encrypting key (KEK) for the filesystem's primary key. In a shared lab environment, it is not feasible for a user to enter their password to set up every PC. And at the same time, IT administrators cannot be asking for and distributing plaintext user passwords. In a corporate environment, that password may authenticate against a unified access control service, and revealing it could grant access to much more than just a lab PC.

[google/fscryptctl](https://github.com/google/fscryptctl) is a related project which provides more direct access to linux's filesystem encryption API. Since fscryptctl does not directly implement any PAM modules or key wrapping, it does not fully serve the same use cases as this project. However, it is useful for supplementing features so that we don't need to re-implmement every fs encryption interface. fscryptctl and fscrypt-multiuser manipulate the same underlying filesystem structures, so fscryptctl can be used to verify the policy and unlock status of encrypted directories.

LUKS for full disk encryption is unsuitable for this environment because they require physical access to the system during reboots, which may be difficult in a remote-work environment. It also allows for only 8 key slots (or 32 for LUKS2), which is too few for this use-case.

This project attempts to address the above issues by focusing on the following design goals:
- The key database must allow decryption of the filesystem's primary key by multiple users. Any number of authorized users should be able to access encrypted resources without sharing passwords.
- KEKs must be generated from a secure hash of the user's login password. This allows IT administrators to set up encryption keys across multiple devices without needing to store or distribute the user's original password. This setup must ensure that decryption can be performed with a user's normal unix login, but exposure of keys distributed to set up encryption will not grant remote system access.

## Usage

### Included Files/Tools

The following files can be included in a typical installation:

- `fscrypt_setup` : Command line interface for managing the fscrypt-multiuser data container and enabling local encryption policies.
- `fscrypt_generate_kek` : Simple executable for generating KEKs from a user's login credentials.
- `pam_fscrypt_multiuser.so` : PAM integration for unlocking system resources at login.
- `fscrypt-multiuser-rule` : Configuration for debian-style PAM setup.
- `fscrypt_pam_subprocess_hook.so`, `fscrypt_pam_hook.h` : See [PAM hooks](#pam-hooks).

### Verifying Encryption Policies

The only encryption ioctls implemented in this project are those strictly required to perform encryption setup and unlock. Verification of encryption policies is outside of that scope, so it's expected that https://github.com/google/fscryptctl can be used for additional operations such as checking directories for existing policies, checking if a mount point has a key added, etc.

### Logging

All logs are sent to syslog (`/var/log/syslog`) with ID `fscrypt_multiuser`.

PAM module logging can be adjusted by adding the `loglevel=` parameter to the PAM configuration in `/usr/share/pam-configs` or `/etc/pam.d`. Valid values for this option are defined by `syslog.h`; the maximum is `loglevel=7` to enable debug trace logging.

### Configuration

The default configuration is `/etc/fscrypt_multiuser.conf`. For testing and development, this path can be overwritten by using the environment variable `FSCRYPT_SET_CONFIG_PATH`.

The file is a simple list of parameters taking the form of one `key=value` pair per line. Where specified, a key can be specified multiple times to supply multiple values.

| Key | Valid Values | Description |
| - | - | - |
| loglevel | Numeric 0-7 | Set logging level, see: [Logging](#logging) |
| mountpoint | `[mountpoint]::[datapath]` | Double colon-separated pair of a mountpoint and the path to a keystore for that mountpoint. Can be specified multiple times |
| pam_post_hook_exec | shared_object.so | Specify a hook to run after attempting an unlock. See [PAM Hooks](#pam-hooks) |
| pam_post_hook_arg | String | Specify an additional argument to pass to the post-hook object |


### PAM Hooks

This PAM module supports dynamically loading a shared object following an attempted key unlock. The goal of this feature is to allow for system administrators to dynamically reconfigure or monitor the system's security configuration following a user's attempted login.

A hook module is a shared object which implements and exports the function defined in [fscrypt_pam_hook.h](inc/fscrypt_pam_hook.h). This hook is run whenever a key unlock is attempted and the result of that unlock is indicated to the hook module. Note that the module always attempts to unwrap and add a user's key, even if the filesystem is already decrypted, so an error reported to the hook does not strictly indicate that encrypted resources are unavailable.

In cases where implementing the hook in compiled code is not desirable, a module is provided in this project which copies the session information into the process environment and executes the file indicated by the `hook-arg` parameter. It can be enabled with the following PAM parameters:

```
auth    optional        pam_fscrypt_multiuser.so post-hook=fscrypt_pam_subprocess_hook.so hook-arg=/usr/bin/my_script.py
```

The `fscrypt_pam_subprocess_hook.so` module exports the following environment variables.

```
HOOKPARAM_VERSION=0.0.0
HOOKPARAM_UNLOCK_OK_COUNT=1
HOOKPARAM_USERNAME=user_xyz
HOOKPARAM_PASSWORD=password_xyz
HOOKPARAM_USER_KEK_DATA=aabbcc001122
```

## Build and Install

### Dependencies
This project is built using cmake.

Build dependencies are the PAM and openssl development headers.

For ubuntu:
```
sudo apt install cmake libpam0g-dev libssl-dev
```

### Build Process

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
