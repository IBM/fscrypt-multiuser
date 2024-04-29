
# User specified build options
DESTDIR?=
BUILD_DIR?=build
CC?=gcc
EXTRA_CFLAGS?=
EXTRA_LDFLAGS?=
BUILD_TYPE?=Debug
DO_PAM_RULE_UPDATE?=Y
DO_PAM_AUTH_UPDATE?=Y
PREFIX?=/usr
INCLUDEDIR?=$(PREFIX)/include
LIBDIR?=$(PREFIX)/lib
BINDIR?=$(PREFIX)/bin
PAMDIR?=$(LIBDIR)/security

ifeq ($(BUILD_TYPE), Debug)
BUILD_DIR_WITH_TYPE=$(BUILD_DIR)/Debug
CFLAGS=-fPIC -Wall -Werror -I inc/ -g -DDEBUG_BUILD $(EXTRA_CFLAGS)
LDFLAGS=-lcrypto $(EXTRA_LDFLAGS)

else ifeq ($(BUILD_TYPE), Release)
BUILD_DIR_WITH_TYPE=$(BUILD_DIR)/Release
CFLAGS=-fPIC -Wall -Werror -I inc/ $(EXTRA_CFLAGS)
LDFLAGS=-lcrypto $(EXTRA_LDFLAGS)

else
$(error Invalid BUILD_TYPE target. Must be Release or Debug)
endif

# Record all source files
SRC=$(wildcard src/*.c)
# Add a target object for each source file
OBJ=$(SRC:%.c=$(BUILD_DIR_WITH_TYPE)/%.o)
# Create dependency list for each object
DEP=$(OBJ:%.o=%.d)

# Define source files that will become executables
BIN=hash_my_password wraptest fscrypt_setup
BIN_TARGETS=$(addprefix $(BUILD_DIR_WITH_TYPE)/,$(BIN))

# Define source files that will become shared objects
LIB=pam_fscrypt_multiuser.so fscrypt_pam_example_hook.so
LIB_TARGETS=$(addprefix $(BUILD_DIR_WITH_TYPE)/,$(LIB))

all: $(BIN_TARGETS) $(LIB_TARGETS)

install:
	install -Dm 664 $(BUILD_DIR_WITH_TYPE)/fscrypt_setup $(DESTDIR)$(BINDIR)/fscrypt_setup
	install -Dm 664 $(BUILD_DIR_WITH_TYPE)/pam_fscrypt_multiuser.so $(DESTDIR)$(PAMDIR)/pam_fscrypt_multiuser.so
	install -Dm 664 inc/fscrypt_pam_hook.h $(DESTDIR)$(INCLUDEDIR)/fscrypt_pam_hook.h
ifeq ($(DO_PAM_RULE_UPDATE), Y)
	install -Dm 664 pam/fscrypt-multiuser-rule $(DESTDIR)$(PREFIX)/share/pam-configs/fscrypt-multiuser-rule
endif
ifeq ($(DO_PAM_AUTH_UPDATE), Y)
	pam-auth-update --force --package
endif

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/fscrypt_setup
	rm -f $(DESTDIR)$(PAMDIR)/pam_fscrypt_multiuser.so
	rm -f $(DESTDIR)$(INCLUDEDIR)/fscrypt_pam_hook.h
	rm -f $(DESTDIR)$(PREFIX)/share/pam-configs/fscrypt-multiuser-rule
ifeq ($(DO_PAM_AUTH_UPDATE), Y)
	pam-auth-update --force --package
endif

clean:
	rm -f $(OBJ) $(DEP) $(BIN_TARGETS) $(LIB_TARGETS)

test: all
	$(BUILD_DIR_WITH_TYPE)/wraptest

# Include dependency files generated by gcc `-MMD`
-include $(DEP)

# Generate objects, use `-MMD` to generate dependency lists for source c files.
$(BUILD_DIR_WITH_TYPE)/%.o: %.c Makefile
	@mkdir -p $(@D)
	$(CC) -MMD $(CFLAGS) -c -o $@ $<

# Specify build-time dependencies for targets
$(BUILD_DIR_WITH_TYPE)/hash_my_password: $(addprefix $(BUILD_DIR_WITH_TYPE)/src/, hash_my_password.o hasher.o)
$(BUILD_DIR_WITH_TYPE)/wraptest: $(addprefix $(BUILD_DIR_WITH_TYPE)/src/, wraptest.o fscrypt_utils.o hasher.o)
$(BUILD_DIR_WITH_TYPE)/fscrypt_setup: $(addprefix $(BUILD_DIR_WITH_TYPE)/src/, fscrypt_setup.o fscrypt_utils.o hasher.o)
$(BUILD_DIR_WITH_TYPE)/pam_fscrypt_multiuser.so: $(addprefix $(BUILD_DIR_WITH_TYPE)/src/, pam_fscrypt_multiuser.o fscrypt_utils.o hasher.o)
$(BUILD_DIR_WITH_TYPE)/fscrypt_pam_example_hook.so: $(addprefix $(BUILD_DIR_WITH_TYPE)/src/, fscrypt_pam_example_hook.o)

$(BIN_TARGETS):
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(LIB_TARGETS):
	$(CC) -shared -rdynamic $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: all install uninstall clean
.SUFFIXES: