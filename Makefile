DESTDIR=
BUILD_DIR=build

CC=gcc
CFLAGS=-fPIC -Wall -Werror -g
LD_FLAGS=-lcrypto

SRC=$(wildcard *.c)
OBJ=$(SRC:%.c=$(BUILD_DIR)/%.o)
DEP=$(OBJ:%.o=%.d)

BIN=hash_my_password wraptest fscrypt_setup
BIN_TARGETS=$(addprefix $(BUILD_DIR)/,$(BIN))

LIB=pam_fscrypt_multiuser.so
LIB_TARGETS=$(addprefix $(BUILD_DIR)/,$(LIB))

all: $(BIN_TARGETS) $(LIB_TARGETS)

install:
	install -m 664 $(BUILD_DIR)/pam_fscrypt_multiuser.so $(DESTDIR)/usr/lib/x86_64-linux-gnu/security
	install -m 664 fscrypt-multiuser-rule $(DESTDIR)/usr/share/pam-configs/
	pam-auth-update --force --package

uninstall:
	rm -f $(DESTDIR)/usr/lib/x86_64-linux-gnu/security/pam_fscrypt_multiuser.so
	rm -f $(DESTDIR)/usr/share/pam-configs/fscrypt-multiuser-rule
	pam-auth-update --force --package

clean:
	rm -rf $(BUILD_DIR)


-include $(DEP)

$(BUILD_DIR)/%.o: %.c Makefile
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -MMD -c -o $@ $<

$(BUILD_DIR)/hash_my_password: $(addprefix $(BUILD_DIR)/,hash_my_password.o hasher.o)
$(BUILD_DIR)/wraptest: $(addprefix $(BUILD_DIR)/,wraptest.o fscrypt_utils.o hasher.o)
$(BUILD_DIR)/fscrypt_setup: $(addprefix $(BUILD_DIR)/,fscrypt_setup.o fscrypt_utils.o hasher.o)
$(BUILD_DIR)/pam_fscrypt_multiuser.so: $(addprefix $(BUILD_DIR)/,pam_fscrypt_multiuser.o fscrypt_utils.o hasher.o)

$(BIN_TARGETS):
	$(CC) $(CFLAGS) -o $@ $^ $(LD_FLAGS)

$(LIB_TARGETS):
	$(CC) -shared -rdynamic $(CFLAGS) -o $@ $^ $(LD_FLAGS)

.PHONY: all install uninstall clean
.SUFFIXES: