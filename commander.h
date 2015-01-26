/*

 Copyright (c) 2015 Douglas J. Bakkum

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/



#ifndef _COMMANDER_H_
#define _COMMANDER_H_


#include <stdint.h>
#ifndef TESTING
#include "conf_usb.h"

#define JSON_REPORT_SIZE   UDI_HID_REPORT_OUT_SIZE
#else
#define JSON_REPORT_SIZE   4096
#endif

#define DIGITAL_BITBOX_VERSION  "1.0"

#define GENERATE_STRING(STRING) #STRING,
#define GENERATE_ENUM_ATTR(ENUM) ATTR_ ## ENUM ## _,
#define GENERATE_ENUM_CMD(ENUM) CMD_ ## ENUM ## _,

#define FOREACH_CMD(CMD)        \
  /*    parent commands     */  \
        CMD(led)                \
        CMD(sign)               \
        CMD(name)               \
        CMD(seed)               \
        CMD(load)               \
        CMD(backup)             \
        CMD(password)           \
        CMD(touchbutton)        \
        CMD(master_public_key)  \
        CMD(random)             \
        CMD(device)             \
        CMD(reset)              \
        CMD(ciphertext)         \
  /*    child commands      */  \
        CMD(timeout)            \
        CMD(threshold)          \
        CMD(button)             \
        CMD(generate_electrum)  \
        CMD(generate_bip32)     \
        CMD(sd_file)            \
        CMD(wallet)             \
        CMD(mnemonic)           \
        CMD(data)               \
        CMD(keypath)            \
        CMD(encoding)           \
        CMD(strength)           \
        CMD(salt)               \
        CMD(filename)           \
        CMD(decrypt)            \
        CMD(encrypt)            \
        CMD(format_sd_card)     \
        CMD(none)                /* keep last */

#define FOREACH_ATTR(ATTR)      \
  /*    command attributes  */  \
        ATTR(electrum)          \
        ATTR(bip32)             \
        ATTR(der)               \
        ATTR(message)           \
        ATTR(enable)            \
        ATTR(disable)           \
        ATTR(true)              \
        ATTR(pseudo)            \
        ATTR(serial)            \
        ATTR(version)           \
        ATTR(__ERASE__)         \
        ATTR(none)               /* keep last */

enum CMD_ENUM { FOREACH_CMD(GENERATE_ENUM_CMD) };
enum ATTR_ENUM { FOREACH_ATTR(GENERATE_ENUM_ATTR) };

#define CMD_NUM      CMD_none_
#define ATTR_NUM     ATTR_none_

enum REPORT_FLAGS { 
    SUCCESS = 0, 
    ERROR = 1, 
};

void fill_report(const char *attr, const char *val, int err);
void fill_report_len(const char *attr, const char *val, int err, int vallen);
char *commander(const char *instruction_encrypted);
char *aes_cbc_b64_encrypt(const unsigned char *in, int inlen, const uint8_t *key, int *out_b64len);
char *aes_cbc_b64_decrypt(const unsigned char *in, int inlen, const uint8_t *key, int *declen);
#ifdef TESTING
void delay_ms(int delay);
#endif


#endif
