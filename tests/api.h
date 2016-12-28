/*

 The MIT License (MIT)

 Copyright (c) 2015-2016 Douglas J. Bakkum

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


#ifndef _API_H_
#define _API_H_


#include "utils.h"
#include "flags.h"
#include "commander.h"


#define HID_REPORT_SIZE   COMMANDER_REPORT_SIZE


static const char tests_pwd[] = "0000";
static const char hidden_pwd[] = "hide";
static char command_sent[COMMANDER_REPORT_SIZE] = {0};
static int TEST_LIVE_DEVICE = 0;


#ifndef CONTINUOUS_INTEGRATION
// http://www.signal11.us/oss/hidapi/
#include <hidapi.h>
#include "conf_usb.h"

static hid_device *HID_HANDLE;
static unsigned char HID_REPORT[HID_REPORT_SIZE] = {0};

static int api_hid_init(void)
{
    HID_HANDLE = hid_open(USB_DEVICE_VENDOR_ID, USB_DEVICE_PRODUCT_ID, NULL);
    if (!HID_HANDLE) {
        return DBB_ERROR;
    }
    return DBB_OK;
}


static void api_hid_read(PASSWORD_ID id)
{
    int res, cnt = 0;
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    while (cnt < HID_REPORT_SIZE) {
        res = hid_read(HID_HANDLE, HID_REPORT + cnt, HID_REPORT_SIZE);
        if (res < 0) {
            printf("ERROR: Unable to read report.\n");
            return;
        }
        cnt += res;
    }
    utils_decrypt_report((char *)HID_REPORT, id);
    //printf("received:  >>%s<<\n", utils_read_decrypted_report());
}


static void api_hid_send_len(const char *cmd, int cmdlen)
{
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    memcpy(HID_REPORT, cmd, cmdlen );
    hid_write(HID_HANDLE, (unsigned char *)HID_REPORT, HID_REPORT_SIZE);
}


static void api_hid_send_encrypt(const char *cmd, uint16_t len, PASSWORD_ID id)
{
    int enc_len;
    char *enc = aes_cbc_b64_encrypt((const unsigned char *)cmd, len, &enc_len, id);
    api_hid_send_len(enc, enc_len);
    free(enc);
}
#endif


static uint16_t api_ser_cmd(const char *command)
{
    int id;
    for (id = 0; id < CMD_NUM; id++) {
        if (strcmp(cmd_str(id), command) == 0) {
            return cmd_instr(id);
        }
    }
    return 0;
}

static uint16_t api_ser_attr(const char *attr)
{
    int id;
    for (id = 0; id < ATTR_NUM; id++) {
        if (strcmp(attr_str(id), attr) == 0) {
            return attr_instr(id);
        }
    }
    return 0;
}

static uint16_t api_serialize_json(const char *command, char *buffer)
{
    yajl_val json_node = yajl_tree_parse(command, NULL, 0);
    const char *cmd_parent = json_node->u.object.keys[0];
    yajl_val args = json_node->u.object.values[0];
    size_t args_len = args->u.object.len;
    uint16_t b_len = 0, ser_cmd;

    // Parent command
    ser_cmd = api_ser_cmd(cmd_parent);
    buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
    buffer[b_len++] = (ser_cmd & 0x00FF);

    if (!args_len) {
        const char *cmd_val = json_node->u.object.values[0]->u.string;
        uint16_t val_len = strlens(cmd_val) + 1;// add 1 for null

        if (strlens(cmd_val)) {
            // Add child command key
            ser_cmd = cmd_instr(CMD_value);
            buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
            buffer[b_len++] = (ser_cmd & 0x00FF);
            // Child command value
            buffer[b_len++] = (val_len & 0xFF00) >> 8;
            buffer[b_len++] = (val_len & 0x00FF);
            memcpy(buffer + b_len, cmd_val, val_len);
            b_len += val_len;
        }

    } else {
        for (size_t i = 0; i < args_len; i++) {
            const char *arg_key = args->u.object.keys[i];
            yajl_val arg_val = args->u.object.values[i];

            // Add child command key
            ser_cmd = api_ser_cmd(arg_key);
            buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
            buffer[b_len++] = (ser_cmd & 0x00FF);

            // Child command value
            if (YAJL_IS_STRING(arg_val)) {
                uint16_t val_len = strlens(arg_val->u.string) + 1;// add 1 for null
                buffer[b_len++] = (val_len & 0xFF00) >> 8;
                buffer[b_len++] = (val_len & 0x00FF);
                memcpy(buffer + b_len, arg_val->u.string, val_len);
                b_len += val_len;

            } else if (YAJL_IS_ARRAY(arg_val)) {
                char array_buf[COMMANDER_REPORT_SIZE];
                memset(array_buf, 0, COMMANDER_REPORT_SIZE);
                uint16_t ab_len = 0;

                // case - data:[hash, keypath]
                for (size_t j = 0; j < arg_val->u.array.len; j++) {
                    yajl_val obj = arg_val->u.array.values[j];
                    const char *keypath_path[] = { cmd_str(CMD_keypath), NULL };
                    const char *hash_path[] = { cmd_str(CMD_hash), NULL };
                    const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));
                    const char *hash = YAJL_GET_STRING(yajl_tree_get(obj, hash_path, yajl_t_string));
                    uint8_t hash_d[32];
                    if (hash && keypath) {
                        uint16_t len = sizeof(hash_d) + strlens(keypath) + 1;// add 1s for null
                        array_buf[ab_len++] = (len & 0xFF00) >> 8;
                        array_buf[ab_len++] = len & 0x00FF;

                        memset(hash_d, 0, sizeof(hash_d));
                        memcpy(hash_d, utils_hex_to_uint8(hash), sizeof(hash_d));
                        memcpy(array_buf + ab_len, hash_d, sizeof(hash_d));
                        ab_len += sizeof(hash_d);

                        memcpy(array_buf + ab_len, keypath, strlens(keypath) + 1);
                        ab_len += strlens(keypath) + 1;
                    }
                }

                // case - checkpub:[pubkey]
                for (size_t j = 0; j < arg_val->u.array.len; j++) {
                    yajl_val obj = arg_val->u.array.values[j];
                    const char *pubkey_path[] = { cmd_str(CMD_pubkey), NULL };
                    const char *keypath_path[] = { cmd_str(CMD_keypath), NULL };
                    const char *pubkey = YAJL_GET_STRING(yajl_tree_get(obj, pubkey_path, yajl_t_string));
                    const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));

                    if (pubkey && keypath) {
                        uint16_t len = strlens(pubkey) + 1 + strlens(keypath) + 1;// add 1s for null
                        array_buf[ab_len++] = (len & 0xFF00) >> 8;
                        array_buf[ab_len++] = len & 0x00FF;

                        memcpy(array_buf + ab_len, pubkey, strlens(pubkey) + 1);
                        ab_len += strlens(pubkey) + 1;

                        memcpy(array_buf + ab_len, keypath, strlens(keypath) + 1);
                        ab_len += strlens(keypath) + 1;
                    }
                }

                // Terminate array serialization with null length
                array_buf[ab_len++] = 0x00;
                array_buf[ab_len++] = 0x00;

                // Add array to buffer
                buffer[b_len++] = (ab_len & 0xFF00) >> 8;
                buffer[b_len++] = (ab_len & 0x00FF);
                memcpy(buffer + b_len, array_buf, ab_len);
                b_len += ab_len;
            }
        }
    }
    yajl_tree_free(json_node);
    return b_len;
}


static void api_send_cmd(const char *command, PASSWORD_ID id)
{
    uint16_t len = 0;
    char command_ser[COMMANDER_REPORT_SIZE];
    memset(command_ser, 0, COMMANDER_REPORT_SIZE);

    if (strlens(command)) {
        len = api_serialize_json(command, command_ser);
    }

    if (len > COMMANDER_REPORT_SIZE) {
        printf("\n\nError: Buffer too long.\n\n");
        exit(1);
    }

    memset(command_sent, 0, sizeof(command_sent));
    if (command) {
        memcpy(command_sent, command_ser, len);
    }
    if (!TEST_LIVE_DEVICE) {
        utils_send_cmd(command_ser, len, id);
    }
#ifndef CONTINUOUS_INTEGRATION
    else if (id == PASSWORD_NONE) {
        api_hid_send_len(command_ser, len);
        api_hid_read(id);
    } else {
        api_hid_send_encrypt(command_ser, len, id);
        api_hid_read(id);
    }
#endif
}


static void api_format_send_cmd(const char *cmd, const char *val, PASSWORD_ID id)
{
    char command[COMMANDER_REPORT_SIZE] = {0};
    strcpy(command, "{\"");
    strcat(command, cmd);
    strcat(command, "\": ");
    if (val[0] == '{') {
        strcat(command, val);
    } else {
        strcat(command, "\"");
        strcat(command, val);
        strcat(command, "\"");
    }
    strcat(command, "}");
    api_send_cmd(command, id);
}


static void api_reset_device(void)
{
    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE); // if not set
    api_format_send_cmd(cmd_str(CMD_reset), attr_str(ATTR___ERASE__), PASSWORD_STAND);
}


static const char *api_read_value(int cmd)
{
    static char value[HID_REPORT_SIZE];
    memset(value, 0, sizeof(value));

    yajl_val json_node = yajl_tree_parse(utils_read_decrypted_report(), NULL, 0);
    if (json_node && YAJL_IS_OBJECT(json_node)) {
        const char *path[] = { cmd_str(cmd), NULL };
        yajl_val v = yajl_tree_get(json_node, path, yajl_t_string);
        snprintf(value, sizeof(value), "%s", v->u.string);
    }

    yajl_tree_free(json_node);
    return value;
}


static char *api_read_value_decrypt(int cmd, PASSWORD_ID id)
{
    const char *val = api_read_value(cmd);
    static char val_dec[HID_REPORT_SIZE];
    memset(val_dec, 0, sizeof(val_dec));

    int decrypt_len;
    char *dec = aes_cbc_b64_decrypt((const unsigned char *)val, strlens(val),
                                    &decrypt_len, id);

    snprintf(val_dec, HID_REPORT_SIZE, "%.*s", decrypt_len, dec);
    free(dec);
    return val_dec;
}

#endif

