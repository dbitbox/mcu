/*

 The MIT License (MIT)

 Copyright (c) 2015-2018 Douglas J. Bakkum

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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "commander.h"
#include "ataes132.h"
#include "memory.h"
#include "random.h"
#include "utils.h"
#include "flags.h"
#include "flash.h"
#include "hmac.h"
#include "sha2.h"
#include "aes.h"
#include "drivers/config/mcu.h"


#if ((MEM_PAGE_LEN != SHA256_DIGEST_LENGTH) || (MEM_PAGE_LEN * 2 != SHA512_DIGEST_LENGTH))
#error "Incompatible macro values"
#endif


// User Zones: 0x0000 to 0x0FFF
#define MEM_ERASED_ADDR                 0x0000// (uint8_t)  Zone 0 reserved for flags
#define MEM_SETUP_ADDR                  0x0002// (uint8_t)
#define MEM_ACCESS_ERR_ADDR             0x0004// (uint16_t)
#define MEM_PIN_ERR_ADDR                0x0006// (uint16_t)
#define MEM_UNLOCKED_ADDR               0x0008// (uint8_t)
#define MEM_EXT_FLAGS_ADDR              0x000A// (uint32_t) 32 possible extension flags
#define MEM_U2F_COUNT_ADDR              0x0010// (uint32_t)
#define MEM_MEMORY_MAP_VERSION_ADDR     0x0014// (uint32_t)
#if (FLASH_USERSIG_FLAG_LEN < (MEM_MEMORY_MAP_VERSION_ADDR + 4) || FLASH_USERSIG_FLAG_LEN >= 0x0100)
#error "Incorrect macro value for memory map"
#endif
#define MEM_NAME_ADDR                   0x0100// (32 bytes) Zone 1
#define MEM_MAP_ADDRS           /*V0*/  /*V1*/  /* Memory map version */\
X(MASTER_BIP32,                 0x0200, 0x0280)\
X(MASTER_BIP32_CHAIN,           0x0300, 0x0380)\
X(AESKEY_STAND,                 0x0400, 0x0480)\
X(AESKEY_VERIFY,                0x0500, 0x0580)\
X(AESKEY_HIDDEN,                0x0800, 0x0880)\
X(MASTER_ENTROPY,               0x0900, 0x0980)\
X(MASTER_U2F,                   0x0A00, 0x0A80)\
X(HIDDEN_BIP32,                 0x0B00, 0x0C80)\
X(HIDDEN_BIP32_CHAIN,           0x0B80, 0x0D80)\
X(MAP_NUM,                      0x0FFF, 0x0FFF)/* keep last */
#define X(a, b, c) MEM_ ## a ## _ADDR_IDX,
enum MEM_MAPPING_ENUM { MEM_MAP_ADDRS };
#undef X
#define X(a, b, c) b,
uint16_t MEM_ADDR_V0[] = { MEM_MAP_ADDRS };
#undef X
#define X(a, b, c) c,
uint16_t MEM_ADDR_V1[] = { MEM_MAP_ADDRS };
#undef X
// Default settings
#define DEFAULT_unlocked                0xFF
#define DEFAULT_erased                  0xFF
#define DEFAULT_setup                   0xFF
#define DEFAULT_u2f_count               0xFFFFFFFF
#define DEFAULT_ext_flags               0xFFFFFFFF// U2F and U2F_hijack enabled by default
#define DEFAULT_memory_map_version      0xFFFFFFFF
// Version settings
#define MEM_MAP_V0                      DEFAULT_memory_map_version
#define MEM_MAP_V1                      0x00000001
#define ACTIVE_memory_map_version       MEM_MAP_V1


static uint8_t MEM_unlocked = DEFAULT_unlocked;
static uint8_t MEM_erased = DEFAULT_erased;
static uint8_t MEM_setup = DEFAULT_setup;
static uint32_t MEM_ext_flags = DEFAULT_ext_flags;
static uint32_t MEM_u2f_count = DEFAULT_u2f_count;
static uint16_t MEM_pin_err = DBB_ACCESS_INITIALIZE;
static uint16_t MEM_access_err = DBB_ACCESS_INITIALIZE;
static uint32_t MEM_memory_map_version = DEFAULT_memory_map_version;

__extension__ static uint8_t MEM_active_key[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_user_entropy[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_stand[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_hidden[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_aeskey_verify[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_hww_entropy[] = {[0 ... MEM_PAGE_LEN - 1] = 0x00};
__extension__ static uint8_t MEM_master_hww_chain[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_hww[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_hidden_hww_chain[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_hidden_hww[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_master_u2f[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ static uint8_t MEM_name[] = {[0 ... MEM_PAGE_LEN - 1] = '0'};

__extension__ const uint8_t MEM_PAGE_ERASE[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
__extension__ const uint16_t MEM_PAGE_ERASE_2X[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFFFF};
__extension__ const uint8_t MEM_PAGE_ERASE_FE[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFE};


static uint8_t memory_eeprom(uint8_t *write_b, uint8_t *read_b, int32_t addr,
                             uint16_t len)
{
    // read current memory
    if (ataes_eeprom(len, addr, read_b, NULL) != DBB_OK) {
        commander_fill_report(cmd_str(CMD_ataes), NULL, DBB_ERR_MEM_ATAES);
        return DBB_ERROR;
    }
    if (write_b) {
        // skip writing if memory does not change
        if (read_b) {
            if (MEMEQ(read_b, write_b, len)) {
                return DBB_OK;
            }
        }
        if (ataes_eeprom(len, addr, read_b, write_b) != DBB_OK) {
            commander_fill_report(cmd_str(CMD_ataes), NULL, DBB_ERR_MEM_ATAES);
            return DBB_ERROR;
        }
        if (read_b) {
            if (MEMEQ(write_b, read_b, len)) {
                return DBB_OK;
            } else {
                // error
                if (len > 2) {
                    memcpy(read_b, MEM_PAGE_ERASE, len);
                }
                return DBB_ERROR;
            }
        }
    }
    return DBB_OK;
}


static uint8_t *memory_crunch(uint8_t *seed, uint8_t seed_len, uint8_t force)
{
    static uint16_t crunched = 0;
    __extension__ static uint8_t data[] = {[0 ... ATAES_CRUNCH_DATA_LEN - 1] = 0xFF};
    __extension__ uint8_t ataes_cmd[] = {[0 ... ATAES_CMD_HEADER_LEN + ATAES_CRUNCH_SEED_LEN - 1] = 0};
    __extension__ uint8_t ataes_ret[] = {[0 ... ATAES_RET_FRAME_LEN + ATAES_CRUNCH_DATA_LEN - 1] = 0};
    if (!(crunched % ATAES_CRUNCH_REFRESH) || force) {
        uint8_t n, ret;
        ataes_cmd[0] = ATAES_CRUNCH_CMD;
        ataes_cmd[3] = ATAES_CRUNCH_COUNT;
        for (n = 0; n < MIN(seed_len, ATAES_CRUNCH_SEED_LEN); n++) {
            ataes_cmd[ATAES_CMD_HEADER_LEN + n] = seed[n];
        }
        ret = ataes_process(ataes_cmd, sizeof(ataes_cmd), ataes_ret, sizeof(ataes_ret));
        if (ret != DBB_OK || !ataes_ret[0] || ataes_ret[1]) {
            HardFault_Handler();
        }
        for (n = 0; n < MIN(seed_len, ATAES_CRUNCH_DATA_LEN); n++) {
            data[n] = seed[n] ^ ataes_ret[n + 2];
        }
    }
    crunched++;
    return data;
}


// Encrypted storage
// `write_b` and `read_b` must be length `MEM_PAGE_LEN`
static uint8_t memory_eeprom_crypt(const uint8_t *write_b, uint8_t *read_b,
                                   uint8_t map_addr, uint32_t map_version)
{
    int enc_len, dec_len, i;
    char *enc, *dec, enc_r[MEM_PAGE_LEN * 4 + 1] = {0};
    static uint8_t mempass[MEM_PAGE_LEN], authkey[MEM_PAGE_LEN], hmac[MEM_PAGE_LEN];
    int32_t addr;

    switch (map_version) {
        case MEM_MAP_V0:
            addr = MEM_ADDR_V0[map_addr];
            break;
        case MEM_MAP_V1:
            addr = MEM_ADDR_V1[map_addr];
            break;
        default:
            goto err;
    }

    // Encrypt data saved to memory using an AES key obfuscated by the
    // bootloader bytes.
    memset(mempass, 0, sizeof(mempass));
    uint8_t rn[FLASH_USERSIG_RN_LEN] = {0};
#ifndef TESTING
    sha256_Raw((uint8_t *)(FLASH_BOOT_START), FLASH_BOOT_LEN, mempass);
#endif
    flash_read_user_signature((uint32_t *)rn, FLASH_USERSIG_RN_LEN / sizeof(uint32_t));
    if (!MEMEQ(rn, MEM_PAGE_ERASE, FLASH_USERSIG_RN_LEN)) {
        hmac_sha256(mempass, MEM_PAGE_LEN, rn, FLASH_USERSIG_RN_LEN, mempass);
    }
    sha256_Raw(mempass, MEM_PAGE_LEN, mempass);
    switch (map_version) {
        case MEM_MAP_V0:
            sha256_Raw((const uint8_t *)(utils_uint8_to_hex(mempass, MEM_PAGE_LEN)), MEM_PAGE_LEN * 2,
                       mempass);
            sha256_Raw(mempass, MEM_PAGE_LEN, mempass);
            break;
        case MEM_MAP_V1: {
            uint8_t *data = memory_crunch(rn, sizeof(rn), 0);
            aes_derive_hmac_keys(mempass, mempass, authkey);
            hmac_sha256(mempass, MEM_PAGE_LEN, data, ATAES_CRUNCH_DATA_LEN, mempass);
            break;
        }
        default:
            goto err;
    }

    if (read_b) {
        switch (map_version) {
            case MEM_MAP_V0:
                enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(read_b, MEM_PAGE_LEN),
                                          MEM_PAGE_LEN * 2, &enc_len, mempass);
                if (!enc) {
                    goto err;
                }
                snprintf(enc_r, sizeof(enc_r), "%.*s", enc_len, enc);
                utils_zero(enc, enc_len);
                free(enc);
                break;
            case MEM_MAP_V1:
                enc = (char *)aes_cbc_init_encrypt((unsigned char *)read_b, MEM_PAGE_LEN, &enc_len,
                                                   mempass);
                if (!enc) {
                    goto err;
                }
                if (sizeof(enc_r) < enc_len + sizeof(hmac)) {
                    utils_zero(enc, enc_len);
                    free(enc);
                    goto err;
                }
                hmac_sha256(authkey, MEM_PAGE_LEN, (uint8_t *)enc, enc_len, hmac);
                memset(enc_r, 0, sizeof(enc_r));
                memcpy(enc_r, enc, enc_len);
                memcpy(enc_r + enc_len, hmac, sizeof(hmac));
                utils_zero(enc, enc_len);
                free(enc);
                break;
            default:
                goto err;
        }
    }

    if (write_b) {
        char enc_w[MEM_PAGE_LEN * 4 + 1];
        memset(enc_w, 0xFF, sizeof(enc_w));
        enc_w[MEM_PAGE_LEN * 4] = '\0';
        switch (map_version) {
            case MEM_MAP_V0:
                enc = aes_cbc_b64_encrypt((unsigned char *)utils_uint8_to_hex(write_b, MEM_PAGE_LEN),
                                          MEM_PAGE_LEN * 2, &enc_len, mempass);
                if (!enc) {
                    goto err;
                }
                snprintf(enc_w, sizeof(enc_w), "%.*s", enc_len, enc);
                utils_zero(enc, enc_len);
                free(enc);
                break;
            case MEM_MAP_V1:
                enc = (char *)aes_cbc_init_encrypt((const unsigned char *)write_b, MEM_PAGE_LEN, &enc_len,
                                                   mempass);
                if (!enc) {
                    goto err;
                }
                if (sizeof(enc_w) < enc_len + sizeof(hmac)) {
                    utils_zero(enc, enc_len);
                    free(enc);
                    goto err;
                }
                hmac_sha256(authkey, MEM_PAGE_LEN, (uint8_t *)enc, enc_len, hmac);
                memcpy(enc_w, enc, enc_len);
                memcpy(enc_w + enc_len, hmac, sizeof(hmac));
                utils_zero(enc, enc_len);
                free(enc);
                break;
            default:
                goto err;
        }
        for (i = 0; i < 4; i++) {
            if (memory_eeprom((uint8_t *)enc_w + MEM_PAGE_LEN * i,
                              (uint8_t *)enc_r + MEM_PAGE_LEN * i, addr + MEM_PAGE_LEN * i,
                              MEM_PAGE_LEN) == DBB_ERROR) {
                goto err;
            }
        }
    } else if (read_b) {
        for (i = 0; i < 4; i++) {
            if (memory_eeprom(NULL, (uint8_t *)enc_r + MEM_PAGE_LEN * i, addr + MEM_PAGE_LEN * i,
                              MEM_PAGE_LEN) == DBB_ERROR) {
                goto err;
            }
        }
    } else {
        goto err;
    }

    switch (map_version) {
        case MEM_MAP_V0:
            dec = aes_cbc_b64_decrypt((unsigned char *)enc_r, MEM_PAGE_LEN * 4, &dec_len, mempass);
            break;
        case MEM_MAP_V1:
            enc_len = MEM_PAGE_LEN + N_BLOCK + N_BLOCK - (MEM_PAGE_LEN % N_BLOCK);
            hmac_sha256(authkey, MEM_PAGE_LEN, (uint8_t *)enc_r, enc_len, hmac);
            if (!MEMEQ(hmac, enc_r + enc_len, sizeof(hmac))) {
                goto err;
            }
            dec = aes_cbc_init_decrypt((unsigned char *)enc_r, enc_len, &dec_len, mempass);
            break;
        default:
            goto err;
    }
    if (!dec) {
        goto err;
    }

    if (read_b) {
        switch (map_version) {
            case MEM_MAP_V0:
                memcpy(read_b, utils_hex_to_uint8(dec), MEM_PAGE_LEN);
                break;
            case MEM_MAP_V1:
                memcpy(read_b, dec, MEM_PAGE_LEN);
                break;
            default:
                goto err;
        }
    }
    utils_zero(dec, dec_len);
    free(dec);

    utils_zero(hmac, sizeof(hmac));
    utils_zero(mempass, MEM_PAGE_LEN);
    utils_clear_buffers();
    return DBB_OK;
err:
    if (read_b) {
        // Randomize return value on error
        hmac_sha256(mempass, MEM_PAGE_LEN, read_b, MEM_PAGE_LEN, read_b);
    }
    utils_zero(hmac, sizeof(hmac));
    utils_zero(mempass, MEM_PAGE_LEN);
    utils_clear_buffers();
    return DBB_ERROR;
}


static void memory_byte_flag(uint8_t *write_b, uint8_t *read_b,
                             int32_t addr, uint8_t byte_len)
{
    uint8_t usersig[FLASH_USERSIG_SIZE];
    if (memory_eeprom(write_b, read_b, addr, byte_len) != DBB_OK) {
        goto err;
    }
    if (MEM_memory_map_version != DEFAULT_memory_map_version) {
        if (flash_read_user_signature((uint32_t *)usersig,
                                      FLASH_USERSIG_SIZE / sizeof(uint32_t))) {
            goto err;
        }
        if (write_b) {
            if (!MEMEQ(usersig + FLASH_USERSIG_FLAG_START + addr, write_b, byte_len)) {
                memcpy(usersig + FLASH_USERSIG_FLAG_START + addr, write_b, byte_len);
                flash_erase_user_signature();
                flash_write_user_signature((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
            }
        }
        if (!MEMEQ(usersig + FLASH_USERSIG_FLAG_START + addr, read_b, byte_len)) {
            goto err;
        }
    }
    utils_zero(usersig, sizeof(usersig));
    return;
err:
    utils_zero(usersig, sizeof(usersig));
    memory_reset_hww();
}


static void memory_write_setup(uint8_t setup)
{
    memory_byte_flag(&setup, &MEM_setup, MEM_SETUP_ADDR, sizeof(MEM_setup));
}


static uint8_t memory_read_setup(void)
{
    memory_byte_flag(NULL, &MEM_setup, MEM_SETUP_ADDR, sizeof(MEM_setup));
    return MEM_setup;
}


static void memory_write_memory_map_version(uint32_t v)
{
    memory_byte_flag((uint8_t *)&v, (uint8_t *)&MEM_memory_map_version,
                     MEM_MEMORY_MAP_VERSION_ADDR, sizeof(MEM_memory_map_version));
}


static uint32_t memory_read_memory_map_version(void)
{
    memory_byte_flag(NULL, (uint8_t *)&MEM_memory_map_version, MEM_MEMORY_MAP_VERSION_ADDR,
                     sizeof(MEM_memory_map_version));
    return MEM_memory_map_version;
}


static void memory_scramble_default_aeskeys(void)
{
    uint8_t number[32] = {0};
    random_bytes(number, sizeof(number), 0);
    memcpy(MEM_aeskey_stand, number, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_hidden, number, MEM_PAGE_LEN);
    memcpy(MEM_aeskey_verify, number, MEM_PAGE_LEN);
    memcpy(MEM_active_key, number, MEM_PAGE_LEN);
}


static void memory_scramble_rn(void)
{
    uint32_t i = 0;
    uint8_t usersig[FLASH_USERSIG_SIZE];
    uint8_t number[FLASH_USERSIG_RN_LEN] = {0};
    random_bytes(number, FLASH_USERSIG_RN_LEN, 0);
    flash_read_user_signature((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
    for (i = 0; i < FLASH_USERSIG_RN_LEN; i++) {
        usersig[i] ^= number[i];
    }
    memory_crunch(usersig, FLASH_USERSIG_RN_LEN, 1);
    flash_erase_user_signature();
    flash_write_user_signature((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
}


void memory_setup(void)
{
    if (memory_read_setup()) {
        // One-time setup on factory install
        // Lock Config Memory:              OP       MODE  PARAMETER1  PARAMETER2
        const uint8_t ataes_cmd[] = {ATAES_LOCK_CMD, 0x02, 0x00, 0x00, 0x00, 0x00};
        // Return packet [Count(1) || Return Code (1) || CRC (2)]
        uint8_t ataes_ret[ATAES_RET_FRAME_LEN] = {0};
        uint8_t ret = ataes_process(ataes_cmd, sizeof(ataes_cmd), ataes_ret, sizeof(ataes_ret));
        if (ret != DBB_OK || !ataes_ret[0] || ataes_ret[1]) {
            HardFault_Handler();
        }
        uint32_t c = 0x00000000;
        memory_write_memory_map_version(ACTIVE_memory_map_version);
        memory_reset_hww();
        memory_reset_u2f();
        memory_u2f_count_set(c);
        memory_write_setup(0x00);
    } else {
        memory_update_memory_map();
        memory_read_ext_flags();
        memory_read_erased();
        memory_master_u2f(NULL);// Load cache so that U2F speed is fast enough
        memory_read_access_err_count();// Load cache
        memory_u2f_count_read();
    }
    memory_scramble_default_aeskeys();
}


void memory_update_memory_map(void)
{
    // Future mappings can be updated sequentially through memory map versions.
    // This is useful, for example, if a firmware upgrade that updated a mapping was skipped.

    switch (memory_read_memory_map_version()) {
        case DEFAULT_memory_map_version: {
            // Remap ECC and AES key memory
            {
                __extension__ uint8_t reset[] = {[0 ... MEM_PAGE_LEN - 1] = 0xFF};
                uint8_t a, i, mem0[MEM_PAGE_LEN], mem1[MEM_PAGE_LEN], ret0, ret1;
                uint16_t addr_idx;
                uint16_t addr_idxs[MEM_MAP_NUM_ADDR_IDX] = {
                    MEM_MASTER_ENTROPY_ADDR_IDX,
                    MEM_MASTER_BIP32_ADDR_IDX,
                    MEM_MASTER_BIP32_CHAIN_ADDR_IDX,
                    MEM_HIDDEN_BIP32_ADDR_IDX,
                    MEM_HIDDEN_BIP32_CHAIN_ADDR_IDX,
                    MEM_AESKEY_STAND_ADDR_IDX,
                    MEM_AESKEY_VERIFY_ADDR_IDX,
                    MEM_AESKEY_HIDDEN_ADDR_IDX,
                    MEM_MASTER_U2F_ADDR_IDX,
                };
                memset(mem0, 0xFF, sizeof(mem0));
                memset(mem1, 0xFF, sizeof(mem1));
                for (a = 0; a < sizeof(addr_idxs) / sizeof(uint16_t); a++) {
                    addr_idx = addr_idxs[a];
                    while (1) {
                        ret0 = memory_eeprom_crypt(NULL, mem0, addr_idx, MEM_MAP_V0);
                        ret1 = memory_eeprom_crypt(NULL, mem1, addr_idx, MEM_MAP_V1);
                        if (ret0 == DBB_OK && ret1 != DBB_OK) {
                            // Copy memory; `continue` to verify the value was copied correctly
                            memory_eeprom_crypt(mem0, mem1, addr_idx, MEM_MAP_V1);
                            continue;
                        }
                        if (ret0 == DBB_OK && ret1 == DBB_OK) {
                            if (MEMEQ(mem0, mem1, MEM_PAGE_LEN)) {
                                // Set the old memory location to chip default 0xFF
                                for (i = 0; i < 4; i++) {
                                    memory_eeprom(reset, NULL, MEM_ADDR_V0[addr_idx] + MEM_PAGE_LEN * i, MEM_PAGE_LEN);
                                }
                            } else {
                                // Unexpected outcome; erase old memory location; set new memory location to chip default 0xFF
                                memory_eeprom_crypt(MEM_PAGE_ERASE, mem0, addr_idx, MEM_MAP_V0);
                                for (i = 0; i < 4; i++) {
                                    memory_eeprom(reset, NULL, MEM_ADDR_V1[addr_idx] + MEM_PAGE_LEN * i, MEM_PAGE_LEN);
                                }
                            }
                            continue;
                        }
                        if (ret0 != DBB_OK && ret1 == DBB_OK) {
                            // Remap completed
                            break;
                        }
                        if (ret0 != DBB_OK && ret1 != DBB_OK) {
                            // Unexpected condition; erase old memory location
                            memory_eeprom_crypt(MEM_PAGE_ERASE, mem0, addr_idx, MEM_MAP_V0);
                            continue;
                        }
                    }
                }
            }
            // Copy settings flags to FLASH
            {
                uint8_t usersig[FLASH_USERSIG_SIZE];
                uint8_t flags[FLASH_USERSIG_FLAG_LEN];
                memory_eeprom(NULL, flags, 0, sizeof(flags));
                flash_read_user_signature((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
                memcpy(usersig + FLASH_USERSIG_FLAG_START, flags, sizeof(flags));
                flash_erase_user_signature();
                flash_write_user_signature((uint32_t *)usersig, FLASH_USERSIG_SIZE / sizeof(uint32_t));
            }
            // Update map version
            memory_write_memory_map_version(MEM_MAP_V1);
            /* FALLTHROUGH */
        }
        case ACTIVE_memory_map_version:
            break;
        default:
            commander_force_reset();
    }
}


void memory_erase_hww_seed(void)
{
    memory_master_hww_entropy(MEM_PAGE_ERASE);
    memory_master_hww_chaincode(MEM_PAGE_ERASE);
    memory_master_hww(MEM_PAGE_ERASE);
    memory_hidden_hww_chaincode(MEM_PAGE_ERASE_FE);
    memory_hidden_hww(MEM_PAGE_ERASE_FE);
    memory_random_password(PASSWORD_HIDDEN);
}

void memory_reset_hww(void)
{
    uint8_t u2f[MEM_PAGE_LEN];
    memcpy(u2f, MEM_master_u2f, MEM_PAGE_LEN);
    memory_scramble_rn();
    memory_master_u2f(u2f);
    memory_random_password(PASSWORD_STAND);
    memory_random_password(PASSWORD_VERIFY);
    memory_random_password(PASSWORD_HIDDEN);
    memory_erase_hww_seed();
    memory_name(DEVICE_DEFAULT_NAME);
    memory_write_erased(DEFAULT_erased);
    memory_write_unlocked(DEFAULT_unlocked);
    memory_write_ext_flags(DEFAULT_ext_flags);
    memory_access_err_count(DBB_ACCESS_INITIALIZE);
    memory_pin_err_count(DBB_ACCESS_INITIALIZE);
    utils_zero(u2f, sizeof(u2f));
}


void memory_reset_u2f(void)
{
    // Create random master U2F key. It is independent of the HWW.
    // U2F is functional on fresh device without a seeded wallet.
    uint8_t number[32] = {0};
    random_bytes(number, sizeof(number), 0);
    memory_master_u2f(number);
    utils_zero(number, sizeof(number));
}


void memory_random_password(PASSWORD_ID id)
{
    uint8_t number[16] = {0};
    random_bytes(number, sizeof(number), 0);
    memory_write_aeskey(utils_uint8_to_hex(number, sizeof(number)), sizeof(number) * 2, id);
    utils_zero(number, sizeof(number));
    utils_clear_buffers();
}


void memory_clear(void)
{
    // Zero important variables in RAM on embedded MCU.
    memcpy(MEM_hidden_hww_chain, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_hidden_hww, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_hww_chain, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_hww, MEM_PAGE_ERASE, MEM_PAGE_LEN);
    memcpy(MEM_master_hww_entropy, MEM_PAGE_ERASE, MEM_PAGE_LEN);
}


uint8_t *memory_name(const char *name)
{
    uint8_t name_b[MEM_PAGE_LEN] = {0};
    if (strlens(name)) {
        snprintf((char *)name_b, MEM_PAGE_LEN, "%s", name);
        memory_eeprom(name_b, MEM_name, MEM_NAME_ADDR, MEM_PAGE_LEN);
    } else {
        memory_eeprom(NULL, MEM_name, MEM_NAME_ADDR, MEM_PAGE_LEN);
    }
    return MEM_name;
}


uint8_t *memory_hidden_hww(const uint8_t *master)
{
    memory_eeprom_crypt(NULL, MEM_hidden_hww, MEM_HIDDEN_BIP32_ADDR_IDX,
                        MEM_memory_map_version);
    if ((master == NULL) && MEMEQ(MEM_hidden_hww, MEM_PAGE_ERASE, 32)) {
        // Backward compatible with firmware <=2.2.3
        return memory_master_hww_chaincode(NULL);
    }
    memory_eeprom_crypt(master, MEM_hidden_hww, MEM_HIDDEN_BIP32_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_hidden_hww;
}


uint8_t *memory_hidden_hww_chaincode(const uint8_t *chain)
{
    memory_eeprom_crypt(NULL, MEM_hidden_hww_chain, MEM_HIDDEN_BIP32_CHAIN_ADDR_IDX,
                        MEM_memory_map_version);
    if ((chain == NULL) && MEMEQ(MEM_hidden_hww_chain, MEM_PAGE_ERASE, 32)) {
        // Backward compatible with firmware <=2.2.3
        return memory_master_hww(NULL);
    }
    memory_eeprom_crypt(chain, MEM_hidden_hww_chain, MEM_HIDDEN_BIP32_CHAIN_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_hidden_hww_chain;
}


uint8_t *memory_master_hww(const uint8_t *master)
{
    memory_eeprom_crypt(master, MEM_master_hww, MEM_MASTER_BIP32_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_master_hww;
}


uint8_t *memory_master_hww_chaincode(const uint8_t *chain)
{
    memory_eeprom_crypt(chain, MEM_master_hww_chain, MEM_MASTER_BIP32_CHAIN_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_master_hww_chain;
}


uint8_t *memory_master_hww_entropy(const uint8_t *master_entropy)
{
    memory_eeprom_crypt(master_entropy, MEM_master_hww_entropy, MEM_MASTER_ENTROPY_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_master_hww_entropy;
}


uint8_t *memory_master_u2f(const uint8_t *master_u2f)
{
    memory_eeprom_crypt(master_u2f, MEM_master_u2f, MEM_MASTER_U2F_ADDR_IDX,
                        MEM_memory_map_version);
    return MEM_master_u2f;
}


uint8_t *memory_report_master_u2f(void)
{
    return MEM_master_u2f;
}


void memory_active_key_set(uint8_t *key)
{
    if (key) {
        memcpy(MEM_active_key, key, MEM_PAGE_LEN);
    }
}


uint8_t *memory_active_key_get(void)
{
    return MEM_active_key;
}


uint8_t memory_write_aeskey(const char *password, int len, PASSWORD_ID id)
{
    int ret = 0;
    uint8_t password_b[MEM_PAGE_LEN];
    memset(password_b, 0, MEM_PAGE_LEN);

    if (len < PASSWORD_LEN_MIN || strlens(password) < PASSWORD_LEN_MIN) {
        return DBB_ERR_IO_PASSWORD_LEN;
    }

    sha256_Raw((const uint8_t *)password, len, password_b);
    sha256_Raw(password_b, MEM_PAGE_LEN, password_b);

    switch ((int)id) {
        case PASSWORD_STAND:
            memcpy(MEM_aeskey_stand, password_b, MEM_PAGE_LEN);
            break;
        case PASSWORD_HIDDEN:
            memcpy(MEM_aeskey_hidden, password_b, MEM_PAGE_LEN);
            break;
        case PASSWORD_VERIFY:
            memcpy(MEM_aeskey_verify, password_b, MEM_PAGE_LEN);
            break;
        default: {
            /* never reached */
        }
    }

    ret |= memory_eeprom_crypt(MEM_aeskey_stand, MEM_aeskey_stand,
                               MEM_AESKEY_STAND_ADDR_IDX, MEM_memory_map_version) - DBB_OK;
    ret |= memory_eeprom_crypt(MEM_aeskey_hidden, MEM_aeskey_hidden,
                               MEM_AESKEY_HIDDEN_ADDR_IDX, MEM_memory_map_version) - DBB_OK;
    ret |= memory_eeprom_crypt(MEM_aeskey_verify, MEM_aeskey_verify,
                               MEM_AESKEY_VERIFY_ADDR_IDX, MEM_memory_map_version) - DBB_OK;

    utils_zero(password_b, MEM_PAGE_LEN);

    if (ret) {
        return DBB_ERR_MEM_ATAES;
    } else {
        return DBB_OK;
    }
}


void memory_read_aeskeys(void)
{
    static uint8_t read = 0;
    if (!read) {
        memory_eeprom_crypt(NULL, MEM_aeskey_stand, MEM_AESKEY_STAND_ADDR_IDX,
                            MEM_memory_map_version);
        memory_eeprom_crypt(NULL, MEM_aeskey_hidden, MEM_AESKEY_HIDDEN_ADDR_IDX,
                            MEM_memory_map_version);
        memory_eeprom_crypt(NULL, MEM_aeskey_verify, MEM_AESKEY_VERIFY_ADDR_IDX,
                            MEM_memory_map_version);
        sha256_Raw(MEM_aeskey_stand, MEM_PAGE_LEN, MEM_user_entropy);
        read++;
    }
}


uint8_t *memory_report_aeskey(PASSWORD_ID id)
{
    switch ((int)id) {
        case PASSWORD_STAND:
            return MEM_aeskey_stand;
        case PASSWORD_HIDDEN:
            return MEM_aeskey_hidden;
        case PASSWORD_VERIFY:
            return MEM_aeskey_verify;
        default:
            return NULL;
    }
}


uint8_t *memory_report_user_entropy(void)
{
    return MEM_user_entropy;
}


uint8_t memory_report_setup(void)
{
    return MEM_setup;
}


void memory_write_unlocked(uint8_t u)
{
    memory_byte_flag(&u, &MEM_unlocked, MEM_UNLOCKED_ADDR, sizeof(MEM_unlocked));
}
uint8_t memory_read_unlocked(void)
{
    memory_byte_flag(NULL, &MEM_unlocked, MEM_UNLOCKED_ADDR, sizeof(MEM_unlocked));
    return MEM_unlocked;
}


void memory_write_erased(uint8_t erased)
{
    memory_byte_flag(&erased, &MEM_erased, MEM_ERASED_ADDR, sizeof(MEM_erased));
}
uint8_t memory_read_erased(void)
{
    memory_byte_flag(NULL, &MEM_erased, MEM_ERASED_ADDR, sizeof(MEM_erased));
    return MEM_erased;
}
uint8_t memory_report_erased(void)
{
    return MEM_erased;
}


uint16_t memory_access_err_count(const uint8_t access)
{
    uint16_t err_count = 0xF0F0;
    if (access == DBB_ACCESS_ITERATE) {
        memory_byte_flag(NULL, (uint8_t *)&MEM_access_err, MEM_ACCESS_ERR_ADDR,
                         sizeof(MEM_access_err));
        err_count = MEM_access_err + 1;
    } else if (access == DBB_ACCESS_INITIALIZE) {
        err_count = 0;
    } else {
        err_count = COMMANDER_MAX_ATTEMPTS; // corrupted input
    }

    // Force reset after too many failed attempts
    if (err_count >= COMMANDER_MAX_ATTEMPTS) {
        commander_force_reset();
    } else {
        memory_byte_flag((uint8_t *)&err_count, (uint8_t *)&MEM_access_err,
                         MEM_ACCESS_ERR_ADDR, sizeof(MEM_access_err));
    }
    return err_count;
}
uint16_t memory_read_access_err_count(void)
{
    memory_byte_flag(NULL, (uint8_t *)&MEM_access_err, MEM_ACCESS_ERR_ADDR,
                     sizeof(MEM_access_err));
    return MEM_access_err;
}
uint16_t memory_report_access_err_count(void)
{
    return MEM_access_err;
}


uint16_t memory_pin_err_count(const uint8_t access)
{
    uint16_t err_count = 0xF0F0;
    if (access == DBB_ACCESS_ITERATE) {
        memory_byte_flag(NULL, (uint8_t *)&MEM_pin_err, MEM_PIN_ERR_ADDR, sizeof(MEM_pin_err));
        err_count = MEM_pin_err + 1;
    } else if (access == DBB_ACCESS_INITIALIZE) {
        err_count = 0;
    } else {
        err_count = COMMANDER_MAX_ATTEMPTS; // corrupted input
    }

    // Force reset after too many failed attempts
    if (err_count >= COMMANDER_MAX_ATTEMPTS) {
        commander_force_reset();
    } else {
        memory_byte_flag((uint8_t *)&err_count, (uint8_t *)&MEM_pin_err, MEM_PIN_ERR_ADDR,
                         sizeof(MEM_pin_err));
    }
    return err_count;
}
uint16_t memory_read_pin_err_count(void)
{
    memory_byte_flag(NULL, (uint8_t *)&MEM_pin_err, MEM_PIN_ERR_ADDR, sizeof(MEM_pin_err));
    return MEM_pin_err;
}


uint32_t memory_u2f_count_iter(void)
{
    uint32_t c;
    memory_u2f_count_read();
    c = MEM_u2f_count + 1;
    memory_eeprom((uint8_t *)&c, (uint8_t *)&MEM_u2f_count, MEM_U2F_COUNT_ADDR,
                  sizeof(MEM_u2f_count));
    return MEM_u2f_count;
}
void memory_u2f_count_set(uint32_t c)
{
    memory_eeprom((uint8_t *)&c, (uint8_t *)&MEM_u2f_count, MEM_U2F_COUNT_ADDR,
                  sizeof(MEM_u2f_count));
}
uint32_t memory_u2f_count_read(void)
{
    memory_eeprom(NULL, (uint8_t *)&MEM_u2f_count, MEM_U2F_COUNT_ADDR, sizeof(MEM_u2f_count));
    return MEM_u2f_count;
}


void memory_write_ext_flags(uint32_t flags)
{
    memory_byte_flag((uint8_t *)&flags, (uint8_t *)&MEM_ext_flags, MEM_EXT_FLAGS_ADDR,
                     sizeof(MEM_ext_flags));
}
uint32_t memory_read_ext_flags(void)
{
    memory_byte_flag(NULL, (uint8_t *)&MEM_ext_flags, MEM_EXT_FLAGS_ADDR,
                     sizeof(MEM_ext_flags));
    return MEM_ext_flags;
}
uint32_t memory_report_ext_flags(void)
{
    return MEM_ext_flags;
}
