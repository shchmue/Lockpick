/*
 * Copyright (c) 2018 shchmue
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "KeyCollection.hpp"

#include "Common.hpp"
#include "Stopwatch.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <stdio.h>

#include <switch.h>

#include "fatfs/ff.h"

extern "C" {
    #include "nx/es.h"
    #include "nx/set_ext.h"
}

#define TITLEKEY_BUFFER_SIZE 0x40000

// hash of empty string
const u8 KeyCollection::null_hash[0x20] = {
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
        0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55};

FsStorage storage;

// function timer
template<typename Duration = std::chrono::microseconds, typename FT, typename ... Args>
typename Duration::rep profile(FT&& fun, Args&&... args) {
    const auto beg = std::chrono::high_resolution_clock::now();
    std::invoke(fun, std::forward<Args>(args)...);
    const auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<Duration>(end - beg).count();
}

KeyCollection::KeyCollection() {
    // init all key hashes
    u8 index = 0;
    char keynum[] = "00";

    for (auto key : std::vector<byte_vector>
    {
        {0xDF, 0x20, 0x6F, 0x59, 0x44, 0x54, 0xEF, 0xDC, 0x70, 0x74, 0x48, 0x3B, 0x0D, 0xED, 0x9F, 0xD3},
        {0x0C, 0x25, 0x61, 0x5D, 0x68, 0x4C, 0xEB, 0x42, 0x1C, 0x23, 0x79, 0xEA, 0x82, 0x25, 0x12, 0xAC},
        {0x33, 0x76, 0x85, 0xEE, 0x88, 0x4A, 0xAE, 0x0A, 0xC2, 0x8A, 0xFD, 0x7D, 0x63, 0xC0, 0x43, 0x3B},
        {0x2D, 0x1F, 0x48, 0x80, 0xED, 0xEC, 0xED, 0x3E, 0x3C, 0xF2, 0x48, 0xB5, 0x65, 0x7D, 0xF7, 0xBE},
        {0xBB, 0x5A, 0x01, 0xF9, 0x88, 0xAF, 0xF5, 0xFC, 0x6C, 0xFF, 0x07, 0x9E, 0x13, 0x3C, 0x39, 0x80},
        {0xD8, 0xCC, 0xE1, 0x26, 0x6A, 0x35, 0x3F, 0xCC, 0x20, 0xF3, 0x2D, 0x3B, 0x51, 0x7D, 0xE9, 0xC0}
    })
    {
        sprintf(keynum, "%02x", index++);
        keyblob_key_source.push_back(Key {"keyblob_key_source_" + std::string(keynum), 0x10, key});
    }

    for (auto key : std::vector<byte_vector>
    {
        {0x0C, 0xF0, 0x59, 0xAC, 0x85, 0xF6, 0x26, 0x65, 0xE1, 0xE9, 0x19, 0x55, 0xE6, 0xF2, 0x67, 0x3D}, /* Zeroes encrypted with Master Key 00. */
        {0x29, 0x4C, 0x04, 0xC8, 0xEB, 0x10, 0xED, 0x9D, 0x51, 0x64, 0x97, 0xFB, 0xF3, 0x4D, 0x50, 0xDD}, /* Master key 00 encrypted with Master key 01. */
        {0xDE, 0xCF, 0xEB, 0xEB, 0x10, 0xAE, 0x74, 0xD8, 0xAD, 0x7C, 0xF4, 0x9E, 0x62, 0xE0, 0xE8, 0x72}, /* Master key 01 encrypted with Master key 02. */
        {0x0A, 0x0D, 0xDF, 0x34, 0x22, 0x06, 0x6C, 0xA4, 0xE6, 0xB1, 0xEC, 0x71, 0x85, 0xCA, 0x4E, 0x07}, /* Master key 02 encrypted with Master key 03. */
        {0x6E, 0x7D, 0x2D, 0xC3, 0x0F, 0x59, 0xC8, 0xFA, 0x87, 0xA8, 0x2E, 0xD5, 0x89, 0x5E, 0xF3, 0xE9}, /* Master key 03 encrypted with Master key 04. */
        {0xEB, 0xF5, 0x6F, 0x83, 0x61, 0x9E, 0xF8, 0xFA, 0xE0, 0x87, 0xD7, 0xA1, 0x4E, 0x25, 0x36, 0xEE}, /* Master key 04 encrypted with Master key 05. */
        {0x1E, 0x1E, 0x22, 0xC0, 0x5A, 0x33, 0x3C, 0xB9, 0x0B, 0xA9, 0x03, 0x04, 0xBA, 0xDB, 0x07, 0x57}, /* Master key 05 encrypted with Master key 06. */
    })
    {
        mkey_vector.push_back(Key {key, 0x10});
    }

    master_kek_source.resize(KNOWN_KEYBLOBS);
    master_kek_source.push_back(Key {"master_kek_source_06", 0x10, {
        0x37, 0x4B, 0x77, 0x29, 0x59, 0xB4, 0x04, 0x30, 0x81, 0xF6, 0xE5, 0x8C, 0x6D, 0x36, 0x17, 0x9A}});

    //======================================Keys======================================//
    // from Package1 -> Secure_Monitor
    aes_kek_generation_source = {"aes_kek_generation_source", 0x10, {
        0x4D, 0x87, 0x09, 0x86, 0xC4, 0x5D, 0x20, 0x72, 0x2F, 0xBA, 0x10, 0x53, 0xDA, 0x92, 0xE8, 0xA9}};
    aes_kek_seed_01 = {"aes_kek_seed_01", 0x10, {
        0xA2, 0xAB, 0xBF, 0x9C, 0x92, 0x2F, 0xBB, 0xE3, 0x78, 0x79, 0x9B, 0xC0, 0xCC, 0xEA, 0xA5, 0x74}};
    aes_kek_seed_03 = {"aes_kek_seed_03", 0x10, {
        0xE5, 0x4D, 0x9A, 0x02, 0xF0, 0x4F, 0x5F, 0xA8, 0xAD, 0x76, 0x0A, 0xF6, 0x32, 0x95, 0x59, 0xBB}};
    package2_key_source = {"package2_key_source", 0x10, {
        0xFB, 0x8B, 0x6A, 0x9C, 0x79, 0x00, 0xC8, 0x49, 0xEF, 0xD2, 0x4D, 0x85, 0x4D, 0x30, 0xA0, 0xC7}};
    titlekek_source = {"titlekek_source", 0x10, {
        0x1E, 0xDC, 0x7B, 0x3B, 0x60, 0xE6, 0xB4, 0xD8, 0x78, 0xB8, 0x17, 0x15, 0x98, 0x5E, 0x62, 0x9B}};
    retail_specific_aes_key_source = {"retail_specific_aes_key_source", 0x10, {
        0xE2, 0xD6, 0xB8, 0x7A, 0x11, 0x9C, 0xB8, 0x80, 0xE8, 0x22, 0x88, 0x8A, 0x46, 0xFB, 0xA1, 0x95}};

    // from Package1ldr (or Secure_Monitor on 6.2.0)
    keyblob_mac_key_source = {"keyblob_mac_key_source", 0x10, {
        0x59, 0xC7, 0xFB, 0x6F, 0xBE, 0x9B, 0xBE, 0x87, 0x65, 0x6B, 0x15, 0xC0, 0x53, 0x73, 0x36, 0xA5}};
    master_key_source = {"master_key_source", 0x10, {
        0xD8, 0xA2, 0x41, 0x0A, 0xC6, 0xC5, 0x90, 0x01, 0xC6, 0x1D, 0x6A, 0x26, 0x7C, 0x51, 0x3F, 0x3C}};
    per_console_key_source = {"per_console_key_source", 0x10, {
        0x4F, 0x02, 0x5F, 0x0E, 0xB6, 0x6D, 0x11, 0x0E, 0xDC, 0x32, 0x7D, 0x41, 0x86, 0xC2, 0xF4, 0x78}};

    // from SPL
    aes_key_generation_source = {"aes_key_generation_source", 0x10, {
        0x89, 0x61, 0x5E, 0xE0, 0x5C, 0x31, 0xB6, 0x80, 0x5F, 0xE5, 0x8F, 0x3D, 0xA2, 0x4F, 0x7A, 0xA8}};

    // from FS
    bis_kek_source = {"bis_kek_source", 0x10, {
        0x34, 0xC1, 0xA0, 0xC4, 0x82, 0x58, 0xF8, 0xB4, 0xFA, 0x9E, 0x5E, 0x6A, 0xDA, 0xFC, 0x7E, 0x4F}};
    bis_key_source_00 = {"bis_key_source_00", 0x20, {
        0xF8, 0x3F, 0x38, 0x6E, 0x2C, 0xD2, 0xCA, 0x32, 0xA8, 0x9A, 0xB9, 0xAA, 0x29, 0xBF, 0xC7, 0x48,
        0x7D, 0x92, 0xB0, 0x3A, 0xA8, 0xBF, 0xDE, 0xE1, 0xA7, 0x4C, 0x3B, 0x6E, 0x35, 0xCB, 0x71, 0x06}};
    bis_key_source_01 = {"bis_key_source_01", 0x20, {
        0x41, 0x00, 0x30, 0x49, 0xDD, 0xCC, 0xC0, 0x65, 0x64, 0x7A, 0x7E, 0xB4, 0x1E, 0xED, 0x9C, 0x5F,
        0x44, 0x42, 0x4E, 0xDA, 0xB4, 0x9D, 0xFC, 0xD9, 0x87, 0x77, 0x24, 0x9A, 0xDC, 0x9F, 0x7C, 0xA4}};
    bis_key_source_02 = {"bis_key_source_02", 0x20, {
        0x52, 0xC2, 0xE9, 0xEB, 0x09, 0xE3, 0xEE, 0x29, 0x32, 0xA1, 0x0C, 0x1F, 0xB6, 0xA0, 0x92, 0x6C,
        0x4D, 0x12, 0xE1, 0x4B, 0x2A, 0x47, 0x4C, 0x1C, 0x09, 0xCB, 0x03, 0x59, 0xF0, 0x15, 0xF4, 0xE4}};

    //=====================================Hashes=====================================//
    // from FS
    header_kek_source = {"header_kek_source", 0x9fd1b07be05b8f4d, {
        0x18, 0x88, 0xca, 0xed, 0x55, 0x51, 0xb3, 0xed, 0xe0, 0x14, 0x99, 0xe8, 0x7c, 0xe0, 0xd8, 0x68,
        0x27, 0xf8, 0x08, 0x20, 0xef, 0xb2, 0x75, 0x92, 0x10, 0x55, 0xaa, 0x4e, 0x2a, 0xbd, 0xff, 0xc2}, 0x10};
    header_key_source = {"header_key_source", 0x3e7228ec5873427b, {
        0x8f, 0x78, 0x3e, 0x46, 0x85, 0x2d, 0xf6, 0xbe, 0x0b, 0xa4, 0xe1, 0x92, 0x73, 0xc4, 0xad, 0xba,
        0xee, 0x16, 0x38, 0x00, 0x43, 0xe1, 0xb8, 0xc4, 0x18, 0xc4, 0x08, 0x9a, 0x8b, 0xd6, 0x4a, 0xa6}, 0x20};
    key_area_key_application_source = {"key_area_key_application_source", 0x0b14ccce20dbb59b, {
        0x04, 0xad, 0x66, 0x14, 0x3c, 0x72, 0x6b, 0x2a, 0x13, 0x9f, 0xb6, 0xb2, 0x11, 0x28, 0xb4, 0x6f,
        0x56, 0xc5, 0x53, 0xb2, 0xb3, 0x88, 0x71, 0x10, 0x30, 0x42, 0x98, 0xd8, 0xd0, 0x09, 0x2d, 0x9e}, 0x10};
    key_area_key_ocean_source = {"key_area_key_ocean_source", 0x055b26945075ff88, {
        0xfd, 0x43, 0x40, 0x00, 0xc8, 0xff, 0x2b, 0x26, 0xf8, 0xe9, 0xa9, 0xd2, 0xd2, 0xc1, 0x2f, 0x6b,
        0xe5, 0x77, 0x3c, 0xbb, 0x9d, 0xc8, 0x63, 0x00, 0xe1, 0xbd, 0x99, 0xf8, 0xea, 0x33, 0xa4, 0x17}, 0x10};
    key_area_key_system_source = {"key_area_key_system_source", 0xb2c28e84e1796251, {
        0x1f, 0x17, 0xb1, 0xfd, 0x51, 0xad, 0x1c, 0x23, 0x79, 0xb5, 0x8f, 0x15, 0x2c, 0xa4, 0x91, 0x2e,
        0xc2, 0x10, 0x64, 0x41, 0xe5, 0x17, 0x22, 0xf3, 0x87, 0x00, 0xd5, 0x93, 0x7a, 0x11, 0x62, 0xf7}, 0x10};
    save_mac_kek_source = {"save_mac_kek_source", 0x1e15ac1f6f21a26a, {
        0x3D, 0xCB, 0xA1, 0x00, 0xAD, 0x4D, 0xF1, 0x54, 0x7F, 0xE3, 0xC4, 0x79, 0x5C, 0x4B, 0x22, 0x8A,
        0xA9, 0x80, 0x38, 0xF0, 0x7A, 0x36, 0xF1, 0xBC, 0x14, 0x8E, 0xEA, 0xF3, 0xDC, 0xD7, 0x50, 0xF4}, 0x10};
    save_mac_key_source = {"save_mac_key_source", 0x68b9ed0d367e6dc4, {
        0xB4, 0x7B, 0x60, 0x0B, 0x1A, 0xD3, 0x14, 0xF9, 0x41, 0x14, 0x7D, 0x8B, 0x39, 0x1D, 0x4B, 0x19,
        0x87, 0xCC, 0x8C, 0x88, 0x4A, 0xC8, 0x9F, 0xFC, 0x91, 0xCA, 0xE2, 0x21, 0xC5, 0x24, 0x51, 0xF7}, 0x10};
    sd_card_kek_source = {"sd_card_kek_source", 0xc408d710a3b821eb, {
        0x6B, 0x2E, 0xD8, 0x77, 0xC2, 0xC5, 0x23, 0x34, 0xAC, 0x51, 0xE5, 0x9A, 0xBF, 0xA7, 0xEC, 0x45,
        0x7F, 0x4A, 0x7D, 0x01, 0xE4, 0x62, 0x91, 0xE9, 0xF2, 0xEA, 0xA4, 0x5F, 0x01, 0x1D, 0x24, 0xB7}, 0x10};
    sd_card_nca_key_source = {"sd_card_nca_key_source", 0xb026106d9699fec0, { // xxhash of first 0x10 bytes
        0x2E, 0x75, 0x1C, 0xEC, 0xF7, 0xD9, 0x3A, 0x2B, 0x95, 0x7B, 0xD5, 0xFF, 0xCB, 0x08, 0x2F, 0xD0,
        0x38, 0xCC, 0x28, 0x53, 0x21, 0x9D, 0xD3, 0x09, 0x2C, 0x6D, 0xAB, 0x98, 0x38, 0xF5, 0xA7, 0xCC}, 0x20};
    sd_card_save_key_source = {"sd_card_save_key_source", 0x9697ba2fec3d3ed1, { // xxhash of first 0x10 bytes
        0xD4, 0x82, 0x74, 0x35, 0x63, 0xD3, 0xEA, 0x5D, 0xCD, 0xC3, 0xB7, 0x4E, 0x97, 0xC9, 0xAC, 0x8A,
        0x34, 0x21, 0x64, 0xFA, 0x04, 0x1A, 0x1D, 0xC8, 0x0F, 0x17, 0xF6, 0xD3, 0x1E, 0x4B, 0xC0, 0x1C}, 0x20};

    // from ES
    eticket_rsa_kek_source = {"eticket_rsa_kek_source", 0x76d15de09d439bdc, {
        0xB7, 0x1D, 0xB2, 0x71, 0xDC, 0x33, 0x8D, 0xF3, 0x80, 0xAA, 0x2C, 0x43, 0x35, 0xEF, 0x88, 0x73,
        0xB1, 0xAF, 0xD4, 0x08, 0xE8, 0x0B, 0x35, 0x82, 0xD8, 0x71, 0x9F, 0xC8, 0x1C, 0x5E, 0x51, 0x1C}, 0x10};
    eticket_rsa_kekek_source = {"eticket_rsa_kekek_source", 0x97436d4ff39703da, {
        0xE8, 0x96, 0x5A, 0x18, 0x7D, 0x30, 0xE5, 0x78, 0x69, 0xF5, 0x62, 0xD0, 0x43, 0x83, 0xC9, 0x96,
        0xDE, 0x48, 0x7B, 0xBA, 0x57, 0x61, 0x36, 0x3D, 0x2D, 0x4D, 0x32, 0x39, 0x18, 0x66, 0xA8, 0x5C}, 0x10};

    // from SSL
    ssl_rsa_kek_source_x = {"ssl_rsa_kek_source_x", 0xa7084dadd5d9da93, {
        0x69, 0xA0, 0x8E, 0x62, 0xE0, 0xAE, 0x50, 0x7B, 0xB5, 0xDA, 0x0E, 0x65, 0x17, 0x9A, 0xE3, 0xBE,
        0x05, 0x1F, 0xED, 0x3C, 0x49, 0x94, 0x1D, 0xF4, 0xEF, 0x29, 0x56, 0xD3, 0x6D, 0x30, 0x11, 0x0C}, 0x10};
    ssl_rsa_kek_source_y = {"ssl_rsa_kek_source_y", 0xbafd95c9f258dc4a, {
        0x1C, 0x86, 0xF3, 0x63, 0x26, 0x54, 0x17, 0xD4, 0x99, 0x22, 0x9E, 0xB1, 0xC4, 0xAD, 0xC7, 0x47,
        0x9B, 0x2A, 0x15, 0xF9, 0x31, 0x26, 0x1F, 0x31, 0xEE, 0x67, 0x76, 0xAE, 0xB4, 0xC7, 0x65, 0x42}, 0x10};

    // from TSEC
    tsec_root_key = {"tsec_root_key", 0x57b73665b0bbd424, {
        0x03, 0x2a, 0xdf, 0x0a, 0x6b, 0xe7, 0xdd, 0x7c, 0x11, 0xa4, 0xfa, 0x5c, 0xd6, 0x4a, 0x15, 0x75,
        0xe4, 0x69, 0xb9, 0xda, 0x5d, 0x8b, 0xd5, 0x6a, 0x12, 0xd0, 0xfb, 0xc0, 0xeb, 0x84, 0xe8, 0xe7}, 0x10};

    rsa_oaep_kek_generation_source = {"rsa_oaep_kek_generation_source", 0x10};
    rsa_private_kek_generation_source = {"rsa_private_kek_generation_source", 0x10};

    es_keys = {
        &eticket_rsa_kek_source,
        &eticket_rsa_kekek_source
    };

    fs_rodata_keys = {
        &header_kek_source,
        &key_area_key_application_source,
        &key_area_key_ocean_source,
        &key_area_key_system_source,
        &save_mac_kek_source,
        &save_mac_key_source
    };

    // only look for sd keys if at least firm 2.0.0
    if (kernelAbove200()) {
        fs_rodata_keys.insert(fs_rodata_keys.end(), {
            &sd_card_kek_source,
            &sd_card_nca_key_source,
            &sd_card_save_key_source
        });
    }

    ssl_keys = {
        &ssl_rsa_kek_source_x,
        &ssl_rsa_kek_source_y
    };
};

void KeyCollection::get_keys() {
    Stopwatch total_time;
    total_time.start();

    int64_t profiler_time = profile(Common::get_tegra_keys, sbk, tsec, tsec_root_key);
    if ((sbk.found() && tsec.found()) || tsec_root_key.found()) {
        Common::draw_text_with_time(0x10, 0x60, GREEN, "Get Tegra keys...", profiler_time);
    } else {
        Common::draw_text(0x010, 0x60, RED, "Get Tegra keys...");
        Common::draw_text(0x190, 0x60, RED, "Failed");
        Common::draw_text(0x2a0, 0x60, RED, "Warning: Saving limited keyset.");
        Common::draw_text(0x2a0, 0x80, RED, "Dump TSEC and Fuses with Hekate.");
    }

    profiler_time = profile(&KeyCollection::get_memory_keys, *this);
    Common::draw_text_with_time(0x10, 0x080, GREEN, "Get keys from memory...", profiler_time);

    profiler_time = profile(&KeyCollection::get_master_keys, *this);
    Common::draw_text_with_time(0x10, 0x0a0, GREEN, "Get master keys...", profiler_time);

    profiler_time = profile(&KeyCollection::derive_keys, *this);
    Common::draw_text_with_time(0x10, 0x0c0, GREEN, "Derive remaining keys...", profiler_time);

    // avoid crash on CFWs that don't use /switch folder
    if (!std::filesystem::exists("/switch"))
        std::filesystem::create_directory("/switch");
    if (!std::filesystem::exists("/switch/Lockpick"))
        std::filesystem::create_directory("/switch/Lockpick");
    // since Lockpick_RCM can dump newer keys, check for existing keyfile
    bool Lockpick_RCM_file_found = false;
    FILE *key_file = fopen("/switch/Lockpick/prod.keys", "r");
    if (key_file) {
        char line[0x200];
        while (fgets(line, sizeof(line), key_file)) {
            if (strncmp("master_key_07", line, 13) == 0) {
                Lockpick_RCM_file_found = true;
            } else if (!eticket_rsa_kek.found() && (strncmp("eticket_rsa_kek", line, 15)) == 0) {
                // grab eticket_rsa_kek from existing file to make sure we can dump titlekeys
                eticket_rsa_kek = Key("eticket_rsa_kek", 0x10, Common::key_string_to_byte_vector(line));
            }
        }
        fclose(key_file);
    }
    if (!Lockpick_RCM_file_found) {
        profiler_time = profile(&KeyCollection::save_keys, *this);
        Common::draw_text_with_time(0x10, 0x0e0, GREEN, "Saving keys to keyfile...", profiler_time);
    } else {
        Common::draw_text(0x10, 0x0e0, YELLOW, "Saving keys to keyfile...");
        Common::draw_text(0x190, 0x0e0, YELLOW, "Newer keyfile found. Skipped overwriting keys");
    }

    total_time.stop();
    Common::draw_line(0x8, 0xf0, 0x280, GREEN);
    Common::draw_text_with_time(0x10, 0x110, GREEN, "Total time elapsed:", total_time.get_elapsed());

    char keys_str[32];
    if (!Lockpick_RCM_file_found) {
        sprintf(keys_str, "Total keys found: %lu", Key::get_saved_key_count());
        Common::draw_text(0x2a0, 0x110, CYAN, keys_str);
        Common::draw_text(0x80, 0x140, YELLOW, "Keys saved to \"/switch/prod.keys\"!");
    }

    Common::draw_text(0x10, 0x170, CYAN, "Dumping titlekeys...");
    Common::update_display();
    profiler_time = profile(&KeyCollection::get_titlekeys, *this);
    Common::draw_text_with_time(0x10, 0x170, GREEN, "Dumping titlekeys...", profiler_time);
    sprintf(keys_str, "Titlekeys found: %lu", titlekeys_dumped);
    Common::draw_text(0x2a0, 0x170, CYAN, keys_str);
    if (titlekeys_dumped > 0)
        Common::draw_text(0x80, 0x1a0, YELLOW, "Titlekeys saved to \"/switch/title.keys\"!");
    else
        Common::draw_text(0x80, 0x1a0, GREEN, "No titlekeys found. Either you've never played or installed a game or dump failed.");
}

void KeyCollection::get_master_keys() {
    char keynum[] = "00";
    if (sbk.found() && tsec.found()) {
        for (u8 i = 0; i < keyblob_key_source.size(); i++) {
            sprintf(keynum, "%02x", i);
            keyblob_key.push_back(Key {"keyblob_key_" + std::string(keynum), 0x10,
                sbk.aes_decrypt_ecb(tsec.aes_decrypt_ecb(keyblob_key_source[i].key))});
            keyblob_mac_key.push_back(Key {"keyblob_mac_key_" + std::string(keynum), 0x10,
                keyblob_key.back().aes_decrypt_ecb(keyblob_mac_key_source.key)});
        }
    }

    if (!keyblob_mac_key.empty()) {
        KeyLocation Keyblobs;
        Keyblobs.get_keyblobs();
        u8 index = 0;
        for (byte_vector::const_iterator It = Keyblobs.data.begin(); It != Keyblobs.data.end(); It += 0x200) {
            sprintf(keynum, "%02x", index);
            encrypted_keyblob.push_back(Key {"encrypted_keyblob_" + std::string(keynum), 0xb0, byte_vector(It, It + 0xb0)});
            byte_vector keyblob_mac(keyblob_mac_key[index].cmac(byte_vector(encrypted_keyblob.back().key.begin() + 0x10, encrypted_keyblob.back().key.end())));
            if (!std::equal(encrypted_keyblob.back().key.begin(), encrypted_keyblob.back().key.begin() + 0x10, keyblob_mac.begin())) {
                // if keyblob cmac fails, invalidate all console-unique keys to prevent faulty derivation or saving bad values
                sbk = Key();
                tsec = Key();
                keyblob_key.clear();
                keyblob_mac_key.clear();
                break;
            }
            index++;
        }
    }

    for (u8 i = 0; i < keyblob_key.size(); i++) {
        sprintf(keynum, "%02x", i);
        keyblob.push_back(Key {"keyblob_" + std::string(keynum), 0x90,
                keyblob_key[i].aes_decrypt_ctr(
                    byte_vector(encrypted_keyblob[i].key.begin() + 0x20, encrypted_keyblob[i].key.end()),
                    byte_vector(encrypted_keyblob[i].key.begin() + 0x10, encrypted_keyblob[i].key.begin() + 0x20))});
        package1_key.push_back(Key {"package1_key_" + std::string(keynum), 0x10,
                byte_vector(keyblob.back().key.begin() + 0x80, keyblob.back().key.end())});
        master_kek.push_back(Key {"master_kek_" + std::string(keynum), 0x10,
                byte_vector(keyblob.back().key.begin(), keyblob.back().key.begin() + 0x10)});
        master_key.push_back(Key {"master_key_" + std::string(keynum), 0x10, master_kek.back().aes_decrypt_ecb(master_key_source.key)});
    }

    if (tsec_root_key.found()) {
        if (master_kek.empty()) {
            master_kek.resize(KNOWN_KEYBLOBS);
            master_key.resize(KNOWN_KEYBLOBS);
        }
        master_kek.push_back(Key {"master_kek_06", 0x10, tsec_root_key.aes_decrypt_ecb(master_kek_source[KNOWN_KEYBLOBS].key)});
        master_key.push_back(Key {"master_key_06", 0x10, master_kek[KNOWN_KEYBLOBS].aes_decrypt_ecb(master_key_source.key)});
        if (!master_key[KNOWN_KEYBLOBS - 1].found()) {
            for (int i = KNOWN_KEYBLOBS - 1; i >= 0; i--) {
                sprintf(keynum, "%02x", i);
                master_key[i] = Key {"master_key_" + std::string(keynum), 0x10, master_key[i+1].aes_decrypt_ecb(mkey_vector[i+1].key)};
            }
            byte_vector zeroes(0x10, 0);
            if (!std::equal(zeroes.begin(), zeroes.end(), master_key[0].aes_decrypt_ecb(mkey_vector[0].key).begin())) {
                // if last mkey doesn't decrypt vector to zeroes, invalidate all master_keys and keks
                master_kek.clear();
                master_key.clear();
            }
        }
    }
}

void KeyCollection::get_memory_keys() {
    KeyLocation
        ESRodata,
        FSRodata,
        FSData,
        SSLRodata;

    FSRodata.get_from_memory(FS_TID, SEG_RODATA);
    FSData.get_from_memory(FS_TID, SEG_DATA);

    FSRodata.find_keys(fs_rodata_keys);

    size_t i = 0;
    /*for ( ; i < FSData.data.size(); i++) {
        // speeds things up but i'm not 100% sure this is always here
        if (*reinterpret_cast<u128 *>(FSData.data.data() + i) == 0x10001)
            break;
    }*/
    header_key_source.find_key(FSData.data, i);

    SSLRodata.get_from_memory(SSL_TID, SEG_RODATA);
    // using find_keys on these is actually slower
    for (auto k : ssl_keys)
        k->find_key(SSLRodata.data);

    // firmware 1.0.0 doesn't have the ES keys
    if (!kernelAbove200())
        return;
    ESRodata.get_from_memory(ES_TID, SEG_RODATA);
    for (auto k : es_keys)
        k->find_key(ESRodata.data);
}

void KeyCollection::derive_keys() {
    if (header_kek_source.found() && header_key_source.found()) {
        u8 tempheaderkek[0x10], tempheaderkey[0x20];
        splCryptoInitialize();
        splCryptoGenerateAesKek(header_kek_source.key.data(), 0, 0, tempheaderkek);
        splCryptoGenerateAesKey(tempheaderkek, header_key_source.key.data() + 0x00, tempheaderkey + 0x00);
        splCryptoGenerateAesKey(tempheaderkek, header_key_source.key.data() + 0x10, tempheaderkey + 0x10);
        header_key = {"header_key", 0x20, byte_vector(tempheaderkey, tempheaderkey + 0x20)};
        splCryptoExit();
    }

    u64 key_generation = 0;
    SetSysFirmwareVersion ver;

    setsysInitialize();
    setsysGetFirmwareVersion(&ver);
    setsysExit();

    Result rc = 0;
    if (ver.major >= 5) {
        rc = splGetConfig(SplConfigItem_NewKeyGeneration, &key_generation);
    }

    if (R_SUCCEEDED(rc) && bis_key_source_00.found() && bis_key_source_01.found() && bis_key_source_02.found()) {
        u8 tempbiskek[0x10], tempbiskey[0x20];
        splFsInitialize();
        splFsGenerateSpecificAesKey(bis_key_source_00.key.data() + 0x00, key_generation, 0, tempbiskey + 0x00);
        splFsGenerateSpecificAesKey(bis_key_source_00.key.data() + 0x10, key_generation, 0, tempbiskey + 0x10);
        bis_key.push_back(Key {"bis_key_00", 0x20, byte_vector(tempbiskey, tempbiskey + 0x20)});
        splFsExit();

        splCryptoInitialize();
        splCryptoGenerateAesKek(bis_kek_source.key.data(), key_generation, 1, tempbiskek);
        splCryptoGenerateAesKey(tempbiskek, bis_key_source_01.key.data() + 0x00, tempbiskey + 0x00);
        splCryptoGenerateAesKey(tempbiskek, bis_key_source_01.key.data() + 0x10, tempbiskey + 0x10);
        bis_key.push_back(Key {"bis_key_01", 0x20, byte_vector(tempbiskey, tempbiskey + 0x20)});
        splCryptoGenerateAesKey(tempbiskek, bis_key_source_02.key.data() + 0x00, tempbiskey + 0x00);
        splCryptoGenerateAesKey(tempbiskek, bis_key_source_02.key.data() + 0x10, tempbiskey + 0x10);
        bis_key.push_back(Key {"bis_key_02", 0x20, byte_vector(tempbiskey, tempbiskey + 0x20)});
        bis_key.push_back(Key {"bis_key_03", 0x20, bis_key[2].key});
        splCryptoExit();
    }

    for (u8 i = 0; i < aes_kek_generation_source.key.size(); i++) {
        rsa_oaep_kek_generation_source.key.push_back(aes_kek_generation_source.key[i] ^ aes_kek_seed_03.key[i]);
        rsa_private_kek_generation_source.key.push_back(aes_kek_generation_source.key[i] ^ aes_kek_seed_01.key[i]);
    }
    rsa_oaep_kek_generation_source.set_found();
    rsa_private_kek_generation_source.set_found();

    if (!keyblob_key.empty())
        device_key = Key {"device_key", 0x10, keyblob_key[0].aes_decrypt_ecb(per_console_key_source.key)};

    if (device_key.found() && save_mac_kek_source.found() && save_mac_key_source.found()) {
        Key kek = {save_mac_kek_source.generate_kek(device_key, aes_kek_generation_source, Key {}), 0x10};
        save_mac_key = Key {"save_mac_key", 0x10, kek.aes_decrypt_ecb(save_mac_key_source.key)};
    }

    char keynum[] = "00";
    for (u8 i = 0; i < master_key.size(); i++) {
        if (!master_key[i].found())
            continue;
        sprintf(keynum, "%02x", i);
        key_area_key_application.push_back(Key {"key_area_key_application_" + std::string(keynum), 0x10,
                key_area_key_application_source.generate_kek(master_key[i], aes_kek_generation_source, aes_key_generation_source)});
        key_area_key_ocean.push_back(Key {"key_area_key_ocean_" + std::string(keynum), 0x10,
                key_area_key_ocean_source.generate_kek(master_key[i], aes_kek_generation_source, aes_key_generation_source)});
        key_area_key_system.push_back(Key {"key_area_key_system_" + std::string(keynum), 0x10,
                key_area_key_system_source.generate_kek(master_key[i], aes_kek_generation_source, aes_key_generation_source)});
        package2_key.push_back(Key {"package2_key_" + std::string(keynum), 0x10, master_key[i].aes_decrypt_ecb(package2_key_source.key)});
        titlekek.push_back(Key {"titlekek_" + std::string(keynum), 0x10, master_key[i].aes_decrypt_ecb(titlekek_source.key)});
    }

    if (eticket_rsa_kek_source.found() && eticket_rsa_kekek_source.found() && !master_key.empty())
        eticket_rsa_kek = Key {"eticket_rsa_kek", 0x10,
            eticket_rsa_kekek_source.generate_kek(master_key[0], rsa_oaep_kek_generation_source, eticket_rsa_kek_source)};
    if (ssl_rsa_kek_source_x.found() && ssl_rsa_kek_source_y.found() && !master_key.empty())
        ssl_rsa_kek = Key {"ssl_rsa_kek", 0x10,
            ssl_rsa_kek_source_x.generate_kek(master_key[0], rsa_private_kek_generation_source, ssl_rsa_kek_source_y)};

    char seed_vector[0x10], seed[0x10], buffer[0x10];
    u32 bytes_read, file_pos = 0;

    // dump sd seed
    if (!kernelAbove200())
        return;
    FILE *sd_private = fopen("/Nintendo/Contents/private", "rb");
    if (!sd_private) return;
    fread(seed_vector, 0x10, 1, sd_private);
    fclose(sd_private);

    FATFS fs;
    FRESULT fr;
    FIL save_file;

    fsOpenBisStorage(&storage, FsBisStorageId_System);
    if (f_mount(&fs, "", 1) ||
        f_chdir("/save") ||
        f_open(&save_file, "8000000000000043", FA_READ | FA_OPEN_EXISTING))
    {
        fsStorageClose(&storage);
        return;
    }

    for (;;) {
        fr = f_read(&save_file, buffer, 0x10, &bytes_read);
        if (fr || (bytes_read == 0)) break;
        if (std::equal(seed_vector, seed_vector + 0x10, buffer)) {
            f_read(&save_file, seed, 0x10, &bytes_read);
            sd_seed = Key {"sd_seed", 0x10, byte_vector(seed, seed + 0x10)};
            break;
        }
        file_pos += 0x4000;
        if (f_lseek(&save_file, file_pos)) break;
    }
    f_close(&save_file);
    fsStorageClose(&storage);
}

void KeyCollection::save_keys() {
    FILE *key_file = fopen("/switch/prod.keys", "w");
    if (!key_file) return;

    aes_kek_generation_source.save_key(key_file);
    aes_key_generation_source.save_key(key_file);
    bis_kek_source.save_key(key_file);
    for (auto k : bis_key)
        k.save_key(key_file);
    bis_key_source_00.save_key(key_file);
    bis_key_source_01.save_key(key_file);
    bis_key_source_02.save_key(key_file);
    device_key.save_key(key_file);
    eticket_rsa_kek.save_key(key_file);
    for (auto k : es_keys)
        k->save_key(key_file);
    header_kek_source.save_key(key_file);
    header_key.save_key(key_file);
    header_key_source.save_key(key_file);
    for (auto k : key_area_key_application)
        k.save_key(key_file);
    key_area_key_application_source.save_key(key_file);
    for (auto k : key_area_key_ocean)
        k.save_key(key_file);
    key_area_key_ocean_source.save_key(key_file);
    for (auto k : key_area_key_system)
        k.save_key(key_file);
    key_area_key_system_source.save_key(key_file);
    for (auto k : keyblob)
        k.save_key(key_file);
    for (auto k : keyblob_key)
        k.save_key(key_file);
    for (auto k : keyblob_key_source)
        k.save_key(key_file);
    for (auto k : keyblob_mac_key)
        k.save_key(key_file);
    keyblob_mac_key_source.save_key(key_file);
    for (auto k : master_kek)
        k.save_key(key_file);
    for (auto k : master_kek_source)
        k.save_key(key_file);
    for (auto k : master_key)
        k.save_key(key_file);
    master_key_source.save_key(key_file);
    for (auto k : package1_key)
        k.save_key(key_file);
    for (auto k : package2_key)
        k.save_key(key_file);
    package2_key_source.save_key(key_file);
    per_console_key_source.save_key(key_file);
    retail_specific_aes_key_source.save_key(key_file);
    rsa_oaep_kek_generation_source.save_key(key_file);
    rsa_private_kek_generation_source.save_key(key_file);
    save_mac_kek_source.save_key(key_file);
    save_mac_key.save_key(key_file);
    save_mac_key_source.save_key(key_file);
    sd_card_kek_source.save_key(key_file);
    sd_card_nca_key_source.save_key(key_file);
    sd_card_save_key_source.save_key(key_file);
    sd_seed.save_key(key_file);
    sbk.save_key(key_file);
    ssl_rsa_kek.save_key(key_file);
    for (auto k : ssl_keys)
        k->save_key(key_file);
    for (auto k : titlekek)
        k.save_key(key_file);
    titlekek_source.save_key(key_file);
    tsec.save_key(key_file);
    tsec_root_key.save_key(key_file);

    fclose(key_file);
}

void KeyCollection::get_titlekeys() {
    if (!kernelAbove200() || !eticket_rsa_kek.found())
        return;

    u32 common_count, personalized_count, bytes_read, ids_written;

    esInitialize();
    esCountCommonTicket(&common_count);
    esCountPersonalizedTicket(&personalized_count);
    NcmNcaId common_rights_ids[common_count], personalized_rights_ids[personalized_count];
    esListCommonTicket(&ids_written, common_rights_ids, sizeof(common_rights_ids));
    esListPersonalizedTicket(&ids_written, personalized_rights_ids, sizeof(personalized_rights_ids));
    esExit();
    if (common_count + personalized_count == 0)
        return;

    /*
        catalog all currently installed rights ids
        since we are crawling the whole save file, we might accidentally find previously deleted tickets
        this would be fine, except we have to match the exact list so we don't stop too early
    */
    char titlekey_block[0x100], buffer[TITLEKEY_BUFFER_SIZE], rights_id_string[0x21], titlekey_string[0x21];
    std::unordered_set<std::string> rights_ids;
    for (size_t i = 0; i < common_count; i++) {
        for (size_t j = 0; j < 0x10; j++) {
            sprintf(&rights_id_string[j*2], "%02x", common_rights_ids[i].c[j]);
        }
        rights_ids.insert(rights_id_string);
    }
    for (size_t i = 0; i < personalized_count; i++) {
        for (size_t j = 0; j < 0x10; j++) {
            sprintf(&rights_id_string[j*2], "%02x", personalized_rights_ids[i].c[j]);
        }
        rights_ids.insert(rights_id_string);
    }

    // get extended eticket RSA key from PRODINFO
    u8 eticket_data[0x244] = {};

    setcalInitialize();
    setcalGetEticketDeviceKey(eticket_data);
    setcalExit();

    byte_vector dec_keypair = eticket_rsa_kek.aes_decrypt_ctr(
        byte_vector(eticket_data + 0x14, eticket_data + 0x244),
        byte_vector(eticket_data + 4, eticket_data + 0x14)
    );

    // public exponent must be 65537 == 0x10001 (big endian)
    if (!(dec_keypair[0x200] == 0) || !(dec_keypair[0x201] == 1) || !(dec_keypair[0x202] == 0) || !(dec_keypair[0x203] == 1))
        return;

    u8 *D = &dec_keypair[0], *N = &dec_keypair[0x100], *E = &dec_keypair[0x200];

    if (!test_key_pair(E, D, N))
        return;

    FATFS fs;
    FRESULT fr;
    FIL save_file;
    // map of all found rights ids and corresponding titlekeys
    std::unordered_map<std::string, std::string> titlekeys;

    fsOpenBisStorage(&storage, FsBisStorageId_System);
    if (f_mount(&fs, "", 1) || f_chdir("/save")) return;
    if (f_open(&save_file, "80000000000000e1", FA_READ | FA_OPEN_EXISTING)) return;
    while ((common_count != 0) && (titlekeys_dumped < common_count)) {
        fr = f_read(&save_file, buffer, TITLEKEY_BUFFER_SIZE, &bytes_read);
        if (fr || (bytes_read == 0)) break;
        for (size_t i = 0; i < bytes_read; i += 0x4000) {
            for (size_t j = i; j < i + 0x4000; j += 0x400) {
                if (*reinterpret_cast<u32 *>(&buffer[j]) == 0x10004) {
                    for (size_t k = 0; k < 0x10; k++)
                        sprintf(&rights_id_string[k*2], "%02x", buffer[j + 0x2a0 + k]);

                    // skip if rights id not reported by es
                    if (rights_ids.find(rights_id_string) == rights_ids.end())
                        continue;
                    // skip if rights id already in map
                    if (titlekeys.find(rights_id_string) != titlekeys.end())
                        continue;

                    for (size_t k = 0; k < 0x10; k++)
                        sprintf(&titlekey_string[k*2], "%02x", buffer[j + 0x180 + k]);
                    titlekeys[rights_id_string] = titlekey_string;
                    titlekeys_dumped++;
                } else {
                    break;
                }
            }
        }
    }
    f_close(&save_file);

    u8 M[0x100];

    if (f_open(&save_file, "80000000000000e2", FA_READ | FA_OPEN_EXISTING)) return;
    while ((personalized_count != 0) && (titlekeys_dumped < common_count + personalized_count)) {
        fr = f_read(&save_file, buffer, TITLEKEY_BUFFER_SIZE, &bytes_read);
        if (fr || (bytes_read == 0)) break;
        for (size_t i = 0; i < bytes_read; i += 0x4000) {
            for (size_t j = i; j < i + 0x4000; j += 0x400) {
                if (*reinterpret_cast<u32 *>(&buffer[j]) == 0x10004) {
                    for (size_t k = 0; k < 0x10; k++)
                        sprintf(&rights_id_string[k*2], "%02x", buffer[j + 0x2a0 + k]);

                    // skip if rights id not reported by es
                    if (rights_ids.find(rights_id_string) == rights_ids.end())
                        continue;
                    // skip if rights id already in map
                    if (titlekeys.find(rights_id_string) != titlekeys.end())
                        continue;

                    std::copy(buffer + j + 0x180, buffer + j + 0x280, titlekey_block);

                    splUserExpMod(titlekey_block, N, D, 0x100, M);

                    // decrypts the titlekey from personalized ticket
                    u8 salt[0x20], db[0xdf];
                    mgf1(M + 0x21, 0xdf, salt, 0x20);
                    for (size_t k = 0; k < 0x20; k++)
                        salt[k] ^= M[k + 1];

                    mgf1(salt, 0x20, db, 0xdf);
                    for (size_t k = 0; k < 0xdf; k++)
                        db[k] ^= M[k + 0x21];

                    // verify it starts with hash of null string
                    if (!std::equal(db, db + 0x20, null_hash))
                        continue;

                    for (size_t k = 0; k < 0x10; k++)
                        sprintf(&titlekey_string[k*2], "%02x", db[k + 0xcf]);
                    titlekeys[rights_id_string] = titlekey_string;
                    titlekeys_dumped++;
                } else {
                    break;
                }
            }
        }
    }
    f_close(&save_file);
    fsStorageClose(&storage);

    if (titlekeys.empty())
        return;

    FILE *titlekey_file = fopen("/switch/title.keys", "wb");
    if (!titlekey_file) return;
    for (auto k : titlekeys)
        fprintf(titlekey_file, "%s = %s\n", k.first.c_str(), k.second.c_str());
    fclose(titlekey_file);
}

void KeyCollection::mgf1(const u8 *data, size_t data_length, u8 *mask, size_t mask_length) {
    u8 data_counter[data_length + 4] = {};
    std::copy(data, data + data_length, data_counter);
    sha256CalculateHash(mask, data_counter, data_length + 4);
    for (u32 i = 1; i < (mask_length / 0x20) + 1; i++) {
        for (size_t j = 0; j < 4; j++)
            data_counter[data_length + 3 - j] = (i >> (8 * j)) & 0xff;
        if (i * 0x20 <= mask_length)
            sha256CalculateHash(mask + (i * 0x20), data_counter, data_length + 4);
            else {
            u8 temp_mask[0x20];
            sha256CalculateHash(temp_mask, data_counter, data_length + 4);
            std::copy(temp_mask, temp_mask + mask_length - (i * 0x20), mask + (i * 0x20));
        }
    }
}

bool KeyCollection::test_key_pair(const void *E, const void *D, const void *N) {
    u8 X[0x100] = {0}, Y[0x100] = {0}, Z[0x100] = {0};

    // 0xCAFEBABE
    X[0xfc] = 0xca; X[0xfd] = 0xfe; X[0xfe] = 0xba; X[0xff] = 0xbe;
    splUserExpMod(X, N, D, 0x100, Y);
    splUserExpMod(Y, N, E, 4, Z);
    for (size_t i = 0; i < 0x100; i++)
        if (X[i] != Z[i])
            return false;

    return true;
}