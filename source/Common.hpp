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

#pragma once

#include "Key.hpp"

#include <ft2build.h>
#include <switch.h>
#include FT_FREETYPE_H

#define GREEN   RGBA8_MAXALPHA(0, 0xff, 0)
#define RED     RGBA8_MAXALPHA(0xff, 0, 0)
#define CYAN    RGBA8_MAXALPHA(0, 0xff, 0xff)
#define YELLOW  RGBA8_MAXALPHA(0xff, 0xff, 0)
#define WHITE   RGBA8_MAXALPHA(0xFF, 0xff, 0xFF)

enum {
    Status_fail = 0,
    Status_success_no_titlekeys,
    Status_success_titlekeys,
    Status_success_titlekeys_failed
};

class Key;

namespace Common {
    // draw letter, called by draw_text
    void draw_glyph(FT_Bitmap *bitmap, u32 x, u32 y, u32 color);
    // draw horizontal line
    void draw_line(u32 x, u32 y, u32 length, u32 color);
    // draw filled rectangle
    void draw_set_rect(u32 x, u32 y, u32 width, u32 height, u32 color);
    // draw string
    void draw_text(u32 x, u32 y, u32 color, const char *str);
    // draw string and time elapsed
    void draw_text_with_time(u32 x, u32 y, u32 color, const char *str, const float time);
    // overload for microseconds
    void draw_text_with_time(u32 x, u32 y, u32 color, const char *str, const int64_t time);

    // init font and draw interface
    void intro();
    // get tegra keys from payload dump
    void get_tegra_keys(Key &sbk, Key &tsec, Key &tsec_root);
    // print exit in color green or red (fail==true)
    void wait_to_exit(int status);

    void sha256(const u8 *data, u8 *hash, size_t length);
    // reads "<keyname> = <hexkey>" and returns byte vector
    std::vector<u8> key_string_to_byte_vector(std::string key_string);
}