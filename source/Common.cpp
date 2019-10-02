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

/*
    Shared font code adapted from
    https://github.com/switchbrew/switch-examples/tree/master/graphics/shared_font
*/

#include "Common.hpp"
#include "Key.hpp"

#include <machine/endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <filesystem>
#include <string>

#include <switch.h>

namespace Common {
    static u32 framebuf_width = 0;
    static Framebuffer fb;
    static u32 stride;
    static u32 *framebuf;
    // FreeType vars
    static FT_Library library;
    static FT_Face face;

    void draw_glyph(FT_Bitmap *bitmap, u32 x, u32 y, u32 color) {
        u32 framex, framey;
        u8* imageptr = bitmap->buffer;

        for (u32 tmpy = 0; tmpy < bitmap->rows; tmpy++) {
            for (u32 tmpx = 0; tmpx < bitmap->width; tmpx++) {
                framex = x + tmpx;
                framey = y + tmpy;

                // color calculation is extremely simplistic and only supports 0 or 0xff in each element for proper antialiasing
                framebuf[framey * framebuf_width + framex] = RGBA8_MAXALPHA(imageptr[tmpx], imageptr[tmpx], imageptr[tmpx]) & color;
            }

            imageptr += bitmap->pitch;
        }
    }

    void draw_line(u32 x, u32 y, u32 length, u32 color) {
        for (u32 tmpx = x; tmpx < x + length; tmpx++)
            framebuf[y * framebuf_width + tmpx] = color;
    }

    void draw_set_rect(u32 x, u32 y, u32 width, u32 height, u32 color) {
        for (u32 tmpy = y; tmpy < y + height; tmpy++)
            draw_line(x, tmpy, width, color);
    }

    void draw_text(u32 x, u32 y, u32 color, const char *str) {
        u32 tmpx = x;
        FT_UInt glyph_index;
        FT_GlyphSlot slot = face->glyph;

        for (size_t i = 0; i < strlen(str); i++) {
            if (str[i] == '\n') {
                tmpx = x;
                y += face->size->metrics.height / 64;
                continue;
            }

            glyph_index = FT_Get_Char_Index(face, (FT_ULong)str[i]);

            if (R_FAILED(FT_Load_Glyph(face, glyph_index, FT_LOAD_COLOR) ||
                FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL) != 0))
            {
                return;
            }

            draw_glyph(&slot->bitmap, tmpx + slot->bitmap_left, y - slot->bitmap_top, color);

            tmpx += slot->advance.x >> 6;
            y += slot->advance.y >> 6;
        }
    }

    void draw_text_with_time(u32 x, u32 y, u32 color, const char *str, const float time) {
        char time_str[32];
        sprintf(time_str, "%1.6f seconds", time);
        draw_text(x, y, color, str);
        draw_text(0x190, y, color, time_str);
    }

    void draw_text_with_time(u32 x, u32 y, u32 color, const char *str, const int64_t time) {
        draw_text_with_time(x, y, color, str, time / 1000000.0f);
    }

    void intro() {
        appletLockExit();

        PlFontData font;

        plGetSharedFontByType(&font, PlSharedFontType_Standard);

        FT_Init_FreeType(&library);
        FT_New_Memory_Face(library, static_cast<FT_Byte *>(font.address), font.size, 0, &face);
        FT_Set_Char_Size(face, 0, 6*64, 300, 300);

        framebufferCreate(&fb, nwindowGetDefault(), FB_WIDTH, FB_HEIGHT, PIXEL_FORMAT_RGBA_8888, 2);
        framebufferMakeLinear(&fb);
        framebuf = (u32 *)framebufferBegin(&fb, &stride);
        framebuf_width = stride / sizeof(u32);
        memset(framebuf, 0, stride*FB_HEIGHT);
        framebufferEnd(&fb);

        draw_text(0x010, 0x020, YELLOW, "Lockpick! by shchmue");
        draw_text(0x190, 0x020, YELLOW, "Note:");
        draw_text(0x1e0, 0x020, YELLOW, "Lockpick can only dump keys 00-05 (or 00-06 on 6.2.0)");
        draw_text(0x1e0, 0x040, CYAN, "Lockpick_RCM");
        draw_text(0x2a0, 0x040, YELLOW, "can get newer keys on firmware 7.0.0+!");

        draw_set_rect(814, 452 + 42 * 0, 450, 42, FLAG_RED);
        draw_set_rect(814, 452 + 42 * 1, 450, 42, FLAG_ORANGE);
        draw_set_rect(814, 452 + 42 * 2, 450, 42, FLAG_YELLOW);
        draw_set_rect(814, 452 + 42 * 3, 450, 42, FLAG_GREEN);
        draw_set_rect(814, 452 + 42 * 4, 450, 42, FLAG_BLUE);
        draw_set_rect(814, 452 + 42 * 5, 450, 42, FLAG_VIOLET);

        if (  !(envIsSyscallHinted(0x60) &&     // svcDebugActiveProcess
                envIsSyscallHinted(0x63) &&     // svcGetDebugEvent
                envIsSyscallHinted(0x65) &&     // svcGetProcessList
                envIsSyscallHinted(0x69) &&     // svcQueryDebugProcessMemory
                envIsSyscallHinted(0x6a))) {    // svcReadDebugProcessMemory
            draw_text(0x190, 0x20, RED, "Error: Please run with debug svc permissions!");
            wait_to_exit();
        }

        draw_text(0x10, 0x060, CYAN, "Get Tegra keys...");
        draw_text(0x10, 0x080, CYAN, "Get keys from memory...");
        draw_text(0x10, 0x0a0, CYAN, "Get master keys...");
        draw_text(0x10, 0x0c0, CYAN, "Derive remaining keys...");
        draw_text(0x10, 0x0e0, CYAN, "Saving keys to keyfile...");
        draw_text(0x10, 0x110, CYAN, "Total time elapsed:");

        update_display();
    }

    void get_tegra_keys(Key &sbk, Key &tsec, Key &tsec_root) {
        // support Hekate dump
        if (std::filesystem::exists("/backup")) {
            for (auto &p : std::filesystem::recursive_directory_iterator("/backup")) {
                if (p.is_regular_file()) {
                    if (!sbk.found() && (p.file_size() == 0x2fc || p.file_size() == 0x300) &&
                        ((p.path().filename().string().substr(0, 5).compare("fuses") == 0) ||
                        (p.path().filename().string().substr(0, 11).compare("fuse_cached") == 0)))
                    {
                        FILE *fuse_file = fopen(p.path().c_str(), "rb");
                        if (!fuse_file) continue;
                        byte_vector temp_key(0x10);
                        fseek(fuse_file, 0xa4, SEEK_SET);
                        fread(temp_key.data(), 0x10, 1, fuse_file);
                        sbk = Key("secure_boot_key", 0x10, temp_key);
                        fclose(fuse_file);
                    }
                    else if (!tsec.found() && (p.file_size() == 0x20 || p.file_size() == 0x30) &&
                        (p.path().filename().string().substr(0, 4).compare("tsec") == 0))
                    {
                        FILE *tsec_file = fopen(p.path().c_str(), "rb");
                        if (!tsec_file) continue;
                        byte_vector temp_key(0x10);
                        fread(temp_key.data(), 0x10, 1, tsec_file);
                        tsec = Key("tsec_key", 0x10, temp_key);
                        fread(temp_key.data(), 0x10, 1, tsec_file);
                        tsec_root.find_key(temp_key);
                        fclose(tsec_file);
                    }
                }
                if (sbk.found() && tsec.found())
                    return;
            }
        }
        // support biskeydump v7 dump
        FILE *key_file = fopen("/device.keys", "r");
        if (key_file) {
            char line[0x100];
            while (fgets(line, sizeof(line), key_file) && !(sbk.found() && tsec.found())) {
                if (strncmp("secure_boot_key", line, 15) == 0)
                    sbk = Key("secure_boot_key", 0x10, key_string_to_byte_vector(line));
                else if (strncmp("tsec_key", line, 8) == 0)
                    tsec = Key("tsec_key", 0x10, key_string_to_byte_vector(line));
            }
            fclose(key_file);
        }
    }

    void wait_to_exit() {
        draw_text(0x10b, 0x24b, YELLOW, ">> Press + to exit <<");

        while(appletMainLoop()) {
            hidScanInput();
            u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);
            if (kDown & KEY_PLUS) break;

            update_display();
        }

        framebufferClose(&fb);
        FT_Done_Face(face);
        FT_Done_FreeType(library);

        appletUnlockExit();
    }

    void update_display() {
        framebufferBegin(&fb, &stride);
        framebufferEnd(&fb);
    }

    byte_vector key_string_to_byte_vector(std::string key_string) {
        key_string = key_string.substr(key_string.find('=') + 2);
        byte_vector temp_key((key_string.size() - 1) / 2);
        for (size_t i = 0; i < temp_key.size() - 1; i += 8)
            *reinterpret_cast<u64 *>(temp_key.data() + i) = __bswap64(strtoul(key_string.substr(i * 2, 0x10).c_str(), NULL, 16));
        return temp_key;
    }
}