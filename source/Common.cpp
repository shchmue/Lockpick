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

#include <algorithm>
#include <filesystem>
#include <fstream>

extern "C" {
    #include <machine/endian.h>
}

#include "sha256.h"

namespace Common {
    static u32 framebuf_width = 0;
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

        consoleInit(NULL);

        plGetSharedFontByType(&font, PlSharedFontType_Standard);

        FT_Init_FreeType(&library);
        FT_New_Memory_Face(library, static_cast<FT_Byte *>(font.address), font.size, 0, &face);
        FT_Set_Char_Size(face, 0, 6*64, 300, 300);

        gfxSetMode(GfxMode_LinearDouble);
        framebuf = (u32 *)gfxGetFramebuffer(&framebuf_width, NULL);
        memset(framebuf, 0, gfxGetFramebufferSize());
        
        draw_text(0x10, 0x020, YELLOW, "Lockpick! by shchmue");
        
        draw_text(814, 452, RED, "MAKE AMERICA GREAT AGAIN!");
        
        draw_text(814, 500, YELLOW, "TRUMP 2020!");
        draw_text(814, 545, WHITE, "IT'S OKAY TO BE WHITE");

        if (  !(envIsSyscallHinted(0x60) &&     // svcDebugActiveProcess
                envIsSyscallHinted(0x63) &&     // svcGetDebugEvent
                envIsSyscallHinted(0x65) &&     // svcGetProcessList
                envIsSyscallHinted(0x69) &&     // svcQueryDebugProcessMemory
                envIsSyscallHinted(0x6a))) {    // svcReadDebugProcessMemory
            draw_text(0x190, 0x20, RED, "Error: Please run with debug svc permissions!");
            wait_to_exit(Status_fail);
        }

        draw_text(0x10, 0x080, CYAN, "Get Tegra keys...");
        draw_text(0x10, 0x0a0, CYAN, "Get keys from memory...");
        draw_text(0x10, 0x0c0, CYAN, "Get master keys...");
        draw_text(0x10, 0x0e0, CYAN, "Derive remaining keys...");
        draw_text(0x10, 0x100, CYAN, "Saving keys to keyfile...");
        draw_text(0x10, 0x130, CYAN, "Total time elapsed:");

        consoleUpdate(NULL);
    }

    void get_tegra_keys(Key &sbk, Key &tsec, Key &tsec_root) {
        // support hekate dump
        if (!std::filesystem::exists("/backup"))
            return;
        for (auto &p : std::filesystem::recursive_directory_iterator("/backup")) {
            if (sbk.found() && tsec.found())
                return;
            if (p.is_regular_file()) {
                if (!sbk.found() && (p.file_size() == 0x2fc) &&
                    (std::string("fuse").compare(std::string(p.path().filename()).substr(0, 4)) == 0))
                {
                    std::ifstream fuse_file(p.path(), std::ios::binary);
                    byte_vector temp_key(0x10);
                    fuse_file.seekg(0xa4);
                    fuse_file.read(reinterpret_cast<char *>(temp_key.data()), 0x10);
                    sbk = Key("secure_boot_key", 0x10, temp_key);
                }
                else if (!tsec.found() && (p.file_size() == 0x30) &&
                    (std::string("tsec").compare(std::string(p.path().filename()).substr(0, 4)) == 0))
                {
                    std::ifstream tsec_file(p.path(), std::ios::binary);
                    byte_vector temp_key(0x10);
                    tsec_file.read(reinterpret_cast<char *>(temp_key.data()), 0x10);
                    tsec = Key("tsec_key", 0x10, temp_key);
                    tsec_file.read(reinterpret_cast<char *>(temp_key.data()), 0x10);
                    tsec_root.find_key(temp_key);
                }
            }
        }

        // support biskeydump v7 dump
        if (std::filesystem::exists("/device.keys")) {
            std::ifstream key_file("/device.keys");
            for (std::string line; std::getline(key_file, line); !sbk.found() && !tsec.found()) {
                line.erase(std::remove_if(
                    line.begin(), line.end(),
                    [l = std::locale{}](auto ch) { return std::isspace(ch, l); }
                ), line.end());
                if (line.substr(0, 15).compare("secure_boot_key") == 0)
                    sbk = Key("secure_boot_key", 0x10, key_string_to_byte_vector(line));
                else if (line.substr(0, 8).compare("tsec_key") == 0)
                    tsec = Key("tsec_key", 0x10, key_string_to_byte_vector(line));
            }
        }
    }

    void wait_to_exit(int status) {
        if (status == Status_fail)
            draw_text(0x1f4, 0x080, RED, ">> Press + to exit <<");
        else if (status == Status_success_no_titlekeys)
            draw_text(0x1f4, 0x1a0, GREEN, ">> Press + to exit <<");
        else if (status == Status_success_titlekeys)
            draw_text(0x1f4, 0x1f0, GREEN, ">> Press + to exit <<");
        else if (status == Status_success_titlekeys_failed)
            draw_text(0x1f4, 0x1f0, RED, ">> Press + to exit <<");

        while(appletMainLoop() & (status != Status_success_no_titlekeys)) {
            hidScanInput();
            u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);
            if (kDown & KEY_PLUS) break;

            consoleUpdate(NULL);
        }

        FT_Done_Face(face);
        FT_Done_FreeType(library);

        consoleExit(NULL);

        appletUnlockExit();
    }

    void sha256(const u8 *data, u8 *hash, size_t length) {
        struct sha256_state ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, data, length);
        sha256_finalize(&ctx);
        sha256_finish(&ctx, hash);
    }

    byte_vector key_string_to_byte_vector(std::string key_string) {
        key_string = key_string.substr(key_string.find('=') + 1);
        byte_vector temp_key(key_string.size() / 2);
        for (size_t i = 0; i < temp_key.size(); i += 8)
            *reinterpret_cast<u64 *>(temp_key.data() + i) = __bswap64(strtoul(key_string.substr(i * 2, 0x10).c_str(), NULL, 16));
        return temp_key;
    }
}