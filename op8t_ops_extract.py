#!/usr/bin/env python3
# (c) B.Kerler, MIT license
import os
import sys
import xml.etree.ElementTree as ET
from struct import unpack
from binascii import unhexlify, hexlify
import shutil
from cffi import FFI

crypt_code = r"""
typedef unsigned char   uint8;
typedef unsigned short  uint16;
typedef unsigned int    uint32;
#define _BYTE  uint8
#define _WORD  uint16
#define _DWORD uint32
#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
#define WORDn(x, n)   (*((_WORD*)&(x)+n))
#define DWORDn(x, n)  (*((_DWORD*)&(x)+n))
#define LAST_IND(x,part_type)    (sizeof(x)/sizeof(part_type) - 1)
#  define HIGH_IND(x,part_type)  LAST_IND(x,part_type)
#  define LOW_IND(x,part_type)   0
#define LOBYTE(x)  BYTEn(x,LOW_IND(x,_BYTE))
#define LOWORD(x)  WORDn(x,LOW_IND(x,_WORD))
#define LODWORD(x) DWORDn(x,LOW_IND(x,_DWORD))
#define HIBYTE(x)  BYTEn(x,HIGH_IND(x,_BYTE))
#define HIWORD(x)  WORDn(x,HIGH_IND(x,_WORD))
#define HIDWORD(x) DWORDn(x,HIGH_IND(x,_DWORD))
#define BYTE1(x)   BYTEn(x,  1)         // byte 1 (counting from 0)
#define BYTE2(x)   BYTEn(x,  2)
#define BYTE3(x)   BYTEn(x,  3)
#define BYTE4(x)   BYTEn(x,  4)

unsigned int box1[] =
{
0xA56363C6, 0xA56363C6, 0x847C7CF8, 0x847C7CF8, 
0x997777EE, 0x997777EE, 0x8D7B7BF6, 0x8D7B7BF6, 
0x0DF2F2FF, 0x0DF2F2FF, 0xBD6B6BD6, 0xBD6B6BD6, 
0xB16F6FDE, 0xB16F6FDE, 0x54C5C591, 0x54C5C591, 
0x50303060, 0x50303060, 0x03010102, 0x03010102, 
0xA96767CE, 0xA96767CE, 0x7D2B2B56, 0x7D2B2B56, 
0x19FEFEE7, 0x19FEFEE7, 0x62D7D7B5, 0x62D7D7B5, 
0xE6ABAB4D, 0xE6ABAB4D, 0x9A7676EC, 0x9A7676EC, 
0x45CACA8F, 0x45CACA8F, 0x9D82821F, 0x9D82821F, 
0x40C9C989, 0x40C9C989, 0x877D7DFA, 0x877D7DFA, 
0x15FAFAEF, 0x15FAFAEF, 0xEB5959B2, 0xEB5959B2, 
0xC947478E, 0xC947478E, 0x0BF0F0FB, 0x0BF0F0FB, 
0xECADAD41, 0xECADAD41, 0x67D4D4B3, 0x67D4D4B3, 
0xFDA2A25F, 0xFDA2A25F, 0xEAAFAF45, 0xEAAFAF45, 
0xBF9C9C23, 0xBF9C9C23, 0xF7A4A453, 0xF7A4A453, 
0x967272E4, 0x967272E4, 0x5BC0C09B, 0x5BC0C09B, 
0xC2B7B775, 0xC2B7B775, 0x1CFDFDE1, 0x1CFDFDE1, 
0xAE93933D, 0xAE93933D, 0x6A26264C, 0x6A26264C, 
0x5A36366C, 0x5A36366C, 0x413F3F7E, 0x413F3F7E, 
0x02F7F7F5, 0x02F7F7F5, 0x4FCCCC83, 0x4FCCCC83, 
0x5C343468, 0x5C343468, 0xF4A5A551, 0xF4A5A551, 
0x34E5E5D1, 0x34E5E5D1, 0x08F1F1F9, 0x08F1F1F9, 
0x937171E2, 0x937171E2, 0x73D8D8AB, 0x73D8D8AB, 
0x53313162, 0x53313162, 0x3F15152A, 0x3F15152A, 
0x0C040408, 0x0C040408, 0x52C7C795, 0x52C7C795, 
0x65232346, 0x65232346, 0x5EC3C39D, 0x5EC3C39D, 
0x28181830, 0x28181830, 0xA1969637, 0xA1969637, 
0x0F05050A, 0x0F05050A, 0xB59A9A2F, 0xB59A9A2F, 
0x0907070E, 0x0907070E, 0x36121224, 0x36121224, 
0x9B80801B, 0x9B80801B, 0x3DE2E2DF, 0x3DE2E2DF, 
0x26EBEBCD, 0x26EBEBCD, 0x6927274E, 0x6927274E, 
0xCDB2B27F, 0xCDB2B27F, 0x9F7575EA, 0x9F7575EA, 
0x1B090912, 0x1B090912, 0x9E83831D, 0x9E83831D, 
0x742C2C58, 0x742C2C58, 0x2E1A1A34, 0x2E1A1A34, 
0x2D1B1B36, 0x2D1B1B36, 0xB26E6EDC, 0xB26E6EDC, 
0xEE5A5AB4, 0xEE5A5AB4, 0xFBA0A05B, 0xFBA0A05B, 
0xF65252A4, 0xF65252A4, 0x4D3B3B76, 0x4D3B3B76, 
0x61D6D6B7, 0x61D6D6B7, 0xCEB3B37D, 0xCEB3B37D, 
0x7B292952, 0x7B292952, 0x3EE3E3DD, 0x3EE3E3DD, 
0x712F2F5E, 0x712F2F5E, 0x97848413, 0x97848413, 
0xF55353A6, 0xF55353A6, 0x68D1D1B9, 0x68D1D1B9, 
0x00000000, 0x00000000, 0x2CEDEDC1, 0x2CEDEDC1, 
0x60202040, 0x60202040, 0x1FFCFCE3, 0x1FFCFCE3, 
0xC8B1B179, 0xC8B1B179, 0xED5B5BB6, 0xED5B5BB6, 
0xBE6A6AD4, 0xBE6A6AD4, 0x46CBCB8D, 0x46CBCB8D, 
0xD9BEBE67, 0xD9BEBE67, 0x4B393972, 0x4B393972, 
0xDE4A4A94, 0xDE4A4A94, 0xD44C4C98, 0xD44C4C98, 
0xE85858B0, 0xE85858B0, 0x4ACFCF85, 0x4ACFCF85, 
0x6BD0D0BB, 0x6BD0D0BB, 0x2AEFEFC5, 0x2AEFEFC5, 
0xE5AAAA4F, 0xE5AAAA4F, 0x16FBFBED, 0x16FBFBED, 
0xC5434386, 0xC5434386, 0xD74D4D9A, 0xD74D4D9A, 
0x55333366, 0x55333366, 0x94858511, 0x94858511, 
0xCF45458A, 0xCF45458A, 0x10F9F9E9, 0x10F9F9E9, 
0x06020204, 0x06020204, 0x817F7FFE, 0x817F7FFE, 
0xF05050A0, 0xF05050A0, 0x443C3C78, 0x443C3C78, 
0xBA9F9F25, 0xBA9F9F25, 0xE3A8A84B, 0xE3A8A84B, 
0xF35151A2, 0xF35151A2, 0xFEA3A35D, 0xFEA3A35D, 
0xC0404080, 0xC0404080, 0x8A8F8F05, 0x8A8F8F05, 
0xAD92923F, 0xAD92923F, 0xBC9D9D21, 0xBC9D9D21, 
0x48383870, 0x48383870, 0x04F5F5F1, 0x04F5F5F1, 
0xDFBCBC63, 0xDFBCBC63, 0xC1B6B677, 0xC1B6B677, 
0x75DADAAF, 0x75DADAAF, 0x63212142, 0x63212142, 
0x30101020, 0x30101020, 0x1AFFFFE5, 0x1AFFFFE5, 
0x0EF3F3FD, 0x0EF3F3FD, 0x6DD2D2BF, 0x6DD2D2BF, 
0x4CCDCD81, 0x4CCDCD81, 0x140C0C18, 0x140C0C18, 
0x35131326, 0x35131326, 0x2FECECC3, 0x2FECECC3, 
0xE15F5FBE, 0xE15F5FBE, 0xA2979735, 0xA2979735, 
0xCC444488, 0xCC444488, 0x3917172E, 0x3917172E, 
0x57C4C493, 0x57C4C493, 0xF2A7A755, 0xF2A7A755, 
0x827E7EFC, 0x827E7EFC, 0x473D3D7A, 0x473D3D7A, 
0xAC6464C8, 0xAC6464C8, 0xE75D5DBA, 0xE75D5DBA, 
0x2B191932, 0x2B191932, 0x957373E6, 0x957373E6, 
0xA06060C0, 0xA06060C0, 0x98818119, 0x98818119, 
0xD14F4F9E, 0xD14F4F9E, 0x7FDCDCA3, 0x7FDCDCA3, 
0x66222244, 0x66222244, 0x7E2A2A54, 0x7E2A2A54, 
0xAB90903B, 0xAB90903B, 0x8388880B, 0x8388880B, 
0xCA46468C, 0xCA46468C, 0x29EEEEC7, 0x29EEEEC7, 
0xD3B8B86B, 0xD3B8B86B, 0x3C141428, 0x3C141428, 
0x79DEDEA7, 0x79DEDEA7, 0xE25E5EBC, 0xE25E5EBC, 
0x1D0B0B16, 0x1D0B0B16, 0x76DBDBAD, 0x76DBDBAD, 
0x3BE0E0DB, 0x3BE0E0DB, 0x56323264, 0x56323264, 
0x4E3A3A74, 0x4E3A3A74, 0x1E0A0A14, 0x1E0A0A14, 
0xDB494992, 0xDB494992, 0x0A06060C, 0x0A06060C, 
0x6C242448, 0x6C242448, 0xE45C5CB8, 0xE45C5CB8, 
0x5DC2C29F, 0x5DC2C29F, 0x6ED3D3BD, 0x6ED3D3BD, 
0xEFACAC43, 0xEFACAC43, 0xA66262C4, 0xA66262C4, 
0xA8919139, 0xA8919139, 0xA4959531, 0xA4959531, 
0x37E4E4D3, 0x37E4E4D3, 0x8B7979F2, 0x8B7979F2, 
0x32E7E7D5, 0x32E7E7D5, 0x43C8C88B, 0x43C8C88B, 
0x5937376E, 0x5937376E, 0xB76D6DDA, 0xB76D6DDA, 
0x8C8D8D01, 0x8C8D8D01, 0x64D5D5B1, 0x64D5D5B1, 
0xD24E4E9C, 0xD24E4E9C, 0xE0A9A949, 0xE0A9A949, 
0xB46C6CD8, 0xB46C6CD8, 0xFA5656AC, 0xFA5656AC, 
0x07F4F4F3, 0x07F4F4F3, 0x25EAEACF, 0x25EAEACF, 
0xAF6565CA, 0xAF6565CA, 0x8E7A7AF4, 0x8E7A7AF4, 
0xE9AEAE47, 0xE9AEAE47, 0x18080810, 0x18080810, 
0xD5BABA6F, 0xD5BABA6F, 0x887878F0, 0x887878F0, 
0x6F25254A, 0x6F25254A, 0x722E2E5C, 0x722E2E5C, 
0x241C1C38, 0x241C1C38, 0xF1A6A657, 0xF1A6A657, 
0xC7B4B473, 0xC7B4B473, 0x51C6C697, 0x51C6C697, 
0x23E8E8CB, 0x23E8E8CB, 0x7CDDDDA1, 0x7CDDDDA1, 
0x9C7474E8, 0x9C7474E8, 0x211F1F3E, 0x211F1F3E, 
0xDD4B4B96, 0xDD4B4B96, 0xDCBDBD61, 0xDCBDBD61, 
0x868B8B0D, 0x868B8B0D, 0x858A8A0F, 0x858A8A0F, 
0x907070E0, 0x907070E0, 0x423E3E7C, 0x423E3E7C, 
0xC4B5B571, 0xC4B5B571, 0xAA6666CC, 0xAA6666CC, 
0xD8484890, 0xD8484890, 0x05030306, 0x05030306, 
0x01F6F6F7, 0x01F6F6F7, 0x120E0E1C, 0x120E0E1C, 
0xA36161C2, 0xA36161C2, 0x5F35356A, 0x5F35356A, 
0xF95757AE, 0xF95757AE, 0xD0B9B969, 0xD0B9B969, 
0x91868617, 0x91868617, 0x58C1C199, 0x58C1C199, 
0x271D1D3A, 0x271D1D3A, 0xB99E9E27, 0xB99E9E27, 
0x38E1E1D9, 0x38E1E1D9, 0x13F8F8EB, 0x13F8F8EB, 
0xB398982B, 0xB398982B, 0x33111122, 0x33111122, 
0xBB6969D2, 0xBB6969D2, 0x70D9D9A9, 0x70D9D9A9, 
0x898E8E07, 0x898E8E07, 0xA7949433, 0xA7949433, 
0xB69B9B2D, 0xB69B9B2D, 0x221E1E3C, 0x221E1E3C, 
0x92878715, 0x92878715, 0x20E9E9C9, 0x20E9E9C9, 
0x49CECE87, 0x49CECE87, 0xFF5555AA, 0xFF5555AA, 
0x78282850, 0x78282850, 0x7ADFDFA5, 0x7ADFDFA5, 
0x8F8C8C03, 0x8F8C8C03, 0xF8A1A159, 0xF8A1A159, 
0x80898909, 0x80898909, 0x170D0D1A, 0x170D0D1A, 
0xDABFBF65, 0xDABFBF65, 0x31E6E6D7, 0x31E6E6D7, 
0xC6424284, 0xC6424284, 0xB86868D0, 0xB86868D0, 
0xC3414182, 0xC3414182, 0xB0999929, 0xB0999929, 
0x772D2D5A, 0x772D2D5A, 0x110F0F1E, 0x110F0F1E, 
0xCBB0B07B, 0xCBB0B07B, 0xFC5454A8, 0xFC5454A8, 
0xD6BBBB6D, 0xD6BBBB6D, 0x3A16162C, 0x3A16162C
};

static void block_crypt(unsigned int* input, unsigned int* output, unsigned int* state)
{
  unsigned int v6; // ebx
  unsigned int v7; // edx
  unsigned int v8; // ST14_4
  unsigned int v9; // edi
  unsigned int v10; // edx
  unsigned int v11; // ebx
  unsigned int v12; // eax
  unsigned int v13; // ebx
  unsigned int* v14; // edi
  unsigned int v15; // esi
  unsigned int v16; // ecx
  unsigned int tmp; // ecx
  int round; // [esp+10h] [ebp-Ch]
  unsigned int v19; // [esp+14h] [ebp-8h]
  unsigned int v20; // [esp+18h] [ebp-4h]
  unsigned int a1b; // [esp+24h] [ebp+8h]
  unsigned int a1a; // [esp+24h] [ebp+8h]
  unsigned int a3a; // [esp+2Ch] [ebp+10h]

  v6 = state[1] ^ input[1];
  a1b = *state ^ *input;
  v7 = state[3] ^ input[3];
  v8 = state[2] ^ input[2];
  v20 = state[4] ^ box1[2 * (a1b&0xff)] ^ *(int*)((char*)&box1[2 * (v7 >> 24)] + 1) ^ *(int*)((char*)&box1[2 * ((v6&0xffff) >> 8)] + 3) ^ *(int*)((char*)&box1[2 * ((v8 >> 16) & 0xFF)] + 2);
  a3a = state[5] ^ box1[2 * (v6&0xff)] ^ *(int*)((char*)&box1[2 * (a1b >> 24)] + 1) ^ *(int*)((char*)&box1[2 * ((v8&0xffff) >> 8)] + 3) ^ *(int*)((char*)&box1[2 * ((v7 >> 16) & 0xFF)] + 2);
  v9 = state[6] ^ box1[2 * (v8&0xff)] ^ *(int*)((char*)&box1[2 * (v6 >> 24)] + 1) ^ *(int*)((char*)&box1[2 * ((a1b >> 16) & 0xFF)] + 2) ^ *(int*)((char*)&box1[2 * ((v7&0xffff) >> 8)] + 3);
  v12 = v7 & 0xff;
  v10 = v20;
  v11 = state[7] ^ box1[2 * v12] ^ *(int*)((char*)&box1[2 * (v8 >> 24)] + 1) ^ *(int*)((char*)&box1[2 * ((a1b&0xffff) >> 8)] + 3) ^ *(int*)((char*)&box1[2 * ((v6 >> 16) & 0xFF)] + 2);
  LOWORD(v12) = a3a;
  a1a = v11;
  v13 = v9;
  v19 = v9;
  v14 = state + 8;
  round = state[60] - 2;
  if (round > 0)
  {
	v15 = a3a;
	do
	{
	  v20 = *v14 ^ box1[2 * (v20&0xff)] ^ *(int*)((char*)&box1[2 * (a1a >> 24)] + 1) ^ *(int*)((char*)&box1[2 * ((v12&0xffff) >> 8)] + 3) ^ *(int*)((char*)&box1[2 * ((v13 >> 16) & 0xFF)] + 2);
	  a3a = v14[1] ^ box1[2 * (a3a&0xff)] ^ *(int*)((char*)&box1[2 * (v10 >> 24)] + 1) ^ *(int*)((char*)&box1[2 * ((v13&0xffff) >> 8)] + 3) ^ *(int*)((char*)&box1[2 * ((a1a >> 16) & 0xFF)] + 2);
	  v13 = v14[2] ^ box1[2 * (v13&0xff)] ^ *(int*)((char*)&box1[2 * (v15 >> 24)] + 1) ^ *(int*)((char*)&box1[2 * ((v10 >> 16) & 0xFF)] + 2) ^ *(int*)((char*)&box1[2 * ((a1a&0xffff) >> 8)] + 3);
	  v16 = *(int*)((char*)&box1[2 * ((v10&0xffff) >> 8)] + 3) ^ *(int*)((char*)&box1[2 * ((v15 >> 16) & 0xFF)]
		+ 2);
	  v10 = v20;
	  v12 = v19 >> 24;
	  v19 = v13;
	  tmp = v14[3] ^ box1[2 * (a1a&0xff)] ^ *(int*)((char*)&box1[2 * v12] + 1) ^ v16;
	  v14 += 4;
	  LOWORD(v12) = a3a;
	  v15 = a3a;
	  a1a = tmp;
	  --round;
	} while (round > 0);
  }
  *output = *v14 ^ BYTE2(box1[2 * (unsigned char)v20]) ^ (*(int*)((char*)&box1[2 * (a1a >> 24)] + 3) & 0xFF000000) ^ (*(int*)((char*)&box1[2 * ((a3a&0xffff) >> 8)] + 1) & 0xFF00) ^ (box1[2 * ((v13 >> 16) & 0xFF)] & 0xFF0000);
	output[1] = v14[1] ^ BYTE2(box1[2 * (unsigned char)a3a]) ^ (*(int*)((char*)&box1[2 * (v20 >> 24)] + 3) & 0xFF000000) ^ (*(int*)((char*)&box1[2 * ((v13&0xffff) >> 8)] + 1) & 0xFF00) ^ (box1[2 * ((a1a >> 16) & 0xFF)] & 0xFF0000);
  output[2] = v14[2] ^ BYTE2(box1[2 * (unsigned char)v13]) ^ (*(int*)((char*)&box1[2 * (a3a >> 24)] + 3) & 0xFF000000) ^ (*(int*)((char*)&box1[2 * ((a1a&0xffff) >> 8)] + 1) & 0xFF00) ^ (box1[2 * ((v20 >> 16) & 0xFF)] & 0xFF0000);
  output[3] = v14[3] ^ BYTE2(box1[2 * (unsigned char)a1a]) ^ (*(int*)((char*)&box1[2 * (v13 >> 24)] + 3) & 0xFF000000) ^ (*(int*)((char*)&box1[2 * ((v20&0xffff) >> 8)] + 1) & 0xFF00) ^ (box1[2 * ((a3a >> 16) & 0xFF)] & 0xFF0000);
}

struct block_state 
{
  unsigned int k[60];
  int round;
};

static void aes_crypt(unsigned char* d)
{
  struct block_state s = {{0x60,0x8A,0x3F,0x2D,0x68,0x6B,0xD4,0x23,0x51,0x0C,0xD0,0x95,0xBB,0x40,0xE9,0x76}, 10};
  block_crypt((unsigned int*)d, (unsigned int*)d, (unsigned int*)&s);
}

"""

ffi = FFI()
ffi.cdef("""
static void block_crypt(unsigned int* input, unsigned int* output, unsigned int* state);
static void aes_crypt(unsigned char* d);
""")
ffi.set_source("op8topscrypt", crypt_code)
ffi.compile(verbose=False)

from op8topscrypt import ffi as op8topscrypt_ffi
from op8topscrypt import lib as op8topscrypt_lib

gkey = [0xD1, 0xB5, 0xE3, 0x9E, 0x5E, 0xEA, 0x04, 0x9D,
        0x67, 0x1D, 0xD5, 0xAB, 0xD2, 0xAF, 0xCB, 0xAF]


def decrypt(data):
    key1 = bytearray(list.copy(gkey))
    data_array = bytearray(data)
    for i in range(int(len(data)/16)):
        key2 = op8topscrypt_ffi.new("char[]", bytes(key1))
        op8topscrypt_lib.aes_crypt(key2)
        key3 = op8topscrypt_ffi.buffer(key2)[:-1]
        key1 = bytearray(key3)
        op8topscrypt_ffi.release(key2)
        key2 = None
        for j in range(16):
            tmp = data_array[i*16+j] ^ key1[j]
            key1[j] = data_array[i*16+j]
            data_array[i*16+j] = tmp

    left = len(data) % 16
    if left > 0:
        i = len(data) - left
        key2 = op8topscrypt_ffi.new("char[]", bytes(key1))
        op8topscrypt_lib.aes_crypt(key2)
        key3 = op8topscrypt_ffi.buffer(key2)[:-1]
        key1 = bytearray(key3)
        op8topscrypt_ffi.release(key2)
        key2 = None
        for j in range(left):
            tmp = data_array[i+j] ^ key1[j]
            key1[j] = data_array[i+j]
            data_array[i+j] = tmp

    return data_array


def extract_xml(filename):
    filesize = os.stat(filename).st_size
    with open(filename, 'rb') as rf:
        pagesize = 0x200
        xmloffset = filesize-pagesize
        rf.seek(xmloffset+0x10)
        if unpack("<I", rf.read(4))[0] == 0x7CEF:
            pagesize = 0x200
        else:
            pagesize = 0x1000
            xmloffset = filesize-pagesize
            rf.seek(xmloffset + 0x10)
            magic = unpack("<I", rf.read(4))[0]
            if not magic == 0x7CEF:
                print("Unknown pagesize. Aborting")
                exit(0)

        rf.seek(xmloffset+0x14)
        offset = unpack("<I", rf.read(4))[0]*pagesize
        length = unpack("<I", rf.read(4))[0]
        if length < 200:  # A57 hack
            length = xmloffset-offset-0x57
        rf.seek(offset)
        data = rf.read(length)
        dec = decrypt(data)

        if b"<?xml" in dec:
            return pagesize, dec
        else:
            return 0, ""


def extract_file(ops_filename, out_path, out_file_name, offset, length, align=0x1000, decrypt_block=0):
    with open(ops_filename, 'rb') as rf:
        with open(os.path.join(out_path, out_file_name), 'wb') as wf:
            rf.seek(offset)
            data = rf.read(length)
            if decrypt_block > 0:
                decrypt_cur = 0
                while (decrypt_cur+decrypt_block) < length:
                    dec_data = decrypt(data[decrypt_cur:decrypt_cur+decrypt_block])
                    decrypt_cur += decrypt_block
                    wf.write(dec_data)
                if (length - decrypt_cur) > 0:
                    dec_data = decrypt(data[decrypt_cur:])
                    wf.write(dec_data)
            if align > 0 and length % align:
                align_data = (align-(length % align))*b'\x00'
                wf.write(align_data)


def main():
    # with open('prog_firehose_ddr.elf', 'rb') as rf:
    #     a=rf.read()
    # b = decrypt(a[:0x40000]) + decrypt(a[0x40000:0x80000]) + decrypt(a[0x80000:0xc0000]) + decrypt(a[0xc0000:])
    # with open('dec.bin', 'wb') as f:
    #     f.write(b)
    # return

    if len(sys.argv) < 3:
        print(
            "Usage: ./op8t_ops_extract.py [Filename.ops] [Directory to extract files to]")
        exit(0)

    ops_filename = sys.argv[1]
    outdir = sys.argv[2]
    if not os.path.exists(outdir):
        os.mkdir(outdir)

    pagesize, data = extract_xml(ops_filename)
    xml = data[:data.rfind(b">")+1].decode('utf-8-sig')

    if "/" in ops_filename:
        path = ops_filename[:ops_filename.rfind("/")]
    elif "\\" in ops_filename:
        path = ops_filename[:ops_filename.rfind("\\")]
    else:
        path = ""

    path = os.path.join(path, outdir)

    if os.path.exists(path):
        shutil.rmtree(path)
        os.mkdir(path)
    else:
        os.mkdir(path)

    with open(os.path.join(path, "manifest.xml"), 'w') as wf:
        wf.write(xml)

    root = ET.fromstring(xml)
    for child in root:
        if child.tag.upper() in ["SAHARA", "UFS_PROVISION"]:
            for item in child:
                if item.tag == "File":
                    out_file_name = item.attrib["Path"]
                    if "label" in item.attrib:
                        label = item.attrib["label"]
                    else:
                        label = out_file_name
                    offset = int(item.attrib["FileOffsetInSrc"]) * pagesize
                    length = int(item.attrib["SizeInByteInSrc"])
                    print(f"Extracting {label} to {out_file_name}")
                    # hack for decrypt Sahara elf file
                    if child.tag.upper() in ["SAHARA"]:
                        decrypt_block = 0x40000
                    else:
                        decrypt_block = 0
                    if out_file_name.endswith(".xml"):
                        extract_file(ops_filename, path, out_file_name, offset, length, align=0, decrypt_block=decrypt_block)
                    else:
                        extract_file(ops_filename, path, out_file_name, offset, length, align=0, decrypt_block=decrypt_block)
        elif "Program" in child.tag:
            if not os.path.exists(os.path.join(path, child.tag)):
               os.mkdir(os.path.join(path, child.tag))
            spath = os.path.join(path, child.tag)
            for item in child:
                if "filename" in item.attrib:
                    out_file_name = item.attrib["filename"]
                    if out_file_name == "":
                        continue
                    if "label" in item.attrib:
                        label = item.attrib["label"]
                    else:
                        label = out_file_name
                    offset = int(item.attrib["FileOffsetInSrc"]) * pagesize
                    length = int(item.attrib["SizeInByteInSrc"])
                    print(f"Extracting {label} to {out_file_name}")
                    extract_file(ops_filename, spath, out_file_name, offset, length)
                else:
                    for subitem in item:
                        if "filename" in subitem.attrib:
                            out_file_name = subitem.attrib["filename"]
                            if out_file_name == "":
                                continue
                            if "label" in item.attrib:
                                label = item.attrib["label"]
                            else:
                                label = out_file_name
                            offset = int(
                                subitem.attrib["FileOffsetInSrc"]) * pagesize
                            length = int(subitem.attrib["SizeInByteInSrc"])
                            print(f"Extracting {label} to {out_file_name}")
                            extract_file(ops_filename, spath,
                                         out_file_name, offset, length)
        # else:
        #    print (child.tag, child.attrib)
    print("Done. Extracted files to " + path)
    exit(0)


if __name__ == "__main__":
    main()
