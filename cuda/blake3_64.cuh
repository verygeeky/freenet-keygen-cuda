// SPDX-License-Identifier: GPL-3.0-or-later
// blake3_64.cuh - BLAKE3 for an input of EXACTLY 64 bytes, 32-byte output.
//
// Why this is short: BLAKE3's tree machinery only engages past one 1024-byte
// chunk. A 64-byte input is a single chunk containing a single block, so the
// whole hash collapses to ONE compression with
// flags = CHUNK_START|CHUNK_END|ROOT and counter = 0. No chunk chaining, no
// parent nodes, no XOF state. That is the entire reason a Freenet contract-key
// search is cheap to put on a GPU: the derivation is
// blake3(code_hash[32] || pubkey[32]).
//
// Implements the compression function as described in the BLAKE3
// specification (IV, message permutation, G function and flags). BLAKE3 and
// its reference implementation are by the BLAKE3 team; see
// THIRD_PARTY_NOTICES.md.
//
// Output byte order: BLAKE3 emits little-endian words. Freenet base58-encodes
// those 32 bytes as a big-endian integer, so a plain lexicographic memcmp over
// the output bytes is exactly an integer comparison — which is what lets the
// range test below be two 32-byte compares instead of a base58 encode.

#pragma once
#include <cstdint>

#ifndef DEVN
#define DEVN __device__ __host__
#endif

typedef unsigned char b3u8;
typedef uint32_t b3u32;

#ifdef __CUDACC__
__device__ __constant__ static const b3u32 B3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};
#endif

// Host mirror (device __constant__ is not addressable from host code).
static const b3u32 B3_IV_H[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};

// Must be visible in device code, so it cannot be a plain host static.
DEVN static inline int b3_perm(int i) {
    const int P[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
    return P[i];
}

DEVN static inline b3u32 b3_rotr(b3u32 x, int n) { return (x >> n) | (x << (32 - n)); }

DEVN static inline void b3_g(b3u32 *v, int a, int b, int c, int d, b3u32 mx, b3u32 my) {
    v[a] = v[a] + v[b] + mx;
    v[d] = b3_rotr(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = b3_rotr(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + my;
    v[d] = b3_rotr(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];
    v[b] = b3_rotr(v[b] ^ v[c], 7);
}

DEVN static inline void b3_round(b3u32 *v, const b3u32 *m) {
    b3_g(v, 0, 4, 8, 12, m[0], m[1]);
    b3_g(v, 1, 5, 9, 13, m[2], m[3]);
    b3_g(v, 2, 6, 10, 14, m[4], m[5]);
    b3_g(v, 3, 7, 11, 15, m[6], m[7]);
    b3_g(v, 0, 5, 10, 15, m[8], m[9]);
    b3_g(v, 1, 6, 11, 12, m[10], m[11]);
    b3_g(v, 2, 7, 8, 13, m[12], m[13]);
    b3_g(v, 3, 4, 9, 14, m[14], m[15]);
}

// in[64] -> out[32].
DEVN static inline void blake3_64(b3u8 *out, const b3u8 *in) {
    const b3u32 CHUNK_START = 1u, CHUNK_END = 2u, ROOT = 8u;

    b3u32 m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = (b3u32)in[4 * i] | ((b3u32)in[4 * i + 1] << 8) |
               ((b3u32)in[4 * i + 2] << 16) | ((b3u32)in[4 * i + 3] << 24);
    }

    b3u32 v[16];
#ifdef __CUDA_ARCH__
    for (int i = 0; i < 8; i++) v[i] = B3_IV[i];
    for (int i = 0; i < 4; i++) v[8 + i] = B3_IV[i];
#else
    for (int i = 0; i < 8; i++) v[i] = B3_IV_H[i];
    for (int i = 0; i < 4; i++) v[8 + i] = B3_IV_H[i];
#endif
    v[12] = 0;                                   // counter low  (single chunk)
    v[13] = 0;                                   // counter high
    v[14] = 64;                                  // block length
    v[15] = CHUNK_START | CHUNK_END | ROOT;      // 11

    b3u32 mm[16];
    for (int i = 0; i < 16; i++) mm[i] = m[i];

    for (int r = 0; r < 7; r++) {
        b3_round(v, mm);
        if (r < 6) {                             // permute between rounds only
            b3u32 t[16];
            for (int i = 0; i < 16; i++) t[i] = mm[b3_perm(i)];
            for (int i = 0; i < 16; i++) mm[i] = t[i];
        }
    }

    // Root output: first 8 words are v[i] ^ v[i+8].
    for (int i = 0; i < 8; i++) {
        b3u32 w = v[i] ^ v[i + 8];
        out[4 * i + 0] = (b3u8)(w & 0xff);
        out[4 * i + 1] = (b3u8)((w >> 8) & 0xff);
        out[4 * i + 2] = (b3u8)((w >> 16) & 0xff);
        out[4 * i + 3] = (b3u8)((w >> 24) & 0xff);
    }
}

// Big-endian-integer range test over 32 raw bytes (see byte-order note above).
DEVN static inline bool b3_in_range(const b3u8 *id, const b3u8 *lo, const b3u8 *hi) {
    int c = 0;
    for (int i = 0; i < 32 && c == 0; i++) c = (int)id[i] - (int)lo[i];
    if (c < 0) return false;
    c = 0;
    for (int i = 0; i < 32 && c == 0; i++) c = (int)id[i] - (int)hi[i];
    return c <= 0;
}
