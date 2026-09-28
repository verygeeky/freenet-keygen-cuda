// SPDX-License-Identifier: GPL-3.0-or-later
// ed25519_fast.cuh - Ed25519 seed->pubkey for CUDA vanity search.
//
// Speedups over a straightforward TweetNaCl-style port:
//   * radix-2^51 field arithmetic (5x uint64 + __int128), ~10x fewer 64-bit
//     multiplies per field op than the 16x int64 (radix-2^16) representation.
//   * fixed-base scalar multiplication via a precomputed comb table
//     (WBITS=8: 32 windows x 255 multiples of B), so each keygen is ~31 mixed
//     additions with NO point doublings, instead of 255 double-and-add steps.
//
// fe_mul / fe_sq follow the radix-2^51 multiply and square formulas of
// curve25519-donna-c64 (Adam Langley, derived from D. J. Bernstein's public
// domain code; see THIRD_PARTY_NOTICES.md). fe_invert uses the ref10 addition
// chain (SUPERCOP, public domain). The point addition uses the extended
// twisted-Edwards (a=-1) formulas of Hisil, Wong, Carter and Dawson (2008).
//
// Correctness is gated by an on-device self-test against known public keys
// (see website-vanity.cu); if the field/point/table code were wrong the two
// known public keys would not reproduce.
#pragma once
#include <cstdint>

#ifdef __CUDACC__
  #define DEV __host__ __device__ __forceinline__
  #define DEVN __host__ __device__
#else
  #define DEV inline
  #define DEVN
#endif

typedef uint8_t  u8;
typedef uint64_t u64;
typedef unsigned __int128 u128;

typedef u64 fe[5];                 // field element, radix 2^51
struct ge    { fe X, Y, Z, T; };   // extended twisted-Edwards coords
struct gepre { fe ypx, ymx, xy2d; };// affine precomp: (y+x, y-x, 2*d*x*y)

#define MASK51 0x7ffffffffffffULL

// ------------------------------ byte helpers ------------------------------
DEV u64 fa_ld64le(const u8 *p){
  u64 r=0; for(int i=7;i>=0;--i) r=(r<<8)|p[i]; return r;
}
DEV u64 fa_ld64be(const u8 *p){
  u64 r=0; for(int i=0;i<8;i++) r=(r<<8)|p[i]; return r;
}
DEV void fa_st64be(u8 *p,u64 x){ for(int i=7;i>=0;--i){ p[i]=(u8)x; x>>=8; } }

// ------------------------------ field ops ---------------------------------
DEV void fe_copy(fe r,const fe a){ r[0]=a[0];r[1]=a[1];r[2]=a[2];r[3]=a[3];r[4]=a[4]; }
DEV void fe_0(fe r){ r[0]=r[1]=r[2]=r[3]=r[4]=0; }
DEV void fe_1(fe r){ r[0]=1; r[1]=r[2]=r[3]=r[4]=0; }

DEV void fe_add(fe r,const fe a,const fe b){
  r[0]=a[0]+b[0]; r[1]=a[1]+b[1]; r[2]=a[2]+b[2]; r[3]=a[3]+b[3]; r[4]=a[4]+b[4];
}
// r = a - b  (add 2p first so limbs stay unsigned/positive)
DEV void fe_sub(fe r,const fe a,const fe b){
  r[0]=a[0]+0xFFFFFFFFFFFDAULL-b[0];   // 2p limb0 = 2^52-38
  r[1]=a[1]+0xFFFFFFFFFFFFEULL-b[1];   // 2^52-2
  r[2]=a[2]+0xFFFFFFFFFFFFEULL-b[2];
  r[3]=a[3]+0xFFFFFFFFFFFFEULL-b[3];
  r[4]=a[4]+0xFFFFFFFFFFFFEULL-b[4];
}

// r = a*b  (curve25519-donna-c64 fmul)
DEV void fe_mul(fe out,const fe a,const fe b){
  u64 r0=a[0],r1=a[1],r2=a[2],r3=a[3],r4=a[4];
  u64 s0=b[0],s1=b[1],s2=b[2],s3=b[3],s4=b[4];
  u128 t0,t1,t2,t3,t4; u64 c;
  t0=(u128)r0*s0;
  t1=(u128)r0*s1+(u128)r1*s0;
  t2=(u128)r0*s2+(u128)r2*s0+(u128)r1*s1;
  t3=(u128)r0*s3+(u128)r3*s0+(u128)r1*s2+(u128)r2*s1;
  t4=(u128)r0*s4+(u128)r4*s0+(u128)r3*s1+(u128)r1*s3+(u128)r2*s2;
  r4*=19; r1*=19; r2*=19; r3*=19;
  t0+=(u128)r4*s1+(u128)r1*s4+(u128)r2*s3+(u128)r3*s2;
  t1+=(u128)r4*s2+(u128)r2*s4+(u128)r3*s3;
  t2+=(u128)r4*s3+(u128)r3*s4;
  t3+=(u128)r4*s4;
  r0=(u64)t0&MASK51; c=(u64)(t0>>51);
  t1+=c; r1=(u64)t1&MASK51; c=(u64)(t1>>51);
  t2+=c; r2=(u64)t2&MASK51; c=(u64)(t2>>51);
  t3+=c; r3=(u64)t3&MASK51; c=(u64)(t3>>51);
  t4+=c; r4=(u64)t4&MASK51; c=(u64)(t4>>51);
  r0+=c*19; c=r0>>51; r0&=MASK51;
  r1+=c;    c=r1>>51; r1&=MASK51;
  r2+=c;
  out[0]=r0;out[1]=r1;out[2]=r2;out[3]=r3;out[4]=r4;
}

// r = a^2  (curve25519-donna-c64 fsquare)
DEV void fe_sq(fe out,const fe a){
  u64 r0=a[0],r1=a[1],r2=a[2],r3=a[3],r4=a[4],c;
  u64 d0=r0*2, d1=r1*2, d2=r2*2*19, d419=r4*19, d4=d419*2;
  u128 t0,t1,t2,t3,t4;
  t0=(u128)r0*r0 + (u128)d4*r1 + (u128)d2*r3;
  t1=(u128)d0*r1 + (u128)d4*r2 + (u128)r3*(r3*19);
  t2=(u128)d0*r2 + (u128)r1*r1 + (u128)d4*r3;
  t3=(u128)d0*r3 + (u128)d1*r2 + (u128)r4*d419;
  t4=(u128)d0*r4 + (u128)d1*r3 + (u128)r2*r2;
  r0=(u64)t0&MASK51; c=(u64)(t0>>51);
  t1+=c; r1=(u64)t1&MASK51; c=(u64)(t1>>51);
  t2+=c; r2=(u64)t2&MASK51; c=(u64)(t2>>51);
  t3+=c; r3=(u64)t3&MASK51; c=(u64)(t3>>51);
  t4+=c; r4=(u64)t4&MASK51; c=(u64)(t4>>51);
  r0+=c*19; c=r0>>51; r0&=MASK51;
  r1+=c;    c=r1>>51; r1&=MASK51;
  r2+=c;
  out[0]=r0;out[1]=r1;out[2]=r2;out[3]=r3;out[4]=r4;
}

DEV void fe_sqn(fe r,const fe a,int n){ fe_sq(r,a); for(int i=1;i<n;i++) fe_sq(r,r); }

// r = 1/z = z^(p-2)   (ref10 addition chain)
DEVN void fe_invert(fe out,const fe z){
  fe t0,t1,t2,t3;
  fe_sq(t0,z);                    // z^2
  fe_sq(t1,t0); fe_sq(t1,t1);     // z^8
  fe_mul(t1,z,t1);                // z^9
  fe_mul(t0,t0,t1);               // z^11
  fe_sq(t2,t0);                   // z^22
  fe_mul(t1,t1,t2);               // z^(2^5-1)
  fe_sqn(t2,t1,5);   fe_mul(t1,t2,t1);   // 2^10-1
  fe_sqn(t2,t1,10);  fe_mul(t2,t2,t1);   // 2^20-1
  fe_sqn(t3,t2,20);  fe_mul(t3,t3,t2);   // 2^40-1
  fe_sqn(t3,t3,10);  fe_mul(t1,t3,t1);   // 2^50-1
  fe_sqn(t2,t1,50);  fe_mul(t2,t2,t1);   // 2^100-1
  fe_sqn(t3,t2,100); fe_mul(t3,t3,t2);   // 2^200-1
  fe_sqn(t3,t3,50);  fe_mul(t1,t3,t1);   // 2^250-1
  fe_sqn(t1,t1,5);   fe_mul(out,t1,t0);  // 2^255-21 = p-2
}

// canonical little-endian 32-byte encoding of a field element
DEVN void fe_tobytes(u8 s[32],const fe h){
  u64 h0=h[0],h1=h[1],h2=h[2],h3=h[3],h4=h[4],c;
  c=h0>>51;h0&=MASK51;h1+=c; c=h1>>51;h1&=MASK51;h2+=c;
  c=h2>>51;h2&=MASK51;h3+=c; c=h3>>51;h3&=MASK51;h4+=c;
  c=h4>>51;h4&=MASK51;h0+=19*c;
  c=h0>>51;h0&=MASK51;h1+=c; c=h1>>51;h1&=MASK51;h2+=c;
  c=h2>>51;h2&=MASK51;h3+=c; c=h3>>51;h3&=MASK51;h4+=c;
  c=h4>>51;h4&=MASK51;h0+=19*c;
  // conditional subtraction of p
  c=(h0+19)>>51; c=(h1+c)>>51; c=(h2+c)>>51; c=(h3+c)>>51; c=(h4+c)>>51;
  h0+=19*c;
  h1+=h0>>51;h0&=MASK51; h2+=h1>>51;h1&=MASK51;
  h3+=h2>>51;h2&=MASK51; h4+=h3>>51;h3&=MASK51; h4&=MASK51;
  u64 t0=h0|(h1<<51), t1=(h1>>13)|(h2<<38), t2=(h2>>26)|(h3<<25), t3=(h3>>39)|(h4<<12);
  for(int i=0;i<8;i++){ s[i]=(u8)(t0>>(8*i)); s[8+i]=(u8)(t1>>(8*i));
                        s[16+i]=(u8)(t2>>(8*i)); s[24+i]=(u8)(t3>>(8*i)); }
}
DEV void fe_frombytes(fe h,const u8 s[32]){
  h[0]= fa_ld64le(s)        & MASK51;
  h[1]=(fa_ld64le(s+6)>>3)  & MASK51;
  h[2]=(fa_ld64le(s+12)>>6) & MASK51;
  h[3]=(fa_ld64le(s+19)>>1) & MASK51;
  h[4]=(fa_ld64le(s+24)>>12)& MASK51;
}

// ------------------------------ group ops ---------------------------------
// R = P + precomp(Q)   (mixed add, Z2=1).  Safe for R aliasing P.
DEV void ge_madd(ge *R,const ge *P,const gepre *q){
  fe A,B,C,D,E,F,G,H;
  fe_sub(A,P->Y,P->X); fe_mul(A,A,q->ymx);
  fe_add(B,P->Y,P->X); fe_mul(B,B,q->ypx);
  fe_mul(C,P->T,q->xy2d);
  fe_add(D,P->Z,P->Z);
  fe_sub(E,B,A); fe_sub(F,D,C); fe_add(G,D,C); fe_add(H,B,A);
  fe_mul(R->X,E,F); fe_mul(R->Y,G,H); fe_mul(R->T,E,H); fe_mul(R->Z,F,G);
}

// ------------------------------- SHA-512 ----------------------------------
DEVN void fa_sha512_block(u64 H[8],const u8 block[128]){
  static const u64 K[80]={
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};
  #define RR(x,c) (((x)>>(c))|((x)<<(64-(c))))
  u64 W[16];
  for(int i=0;i<16;i++) W[i]=fa_ld64be(block+8*i);
  u64 a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
  for(int i=0;i<80;i++){
    if(i>=16){
      u64 w15=W[(i+1)&15], w2=W[(i+14)&15];
      u64 s0=RR(w15,1)^RR(w15,8)^(w15>>7);
      u64 s1=RR(w2,19)^RR(w2,61)^(w2>>6);
      W[i&15]+=s0+W[(i+9)&15]+s1;
    }
    u64 S1=RR(e,14)^RR(e,18)^RR(e,41);
    u64 ch=(e&f)^(~e&g);
    u64 T1=h+S1+ch+K[i]+W[i&15];
    u64 S0=RR(a,28)^RR(a,34)^RR(a,39);
    u64 maj=(a&b)^(a&c)^(b&c);
    u64 T2=S0+maj;
    h=g;g=f;f=e;e=d+T1;d=c;c=b;b=a;a=T1+T2;
  }
  #undef RR
  H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
}
// single-block SHA-512 for messages of length < 112 bytes
DEVN void sha512_short(u8 out[64],const u8 *msg,unsigned len){
  u64 H[8]={0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
  u8 block[128];
  for(int i=0;i<128;i++) block[i]=0;
  for(unsigned i=0;i<len;i++) block[i]=msg[i];
  block[len]=0x80;
  u64 bits=(u64)len*8;
  fa_st64be(block+120,bits);
  fa_sha512_block(H,block);
  for(int i=0;i<8;i++) fa_st64be(out+8*i,H[i]);
}

// --------------------- Ed25519 pubkey via comb table ----------------------
// comb window width in bits (4 or 8).  8 -> 32 windows (~31 mixed adds/key);
// 4 -> 64 windows (~60 adds/key).  table[i*ROWSZ + d] = precomp( d * 2^(WBITS*i) * B )
#ifndef WBITS
#define WBITS 8
#endif
#define NWIN  (256/WBITS)
#define ROWSZ (1<<WBITS)
DEVN void ed25519_pubkey_fast(u8 pk[32],const u8 seed[32],const gepre *table){
  u8 a[64];
  sha512_short(a,seed,32);
  a[0]&=248; a[31]&=127; a[31]|=64;
  ge R; fe_0(R.X); fe_1(R.Y); fe_1(R.Z); fe_0(R.T);   // identity
  #pragma unroll 1
  for(int i=0;i<NWIN;i++){
#if WBITS==8
    unsigned d=a[i];
#else
    unsigned d=(a[i>>1]>>((i&1)*4))&15;
#endif
    if(d) ge_madd(&R,&R,&table[i*ROWSZ+d]);
  }
  fe zi,x,y; fe_invert(zi,R.Z);
  fe_mul(x,R.X,zi); fe_mul(y,R.Y,zi);
  u8 xs[32];
  fe_tobytes(pk,y);
  fe_tobytes(xs,x);
  pk[31]^=(xs[0]&1)<<7;
}
