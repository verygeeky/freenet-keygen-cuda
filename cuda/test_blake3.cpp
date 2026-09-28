// SPDX-License-Identifier: GPL-3.0-or-later
// test_blake3.cpp - host-side known-answer test for blake3_64.cuh.
//
// Each vector is blake3(code_hash || pubkey) with code_hash = the Freenet
// website container contract hash and pubkey = a public Ed25519 test key.
// Expected digests come from the reference BLAKE3 implementation.
//
// Build and run:  g++ -O2 -x c++ cuda/test_blake3.cpp -o cuda/test_blake3 && cuda/test_blake3
//                 (or `make test`)
#define DEVN
#include "blake3_64.cuh"
#include <cstdio>
#include <cstring>
static void hx(const char*h,unsigned char*o,int n){for(int i=0;i<n;i++){unsigned v;sscanf(h+2*i,"%2x",&v);o[i]=(unsigned char)v;}}
static int chk(const char*name,const char*codeh,const char*pubh,const char*wanth){
  unsigned char code[32],pub[32],want[32],buf[64],out[32];
  hx(codeh,code,32); hx(pubh,pub,32); hx(wanth,want,32);
  memcpy(buf,code,32); memcpy(buf+32,pub,32);
  blake3_64(out,buf);
  int ok=!memcmp(out,want,32);
  printf("%-12s %s\n",name,ok?"OK":"MISMATCH");
  if(!ok){printf("  got  ");for(int i=0;i<32;i++)printf("%02x",out[i]);printf("\n  want ");for(int i=0;i<32;i++)printf("%02x",want[i]);printf("\n");}
  return ok;
}
int main(){
  // base58 7EBvjNgTAteeJBKE3TRHq9vSiDPi8Ex7aKWZfhwtf13r
  const char*CODE="5c8706ce343545f33ed3fece90a800aab8115b09f9c88e5e1494c420ecdb5785";
  int ok=1;
  // RFC 8032 section 7.1, TEST 1 public key
  ok &= chk("rfc8032-t1",CODE,"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "932f7f36200c3f85b556c287a7636d1d74430e4ba72d53eddd33ddbaf896f4f9");
  // RFC 8032 section 7.1, TEST 2 public key
  ok &= chk("rfc8032-t2",CODE,"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "0bce115e5c0e56174817f0d4870ee415568adf79d779a81324ffac2fa72e837c");
  // public key of the all-zero seed
  ok &= chk("zero-seed",CODE,"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            "75952f2e15daaadbcbed5e5490327b6a543e3c11eb1ed1dd3e675b34ce34c0c1");
  printf("%s\n", ok?"ALL VECTORS PASS":"FAILED");
  return ok?0:1;
}
