// SPDX-License-Identifier: GPL-3.0-or-later
// website-vanity.cu - CUDA vanity search for Freenet website contract keys.
//
//   contract_id = blake3( container_code_hash[32] || ed25519_pubkey[32] )
//
// Each GPU thread derives Ed25519 seeds, computes the public key with the
// comb-table code in ed25519_fast.cuh, hashes code||pubkey with the single-
// block BLAKE3 in blake3_64.cuh, and checks the digest against a sorted set of
// numeric ranges (one or two per wanted base58 prefix). The ranges are built
// by the fn-vanity / fn-words wrappers; this binary knows nothing about base58.
//
// The driver started life as a MeshCore vanity key generator (hex prefix on
// the raw public key) and was adapted to the Freenet contract-id derivation.
//
// Build:  nvcc -O3 -arch=sm_120 cuda/website-vanity.cu -o cuda/website-vanity-gpu
//         (or `make`; set ARCH for other GPUs)
// Run:    cuda/website-vanity-gpu <code_hex64> <ranges.bin>
//         Normally invoked through ./fn-vanity or ./fn-words.
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <csignal>
#include <cuda_runtime.h>
#include "ed25519_fast.cuh"
#include "blake3_64.cuh"

#define CUDA_CHECK(x) do{ cudaError_t e=(x); if(e!=cudaSuccess){ \
  fprintf(stderr,"CUDA error %s at %s:%d\n",cudaGetErrorString(e),__FILE__,__LINE__); exit(1);} }while(0)

// ---------------------- host: build the comb table ------------------------
// complete twisted-Edwards (a=-1) addition, both points extended.  Used only
// at init to construct the table; safe for R aliasing P and/or Q.
static void ge_add_full(ge *R,const ge *P,const ge *Q,const fe d2){
  fe A,B,C,D,E,F,G,H,t;
  fe_sub(A,P->Y,P->X); fe_sub(t,Q->Y,Q->X); fe_mul(A,A,t);
  fe_add(B,P->Y,P->X); fe_add(t,Q->Y,Q->X); fe_mul(B,B,t);
  fe_mul(C,P->T,Q->T); fe_mul(C,C,d2);
  fe_mul(D,P->Z,Q->Z); fe_add(D,D,D);
  fe_sub(E,B,A); fe_sub(F,D,C); fe_add(G,D,C); fe_add(H,B,A);
  fe_mul(R->X,E,F); fe_mul(R->Y,G,H); fe_mul(R->T,E,H); fe_mul(R->Z,F,G);
}
static void ge_precompute(gepre *pre,const ge *P,const fe d2){
  fe zi,x,y,xy;
  fe_invert(zi,P->Z);
  fe_mul(x,P->X,zi); fe_mul(y,P->Y,zi);
  fe_add(pre->ypx,y,x);
  fe_sub(pre->ymx,y,x);
  fe_mul(xy,x,y); fe_mul(pre->xy2d,xy,d2);
}
// big-endian hex string -> little-endian 32-byte array
static void behex_to_le(const char *h,u8 out[32]){
  auto hv=[](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10;
                           if(c>='A'&&c<='F')return c-'A'+10; return 0; };
  for(int i=0;i<32;i++) out[31-i]=(u8)((hv(h[2*i])<<4)|hv(h[2*i+1]));
}
static gepre* build_table(){
  // curve constants
  const char *BX="216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A";
  const char *BY="6666666666666666666666666666666666666666666666666666666666666658";
  const char *DD="52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3";
  u8 bx[32],by[32],dd[32];
  behex_to_le(BX,bx); behex_to_le(BY,by); behex_to_le(DD,dd);
  fe d,d2; fe_frombytes(d,dd); fe_add(d2,d,d);
  ge B; fe_frombytes(B.X,bx); fe_frombytes(B.Y,by); fe_1(B.Z); fe_mul(B.T,B.X,B.Y);

  gepre *tab=(gepre*)malloc(sizeof(gepre)*NWIN*ROWSZ);
  ge rowbase=B;
  for(int i=0;i<NWIN;i++){
    ge acc=rowbase;
    ge_precompute(&tab[i*ROWSZ+1],&acc,d2);
    for(int j=2;j<ROWSZ;j++){
      ge_add_full(&acc,&acc,&rowbase,d2);
      ge_precompute(&tab[i*ROWSZ+j],&acc,d2);
    }
    for(int k=0;k<WBITS;k++) ge_add_full(&rowbase,&rowbase,&rowbase,d2); // *2^WBITS
  }
  return tab;
}

// ------------------------------- kernels ----------------------------------
// Freenet website contract id = blake3(container_code_hash || ed25519_pubkey).
// The container code is constant for every site, so it is a fixed 32-byte
// prefix and only the pubkey varies: one blake3 over 64 bytes per candidate.
// cmp32: lexicographic == big-endian integer comparison over 32 bytes.
__device__ static inline int cmp32(const u8 *a,const u8 *b){
  for(int i=0;i<32;i++){ if(a[i]!=b[i]) return (int)a[i]-(int)b[i]; }
  return 0;
}
// Ranges are sorted by `lo` and MERGED to be disjoint on the host, which is
// what makes a plain binary search exhaustive: with overlapping ranges the
// "greatest lo <= id" entry can miss an enclosing range (a 6-letter word's
// range contains every 7-letter word sharing that prefix), and we would report
// a miss on a real hit.
__device__ static bool match_contract(const u8 *pub,const u8 *code,
                                      const u8 *ranges,int nranges,u8 *idOut){
  u8 buf[64];
  for(int i=0;i<32;i++) buf[i]=code[i];
  for(int i=0;i<32;i++) buf[32+i]=pub[i];
  u8 id[32]; blake3_64(id,buf);
  for(int i=0;i<32;i++) idOut[i]=id[i];

  int lo=0, hi=nranges-1, cand=-1;
  while(lo<=hi){
    int mid=(lo+hi)>>1;
    const u8 *r=ranges+(size_t)mid*64;
    if(cmp32(id,r)>=0){ cand=mid; lo=mid+1; } else hi=mid-1;
  }
  if(cand<0) return false;
  return cmp32(id,ranges+(size_t)cand*64+32)<=0;
}
__global__ void selftest_kernel(const u8 *seed,u8 *pub,const gepre *table){
  u8 p[32]; ed25519_pubkey_fast(p,seed,table);
  for(int i=0;i<32;i++) pub[i]=p[i];
}
// Hashes an arbitrary 64-byte buffer on the DEVICE so the blake3 port is
// checked against reference BLAKE3 output before any search runs.
__global__ void blake3_selftest_kernel(const u8 *in,u8 *out){
  u8 o[32]; blake3_64(o,in);
  for(int i=0;i<32;i++) out[i]=o[i];
}
// seed = SHA512(base32 || counter64)[:32]  -> standard Ed25519 pubkey
__global__ void search_kernel(const u8 *base,unsigned long long startCounter,int work,
                              const u8 *code,const u8 *ranges,int nranges,
                              int *found,u8 *outSeed,u8 *outPub,u8 *outId,const gepre *table){
  unsigned long long idx=(unsigned long long)blockIdx.x*blockDim.x+threadIdx.x;
  unsigned long long c0=startCounter+idx*(unsigned long long)work;
  u8 in[40];
  for(int i=0;i<32;i++) in[i]=base[i];
  for(int w=0;w<work;++w){
    if(*found) return;
    unsigned long long counter=c0+(unsigned long long)w;
    for(int i=0;i<8;i++) in[32+i]=(u8)(counter>>(8*i));
    u8 hh[64],seed[32],pub[32];
    sha512_short(hh,in,40);
    for(int i=0;i<32;i++) seed[i]=hh[i];
    ed25519_pubkey_fast(pub,seed,table);
    u8 id[32];
    if(match_contract(pub,code,ranges,nranges,id)){
      if(atomicCAS(found,0,1)==0)
        for(int i=0;i<32;i++){ outSeed[i]=seed[i]; outPub[i]=pub[i]; outId[i]=id[i]; }
      return;
    }
  }
}

// ------------------------------- driver -----------------------------------
static volatile sig_atomic_t g_stop=0;
static void on_sigint(int){ g_stop=1; }
static void tohex(const u8 *b,int n,char *out){
  static const char *h="0123456789abcdef";
  for(int i=0;i<n;i++){ out[2*i]=h[b[i]>>4]; out[2*i+1]=h[b[i]&15]; } out[2*n]=0;
}
static int hexval(char c){
  if(c>='0'&&c<='9') return c-'0';
  if(c>='a'&&c<='f') return c-'a'+10;
  if(c>='A'&&c<='F') return c-'A'+10;
  return -1;
}

int main(int argc,char**argv){
  if(argc<3){ fprintf(stderr,"usage: %s <code_hex64> <ranges.bin>\n",argv[0]); return 2; }
  u8 code[32];
  { const char*a=argv[1];
    if(strlen(a)!=64){ fprintf(stderr,"code must be 64 hex chars\n"); return 2; }
    for(int i=0;i<32;i++){ int h=hexval(a[2*i]),l=hexval(a[2*i+1]);
      if(h<0||l<0){ fprintf(stderr,"bad hex\n"); return 2; } code[i]=(u8)((h<<4)|l); } }
  // ranges.bin: uint32 count, then count * (32-byte lo || 32-byte hi),
  // sorted by lo and already merged to be disjoint (see match_contract).
  unsigned int nranges=0; u8 *hRanges=NULL;
  { FILE*f=fopen(argv[2],"rb");
    if(!f){ fprintf(stderr,"cannot open %s\n",argv[2]); return 2; }
    if(fread(&nranges,4,1,f)!=1||nranges==0){ fprintf(stderr,"bad ranges file\n"); return 2; }
    hRanges=(u8*)malloc((size_t)nranges*64);
    if(fread(hRanges,64,nranges,f)!=nranges){ fprintf(stderr,"short ranges file\n"); return 2; }
    fclose(f); }
  printf("ranges: %u\n",nranges);

  // Yield instead of spinning while waiting on the GPU (default is a busy-wait
  // that pegs one host core at ~100% and reads as a CPU bottleneck; it is not).
  CUDA_CHECK(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));
  int dev=0; cudaDeviceProp prop;
  CUDA_CHECK(cudaGetDeviceProperties(&prop,dev));
  printf("GPU: %s (sm_%d%d, %d SMs)\n",prop.name,prop.major,prop.minor,prop.multiProcessorCount);

  // build comb table on host, upload to device
  gepre *hTab=build_table();
  gepre *dTab; CUDA_CHECK(cudaMalloc(&dTab,sizeof(gepre)*NWIN*ROWSZ));
  CUDA_CHECK(cudaMemcpy(dTab,hTab,sizeof(gepre)*NWIN*ROWSZ,cudaMemcpyHostToDevice));

  // mandatory device self-test against known Ed25519 vectors (seed = 32 zero
  // bytes, and seed = 00 01 02 .. 1f; expected public keys from libsodium/PyNaCl)
  {
    u8 s0[32]={0}, s1[32]; for(int i=0;i<32;i++) s1[i]=(u8)i;
    const char *exp0="3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    const char *exp1="03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    u8 *dSeed,*dPub; CUDA_CHECK(cudaMalloc(&dSeed,32)); CUDA_CHECK(cudaMalloc(&dPub,32));
    char got[65]; u8 pub[32];
    CUDA_CHECK(cudaMemcpy(dSeed,s0,32,cudaMemcpyHostToDevice));
    selftest_kernel<<<1,1>>>(dSeed,dPub,dTab); CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(pub,dPub,32,cudaMemcpyDeviceToHost)); tohex(pub,32,got);
    if(strcmp(got,exp0)){ fprintf(stderr,"SELF-TEST FAILED (vec0)\n got %s\n exp %s\n",got,exp0); return 1; }
    CUDA_CHECK(cudaMemcpy(dSeed,s1,32,cudaMemcpyHostToDevice));
    selftest_kernel<<<1,1>>>(dSeed,dPub,dTab); CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(pub,dPub,32,cudaMemcpyDeviceToHost)); tohex(pub,32,got);
    if(strcmp(got,exp1)){ fprintf(stderr,"SELF-TEST FAILED (vec1)\n got %s\n exp %s\n",got,exp1); return 1; }
    cudaFree(dSeed); cudaFree(dPub);
    printf("self-test: OK (Ed25519 verified on device)\n");
  }

  // mandatory device self-test of the BLAKE3 port: website container code hash
  // || RFC 8032 test-1 public key, expected digest from the reference BLAKE3
  // implementation. Same vector as cuda/test_blake3.cpp.
  {
    const char *codeh="5c8706ce343545f33ed3fece90a800aab8115b09f9c88e5e1494c420ecdb5785";
    const char *pubh ="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const char *exp  ="932f7f36200c3f85b556c287a7636d1d74430e4ba72d53eddd33ddbaf896f4f9";
    u8 in[64];
    for(int i=0;i<32;i++){ in[i]=(u8)((hexval(codeh[2*i])<<4)|hexval(codeh[2*i+1]));
                           in[32+i]=(u8)((hexval(pubh[2*i])<<4)|hexval(pubh[2*i+1])); }
    u8 *dIn,*dOut,out[32]; char got[65];
    CUDA_CHECK(cudaMalloc(&dIn,64)); CUDA_CHECK(cudaMalloc(&dOut,32));
    CUDA_CHECK(cudaMemcpy(dIn,in,64,cudaMemcpyHostToDevice));
    blake3_selftest_kernel<<<1,1>>>(dIn,dOut); CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(out,dOut,32,cudaMemcpyDeviceToHost)); tohex(out,32,got);
    if(strcmp(got,exp)){ fprintf(stderr,"SELF-TEST FAILED (blake3)\n got %s\n exp %s\n",got,exp); return 1; }
    cudaFree(dIn); cudaFree(dOut);
    printf("self-test: OK (BLAKE3 verified on device)\n");
  }

  u8 base[32];
  { FILE*f=fopen("/dev/urandom","rb"); if(!f||fread(base,1,32,f)!=32){ fprintf(stderr,"urandom failed\n"); return 1; } fclose(f); }

  u8 *dBase,*dCode,*dRanges,*dOutId,*dOutSeed,*dOutPub; int *dFound;
  CUDA_CHECK(cudaMalloc(&dBase,32));   CUDA_CHECK(cudaMemcpy(dBase,base,32,cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMalloc(&dCode,32)); CUDA_CHECK(cudaMemcpy(dCode,code,32,cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMalloc(&dRanges,(size_t)nranges*64));
  CUDA_CHECK(cudaMemcpy(dRanges,hRanges,(size_t)nranges*64,cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMalloc(&dOutId,32));
  CUDA_CHECK(cudaMalloc(&dFound,sizeof(int)));
  CUDA_CHECK(cudaMalloc(&dOutSeed,32)); CUDA_CHECK(cudaMalloc(&dOutPub,32));
  int zero=0; CUDA_CHECK(cudaMemcpy(dFound,&zero,sizeof(int),cudaMemcpyHostToDevice));

  int threads=256, blocks=prop.multiProcessorCount*16, work=48;
  if(const char*e=getenv("VANITY_THREADS")) threads=atoi(e);
  if(const char*e=getenv("VANITY_BLOCKS"))  blocks=atoi(e);
  if(const char*e=getenv("VANITY_WORK"))    work=atoi(e);
  unsigned long long perLaunch=(unsigned long long)blocks*threads*work;
  printf("contract-key range search (blake3(code||pubkey))\n");
  printf("grid: %d blocks x %d threads x %d work = %llu keys/launch\n",blocks,threads,work,perLaunch);
  printf("searching...  (Ctrl-C to stop)\n");
  signal(SIGINT,on_sigint);

  auto t0=std::chrono::steady_clock::now(); auto tlast=t0;
  unsigned long long counter=0, tried=0, triedAtLast=0; int found=0;
  while(!found && !g_stop){
    search_kernel<<<blocks,threads>>>(dBase,counter,work,dCode,dRanges,(int)nranges,dFound,dOutSeed,dOutPub,dOutId,dTab);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());
    counter+=perLaunch; tried+=perLaunch;
    CUDA_CHECK(cudaMemcpy(&found,dFound,sizeof(int),cudaMemcpyDeviceToHost));
    auto now=std::chrono::steady_clock::now();
    double since=std::chrono::duration<double>(now-tlast).count();
    if(since>=1.0 && !found){
      double rate=(tried-triedAtLast)/since/1e6, tot=std::chrono::duration<double>(now-t0).count();
      printf("\r  %.1f Mkey/s   tried %.2e   %.0fs   ",
             rate,(double)tried,tot); fflush(stdout);
      tlast=now; triedAtLast=tried;
    }
  }
  printf("\n");

  if(found){
    u8 seed[32],pub[32]; char hseed[65],hpub[65],hfull[129];
    CUDA_CHECK(cudaMemcpy(seed,dOutSeed,32,cudaMemcpyDeviceToHost));
    u8 idb[32]; char idhex[65];
    CUDA_CHECK(cudaMemcpy(idb,dOutId,32,cudaMemcpyDeviceToHost));
    tohex(idb,32,idhex); printf("contract_id_hex = %s\n",idhex);
    CUDA_CHECK(cudaMemcpy(pub,dOutPub,32,cudaMemcpyDeviceToHost));
    // Re-check on the HOST that the id really lies in some range. The Python
    // wrappers then re-encode the id to base58 and check the prefix again.
    bool ok=false;
    for(unsigned int r=0;r<nranges&&!ok;r++){
      const u8*L=hRanges+(size_t)r*64,*H=L+32; int c=0;
      for(int i=0;i<32&&c==0;i++) c=(int)idb[i]-(int)L[i]; if(c<0) continue;
      c=0; for(int i=0;i<32&&c==0;i++) c=(int)idb[i]-(int)H[i]; if(c<=0) ok=true; }
    tohex(seed,32,hseed); tohex(pub,32,hpub);
    { u8 full[64]; memcpy(full,seed,32); memcpy(full+32,pub,32); tohex(full,64,hfull); }
    double tot=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
    printf("FOUND%s in %.1fs (%.2e tries)\n\n", ok?"":" (WARNING: OUT OF RANGE — bug!)", tot,(double)tried);
    printf("Public key (identity) : %s\n",hpub);
    printf("Private key (seed)    : %s\n",hseed);
    printf("Full key (seed+pub)   : %s\n",hfull);
  } else {
    printf("stopped without a match.\n");
  }
  free(hTab);
  cudaFree(dBase); cudaFree(dCode); cudaFree(dRanges); cudaFree(dOutId); cudaFree(dFound); cudaFree(dOutSeed); cudaFree(dOutPub); cudaFree(dTab);
  return found?0:1;
}
