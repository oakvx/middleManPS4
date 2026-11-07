/* Compact standalone SHA-256/HMAC implementation for a LAN-only challenge. */
#include "live_crypto.h"
#include <stdint.h>
#include <string.h>

static const uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct mmps4_ctx {
  uint32_t h[8];
  uint64_t bits;
  unsigned char block[64];
  size_t count;
} mmps4_ctx;

static uint32_t rr(uint32_t x, unsigned int n) { return (x >> n) | (x << (32U - n)); }
static void compress(mmps4_ctx *s, const unsigned char *buf)
{
    uint32_t w[64], a,b,c,d,e,f,g,h;
    unsigned int i;
    for (i=0;i<16;i++) {
        w[i]=((uint32_t)buf[4*i]<<24)|((uint32_t)buf[4*i+1]<<16)|
             ((uint32_t)buf[4*i+2]<<8)|((uint32_t)buf[4*i+3]);
    }
    for (i=16;i<64;i++) {
        uint32_t p=w[i-15], q=w[i-2];
        w[i]=w[i-16]+(rr(p,7)^rr(p,18)^(p>>3))+w[i-7]+
             (rr(q,17)^rr(q,19)^(q>>10));
    }
    a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];
    e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
    for (i=0;i<64;i++) {
        uint32_t t1=h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^((~e)&g))+k[i]+w[i];
        uint32_t t2=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;
    s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void init(mmps4_ctx *s)
{
    const uint32_t initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                               0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(s->h,initial,sizeof(initial));s->bits=0;s->count=0;
}
static void put(mmps4_ctx *s, const unsigned char *buf, size_t n)
{
    size_t i;
    for (i=0;i<n;i++) {
        s->block[s->count++]=buf[i];
        if (s->count==64) { compress(s,s->block);s->count=0; }
    }
    s->bits+=(uint64_t)n*8U;
}
static void finish(mmps4_ctx *s, unsigned char out[32])
{
    unsigned char pad[128],len[8];size_t padding;unsigned int i;
    uint64_t bits=s->bits;
    for (i=0;i<8;i++) len[7-i]=(unsigned char)(bits>>(8U*i));
    memset(pad,0,sizeof(pad));pad[0]=0x80;
    padding=s->count<56?56-s->count:120-s->count;
    put(s,pad,padding);put(s,len,8);
    for (i=0;i<8;i++) {
        out[4*i]=(unsigned char)(s->h[i]>>24);
        out[4*i+1]=(unsigned char)(s->h[i]>>16);
        out[4*i+2]=(unsigned char)(s->h[i]>>8);
        out[4*i+3]=(unsigned char)s->h[i];
    }
}
void mmps4_sha256(const unsigned char *data, size_t length, unsigned char out[32])
{
    mmps4_ctx s;init(&s);put(&s,data,length);finish(&s,out);
}
void mmps4_hmac_sha256(const unsigned char *key,size_t keylen,
                       const unsigned char *data,size_t len,unsigned char out[32])
{
    mmps4_ctx s;unsigned char block[64],inside[32];size_t i;
    memset(block,0,sizeof(block));
    if(keylen>64){mmps4_sha256(key,keylen,block);keylen=32;}
    else memcpy(block,key,keylen);
    for(i=0;i<64;i++)block[i]^=0x36;
    init(&s);put(&s,block,64);put(&s,data,len);finish(&s,inside);
    for(i=0;i<64;i++)block[i]^=0x36^0x5c;
    init(&s);put(&s,block,64);put(&s,inside,32);finish(&s,out);
    memset(block,0,sizeof(block));memset(inside,0,sizeof(inside));
}
static int nibble(char c)
{
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    return -1;
}
int mmps4_hex_key(const char *hex,unsigned char key[32])
{
    unsigned int i;
    if(hex==NULL||strlen(hex)!=64)return -1;
    for(i=0;i<32;i++){int h=nibble(hex[i*2]),l=nibble(hex[i*2+1]);
        if(h<0||l<0)return -1;
        key[i]=(unsigned char)((h<<4)|l);
    }
    return 0;
}
void mmps4_hex_encode(const unsigned char *source,size_t n,char *out)
{
    const char alphabet[]="0123456789abcdef";size_t i;
    for(i=0;i<n;i++){out[i*2]=alphabet[source[i]>>4];out[i*2+1]=alphabet[source[i]&15];}
    out[n*2]=0;
}
