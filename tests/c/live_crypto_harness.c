#include "live_crypto.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    unsigned char hash[32],key[32];char hex[65];
    const unsigned char text[]="The quick brown fox jumps over the lazy dog";
    mmps4_sha256((const unsigned char *)"abc",3,hash);mmps4_hex_encode(hash,32,hex);
    assert(strcmp(hex,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")==0);
    mmps4_hmac_sha256((const unsigned char *)"key",3,text,sizeof(text)-1,hash);
    mmps4_hex_encode(hash,32,hex);
    assert(strcmp(hex,"f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")==0);
    assert(mmps4_hex_key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",key)==0);
    assert(key[0]==0&&key[31]==31);
    assert(mmps4_hex_key("xyz",key)!=0);
    puts("live HMAC tests: OK");return 0;
}
