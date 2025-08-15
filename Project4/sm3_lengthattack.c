#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// ---------------- SM3 基础实现 ----------------
typedef struct {
    uint32_t h[8];
    uint8_t buffer[64];
    uint64_t length;
} SM3_CTX;

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define P0(x) ((x) ^ ROTL32((x),9) ^ ROTL32((x),17))
#define P1(x) ((x) ^ ROTL32((x),15) ^ ROTL32((x),23))

uint32_t T_j(int j) { return (j<16) ? 0x79cc4519 : 0x7a879d8a; }

void SM3Compress(SM3_CTX *ctx, const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    for(int i=0;i<16;i++)
        W[i] = (block[i*4]<<24)|(block[i*4+1]<<16)|(block[i*4+2]<<8)|block[i*4+3];
    for(int i=16;i<68;i++)
        W[i] = P1(W[i-16]^W[i-9]^ROTL32(W[i-3],15))^ROTL32(W[i-13],7)^W[i-6];
    for(int i=0;i<64;i++)
        W1[i] = W[i]^W[i+4];

    uint32_t A=ctx->h[0],B=ctx->h[1],C=ctx->h[2],D=ctx->h[3];
    uint32_t E=ctx->h[4],F=ctx->h[5],G=ctx->h[6],H=ctx->h[7];

    for(int j=0;j<64;j++){
        uint32_t SS1 = ROTL32((ROTL32(A,12)+E+ROTL32(T_j(j),j))&0xFFFFFFFF,7);
        uint32_t SS2 = SS1 ^ ROTL32(A,12);
        uint32_t TT1,TT2;
        if(j<16)
            TT1 = (A^B^C)+D+SS2+W1[j];
        else
            TT1 = ((A&B)|(A&C)|(B&C))+D+SS2+W1[j];
        if(j<16)
            TT2 = (E^F^G)+H+SS1+W[j];
        else
            TT2 = ((E&F)|((~E)&G))+H+SS1+W[j];

        D=C; C=ROTL32(B,9); B=A; A=TT1;
        H=G; G=ROTL32(F,19); F=E; E=TT2;
    }

    ctx->h[0]^=A; ctx->h[1]^=B; ctx->h[2]^=C; ctx->h[3]^=D;
    ctx->h[4]^=E; ctx->h[5]^=F; ctx->h[6]^=G; ctx->h[7]^=H;
}

void SM3Init(SM3_CTX *ctx){
    ctx->h[0]=0x7380166f; ctx->h[1]=0x4914b2b9; ctx->h[2]=0x172442d7; ctx->h[3]=0xda8a0600;
    ctx->h[4]=0xa96f30bc; ctx->h[5]=0x163138aa; ctx->h[6]=0xe38dee4d; ctx->h[7]=0xb0fb0e4e;
    ctx->length=0;
}

void SM3Update(SM3_CTX *ctx, const uint8_t *data, size_t len){
    size_t fill = ctx->length % 64;
    ctx->length += len;
    size_t i=0;
    if(fill>0){
        size_t n = 64-fill;
        if(len<n) n=len;
        memcpy(ctx->buffer+fill,data,n);
        fill+=n;
        if(fill==64){ SM3Compress(ctx,ctx->buffer); fill=0; }
        i=n;
    }
    for(; i+64<=len; i+=64)
        SM3Compress(ctx,data+i);
    if(i<len)
        memcpy(ctx->buffer,data+i,len-i);
}

void SM3Final(SM3_CTX *ctx, uint8_t digest[32]){
    uint8_t msgLen[8];
    uint64_t bitLen = ctx->length*8;
    for(int i=0;i<8;i++)
        msgLen[7-i] = bitLen >> (i*8);

    size_t fill = ctx->length % 64;
    ctx->buffer[fill++] = 0x80;
    if(fill>56){
        memset(ctx->buffer+fill,0,64-fill);
        SM3Compress(ctx,ctx->buffer);
        fill=0;
    }
    memset(ctx->buffer+fill,0,56-fill);
    memcpy(ctx->buffer+56,msgLen,8);
    SM3Compress(ctx,ctx->buffer);

    for(int i=0;i<8;i++){
        digest[i*4] = ctx->h[i]>>24;
        digest[i*4+1] = ctx->h[i]>>16;
        digest[i*4+2] = ctx->h[i]>>8;
        digest[i*4+3] = ctx->h[i];
    }
}

// ----------------- 长度扩展攻击 -----------------
void printHex(uint8_t *buf, size_t len){
    for(size_t i=0;i<len;i++) printf("%02x",buf[i]);
    printf("\n");
}

// 生成 padding
size_t sm3Padding(uint64_t origBitLen, uint8_t *padding){
    size_t padLen = 64 - ((origBitLen/8+8+1)%64);
    if(padLen<0) padLen+=64;
    size_t total = padLen+1+8;
    padding[0]=0x80;
    memset(padding+1,0,padLen);
    for(int i=0;i<8;i++)
        padding[1+padLen+i] = (origBitLen >> ((7-i)*8)) &0xFF;
    return total;
}

// 利用原始 hash 构造伪造 hash
void sm3LengthExtension(uint8_t origDigest[32], uint64_t origLen, const uint8_t *append, size_t appendLen, uint8_t outHash[32]){
    SM3_CTX ctx;
    for(int i=0;i<8;i++)
        ctx.h[i] = (origDigest[i*4]<<24)|(origDigest[i*4+1]<<16)|(origDigest[i*4+2]<<8)|origDigest[i*4+3];
    ctx.length = origLen; // 这里是原始消息填充后的长度

    SM3Update(&ctx, append, appendLen);
    SM3Final(&ctx,outHash);
}

// ---------------- 测试 -----------------
int main(){
    const char *orig = "original";
    const char *append = "append";
    uint8_t hashOrig[32];
    uint8_t hashForged[32];

    // 原始 hash
    SM3_CTX ctx;
    SM3Init(&ctx);
    SM3Update(&ctx,(uint8_t*)orig,strlen(orig));
    SM3Final(&ctx,hashOrig);

    // 构造 padding 长度
    uint8_t padding[64];
    size_t padLen = sm3Padding(strlen(orig)*8, padding);
    uint64_t forgedLen = strlen(orig)+padLen; // 伪造初始长度

    // 伪造 hash
    sm3LengthExtension(hashOrig,forgedLen, (uint8_t*)append, strlen(append), hashForged);

    printf("Original SM3(\"%s\") = ", orig);
    printHex(hashOrig,32);

    printf("Forged SM3 with appended data = ");
    printHex(hashForged,32);

    // 验证直接计算 hash
    uint8_t direct[32];
    SM3Init(&ctx);
    SM3Update(&ctx,(uint8_t*)orig,strlen(orig));
    SM3Update(&ctx,padding,padLen);
    SM3Update(&ctx,(uint8_t*)append,strlen(append));
    SM3Final(&ctx,direct);
    printf("Direct SM3(\"original||padding||append\") = ");
    printHex(direct,32);

    return 0;
}
