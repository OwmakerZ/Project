#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <immintrin.h> // 包含 AVX 指令集头文件

#define SM3_BLOCK_SIZE 64
#define SM3_HASH_SIZE 32

typedef uint8_t BYTE;
typedef uint32_t WORD;

#define ROTL(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define P0(x) ((x) ^ ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^ ROTL((x),15) ^ ROTL((x),23))
#define FF(x,y,z,j) ((j) <= 15 ? ((x) ^ (y) ^ (z)) : (((x)&(y)) | ((x)&(z)) | ((y)&(z))))
#define GG(x,y,z,j) ((j) <= 15 ? ((x) ^ (y) ^ (z)) : (((x)&(y)) | ((~(x))&(z))))

static const WORD T[64] = {
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a
};

// 消息扩展
void messageExpand(const BYTE* block, WORD W[68], WORD W1[64]) {
    for (int i = 0; i < 16; i++) {
        W[i] = (block[i*4]<<24) | (block[i*4+1]<<16) | (block[i*4+2]<<8) | block[i*4+3];
    }
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i-16] ^ W[i-9] ^ ROTL(W[i-3],15)) ^ ROTL(W[i-13],7) ^ W[i-6];
    }
    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i+4];
    }
}

// 压缩函数
void compressBlock(WORD V[8], const BYTE* block) {
    WORD W[68], W1[64];
    messageExpand(block, W, W1);

    WORD A=V[0],B=V[1],C=V[2],D=V[3];
    WORD E=V[4],F=V[5],G=V[6],H=V[7];

    for(int j=0;j<64;j++){
        WORD SS1 = ROTL((ROTL(A,12)+E+ROTL(T[j],j)),7);
        WORD SS2 = SS1 ^ ROTL(A,12);
        WORD TT1 = FF(A,B,C,j)+D+SS2+W1[j];
        WORD TT2 = GG(E,F,G,j)+H+SS1+W[j];
        D = C;
        C = ROTL(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F,19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// 消息填充
BYTE* padMessage(const BYTE* msg, size_t msgLen, size_t* newLen) {
    uint64_t bitLen = msgLen*8;
    size_t k = (56 - (msgLen+1)%64)%64;
    *newLen = msgLen + 1 + k + 8;
    BYTE* padded = (BYTE*)calloc(*newLen,1);
    memcpy(padded,msg,msgLen);
    padded[msgLen] = 0x80;
    for(int i=0;i<8;i++){
        padded[*newLen-8+i] = (BYTE)((bitLen >> (56-8*i)) & 0xFF);
    }
    return padded;
}

// SM3 哈希函数
void sm3Hash(const BYTE* msg, size_t msgLen, BYTE digest[SM3_HASH_SIZE]) {
    WORD V[8] = {0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
                 0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E};

    size_t newLen;
    BYTE* padded = padMessage(msg,msgLen,&newLen);

    for(size_t i=0;i<newLen;i+=SM3_BLOCK_SIZE){
        compressBlock(V,padded+i);
    }
    free(padded);

    for(int i=0;i<8;i++){
        digest[i*4] = (BYTE)(V[i]>>24);
        digest[i*4+1] = (BYTE)(V[i]>>16);
        digest[i*4+2] = (BYTE)(V[i]>>8);
        digest[i*4+3] = (BYTE)V[i];
    }
}

// 吞吐量测试
void throughputTest() {
    const size_t testSize = 16*1024*1024; // 16 MB
    BYTE* data = (BYTE*)malloc(testSize);
    memset(data,0x61,testSize);
    BYTE digest[SM3_HASH_SIZE];

    clock_t start = clock();
    sm3Hash(data,testSize,digest);
    clock_t end = clock();

    double seconds = (double)(end-start)/CLOCKS_PER_SEC;
    printf("Processed 16MB in %.3f seconds, throughput %.2f MB/s\n",seconds,testSize/1024.0/1024.0/seconds);

    free(data);
}

void printDigest(BYTE digest[SM3_HASH_SIZE]){
    for(int i=0;i<SM3_HASH_SIZE;i++)
        printf("%02x",digest[i]);
    printf("\n");
}

int main() {
    const char* msg = "abc";
    BYTE digest[SM3_HASH_SIZE];
    sm3Hash((BYTE*)msg,strlen(msg),digest);
    printf("SM3(\"%s\") = ",msg);
    printDigest(digest);

    throughputTest();
    return 0;
}
