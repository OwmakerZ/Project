#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "sm4.h"

// 测试数据
static const uint8_t testKey[SM4_KEY_SIZE] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};

static const uint8_t testPlaintext[SM4_BLOCK_SIZE] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
};

#define TEST_LOOPS 1000000

// 打印块数据
void printBlock(const char* label, const uint8_t* data, size_t length)
{
    printf("%-15s: ", label);
    for (size_t i = 0; i < length; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// 时间测量
static double measureTime(void (*func)(const uint8_t*, uint8_t*, const uint32_t*), const uint8_t *input, uint8_t *output, const uint32_t *roundKeys)
{
    clock_t start = clock();
    for (int i = 0; i < TEST_LOOPS; i++)
    {
        func(input, output, roundKeys);
    }
    clock_t end = clock();
    return ((double)(end - start)) / CLOCKS_PER_SEC;
}

static void printSpeed(const char* label, double elapsedSeconds)
{
    double totalBytes = (double)(TEST_LOOPS * SM4_BLOCK_SIZE);
    double mb = totalBytes / (1024.0 * 1024.0);
    double mbps = mb / elapsedSeconds;
    printf("%-25s: %8.4f sec, %8.2f MB, %8.2f MB/s\n", label, elapsedSeconds, mb, mbps);
}

int main()
{
    uint32_t roundKeys[SM4_ROUNDS];
    uint8_t encrypted[SM4_BLOCK_SIZE];
    uint8_t decrypted[SM4_BLOCK_SIZE];

    printf("=== SM4 Basic Encryption Test ===\n");
    Sm4InitTTable();
    Sm4KeySchedule(testKey, roundKeys);
    Sm4TKeySchedule(testKey, roundKeys);
    Sm4EncryptBlock(testPlaintext, encrypted, roundKeys);
    Sm4DecryptBlock(encrypted, decrypted, roundKeys);

    printBlock("Plaintext", testPlaintext, SM4_BLOCK_SIZE);
    printBlock("Encrypted", encrypted, SM4_BLOCK_SIZE);
    printBlock("Decrypted", decrypted, SM4_BLOCK_SIZE);

    // 基础加密速度测试
    double timeBasic = measureTime(Sm4EncryptBlock, testPlaintext, encrypted, roundKeys);
    printSpeed("Basic Encryption Speed", timeBasic);

#ifdef USE_TTABLE
    printf("\n=== SM4 T-Table Optimization Test ===\n");
    extern void Sm4EncryptBlockTTable(const uint8_t*, uint8_t*, const uint32_t*);
    double timeTTable = measureTime(Sm4EncryptBlockTTable, testPlaintext, encrypted, roundKeys);
    printSpeed("T-Table Encryption Speed", timeTTable);
#endif

#ifdef USE_AESNI
    printf("\n=== SM4 AES-NI Optimization Test ===\n");
    extern void Sm4EncryptBlockAESNI(const uint8_t*, uint8_t*, const uint32_t*);
    double timeAESNI = measureTime(Sm4EncryptBlockAESNI, testPlaintext, encrypted, roundKeys);
    printSpeed("AES-NI Encryption Speed", timeAESNI);
#endif

#ifdef USE_GCM
    printf("\n=== SM4 GCM Mode Test ===\n");
    uint8_t nonce[12] = {0};
    uint8_t ciphertext[SM4_BLOCK_SIZE];
    uint8_t tag[16];
    Sm4GcmEncrypt(testPlaintext, SM4_BLOCK_SIZE, testKey, nonce, sizeof(nonce), ciphertext, tag);
    uint8_t decryptedGcm[SM4_BLOCK_SIZE];
    Sm4GcmDecrypt(ciphertext, SM4_BLOCK_SIZE, testKey, nonce, sizeof(nonce), tag, decryptedGcm);

    printBlock("GCM Ciphertext", ciphertext, SM4_BLOCK_SIZE);
    printBlock("GCM Tag", tag, 16);
    printBlock("GCM Decrypted", decryptedGcm, SM4_BLOCK_SIZE);

    int ok = memcmp(testPlaintext, decryptedGcm, SM4_BLOCK_SIZE) == 0;
    printf("%-15s: %s\n", "GCM Verification", ok ? "SUCCESS" : "FAILURE");
#endif

    return 0;
}
