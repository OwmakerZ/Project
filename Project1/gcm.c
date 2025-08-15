#include "sm4.h"
#include <string.h>
#include <stdint.h>

// 简单 GHASH 函数
static void GhashMultiply(uint8_t *X, const uint8_t *H)
{
    // 此处为简化示例，可以替换成高效 GF(2^128) 乘法
    for (int i = 0; i < 16; i++)
    {
        X[i] ^= H[i];
    }
}

// 生成初始向量
static void GenerateInitialVector(const uint8_t *nonce, size_t nonceLen, uint8_t *iv)
{
    if (nonceLen == 12)
    {
        memcpy(iv, nonce, 12);
        iv[12] = 0x00;
        iv[13] = 0x00;
        iv[14] = 0x00;
        iv[15] = 0x01;
    }
    else
    {
        memset(iv, 0, 16);
    }
}

// GCM 加密
void Sm4GcmEncrypt(const uint8_t *plaintext, size_t length, const uint8_t *key, const uint8_t *nonce, size_t nonceLen, uint8_t *ciphertext, uint8_t *tag)
{
    uint32_t roundKeys[SM4_ROUNDS];
    Sm4KeySchedule(key, roundKeys);

    uint8_t iv[16];
    GenerateInitialVector(nonce, nonceLen, iv);

    uint8_t counter[16];
    memcpy(counter, iv, 16);

    uint8_t H[16] = {0};
    uint8_t tmp[16];

    Sm4EncryptBlock(H, H, roundKeys);

    for (size_t i = 0; i < length; i += 16)
    {
        size_t blockSize = (length - i >= 16) ? 16 : (length - i);
        memcpy(tmp, counter, 16);
        Sm4EncryptBlock(tmp, tmp, roundKeys);
        for (size_t j = 0; j < blockSize; j++)
        {
            ciphertext[i + j] = plaintext[i + j] ^ tmp[j];
        }
        counter[15]++;
        GhashMultiply(H, &ciphertext[i]);
    }

    memcpy(tag, H, 16);
}

// GCM 解密
void Sm4GcmDecrypt(const uint8_t *ciphertext, size_t length, const uint8_t *key, const uint8_t *nonce, size_t nonceLen, const uint8_t *tag, uint8_t *plaintext)
{
    uint32_t roundKeys[SM4_ROUNDS];
    Sm4KeySchedule(key, roundKeys);

    uint8_t iv[16];
    GenerateInitialVector(nonce, nonceLen, iv);

    uint8_t counter[16];
    memcpy(counter, iv, 16);

    uint8_t H[16] = {0};
    uint8_t tmp[16];

    Sm4EncryptBlock(H, H, roundKeys);

    for (size_t i = 0; i < length; i += 16)
    {
        size_t blockSize = (length - i >= 16) ? 16 : (length - i);
        memcpy(tmp, counter, 16);
        Sm4EncryptBlock(tmp, tmp, roundKeys);
        for (size_t j = 0; j < blockSize; j++)
        {
            plaintext[i + j] = ciphertext[i + j] ^ tmp[j];
        }
        counter[15]++;
        GhashMultiply(H, &ciphertext[i]);
    }
}
