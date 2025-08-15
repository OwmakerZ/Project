#include "sm4.h"
#include <string.h>
#include <wmmintrin.h> // AES-NI

// AES-NI 版本密钥扩展（简单映射示例）
void Sm4KeyScheduleAESNI(const uint8_t *key, uint32_t roundKeys[SM4_ROUNDS])
{
    for (int i = 0; i < SM4_ROUNDS; i++)
    {
        roundKeys[i] =
            ((uint32_t)key[i % SM4_KEY_SIZE] << 24) |
            ((uint32_t)key[(i + 1) % SM4_KEY_SIZE] << 16) |
            ((uint32_t)key[(i + 2) % SM4_KEY_SIZE] << 8) |
            ((uint32_t)key[(i + 3) % SM4_KEY_SIZE]);
    }
}

// AES-NI 加密单块
void Sm4EncryptBlockAESNI(const uint8_t *inputBlock, uint8_t *outputBlock, const uint32_t roundKeys[SM4_ROUNDS])
{
    __m128i block = _mm_loadu_si128((const __m128i *)inputBlock);

    for (int i = 0; i < SM4_ROUNDS; i++)
    {
        __m128i roundKey = _mm_set1_epi32(roundKeys[i]);
        block = _mm_aesenc_si128(block, roundKey);
    }

    _mm_storeu_si128((__m128i *)outputBlock, block);
}

// AES-NI 解密单块（逆序轮密钥）
void Sm4DecryptBlockAESNI(const uint8_t *inputBlock, uint8_t *outputBlock, const uint32_t roundKeys[SM4_ROUNDS])
{
    uint32_t reversedKeys[SM4_ROUNDS];
    for (int i = 0; i < SM4_ROUNDS; i++)
    {
        reversedKeys[i] = roundKeys[SM4_ROUNDS - 1 - i];
    }
    Sm4EncryptBlockAESNI(inputBlock, outputBlock, reversedKeys);
}
