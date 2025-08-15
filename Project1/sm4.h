#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>

// SM4 常量定义
#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_ROUNDS 32

// S盒
extern const uint8_t Sm4SBox[256];

// SM4 密钥扩展函数
void Sm4KeySchedule(const uint8_t *key, uint32_t roundKeys[SM4_ROUNDS]);

// SM4 单块加密函数
void Sm4EncryptBlock(const uint8_t *inputBlock, uint8_t *outputBlock, const uint32_t roundKeys[SM4_ROUNDS]);

// SM4 单块解密函数
void Sm4DecryptBlock(const uint8_t *inputBlock, uint8_t *outputBlock, const uint32_t roundKeys[SM4_ROUNDS]);

// GCM 加密
void Sm4GcmEncrypt(const uint8_t *plaintext, size_t length, const uint8_t *key, const uint8_t *nonce, size_t nonceLen, uint8_t *ciphertext, uint8_t *tag);
// GCM 解密
void Sm4GcmDecrypt(const uint8_t *ciphertext, size_t length, const uint8_t *key, const uint8_t *nonce, size_t nonceLen, const uint8_t *tag, uint8_t *plaintext);


void Sm4InitTTable(void); 
// 轮密钥生成
void Sm4TKeySchedule(const uint8_t key[16], uint32_t rk[SM4_ROUNDS]);
// T-Table 加密
void Sm4EncryptBlockTTable(const uint8_t in[16], uint8_t out[16], const uint32_t rk[SM4_ROUNDS]);

#endif
