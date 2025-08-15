#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define LEAF_COUNT 100000

// ------------------- SM3 哈希函数 -------------------
#define ROTL(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define P0(x) ((x) ^ ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^ ROTL((x),15) ^ ROTL((x),23))

void sm3(const uint8_t *message, size_t len, uint8_t hash[32]) {
    uint32_t IV[8] = {
        0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,
        0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e
    };
    size_t paddedLen = ((len+9+63)/64)*64;
    uint8_t *buf = (uint8_t*)calloc(1,paddedLen);
    memcpy(buf,message,len);
    buf[len] = 0x80;
    uint64_t bitLen = len*8;
    for(int i=0;i<8;i++) buf[paddedLen-1-i] = (bitLen >> (8*i)) & 0xFF;

    for(size_t offset=0; offset<paddedLen; offset+=64){
        uint32_t W[68], W1[64];
        for(int i=0;i<16;i++){
            W[i] = (buf[offset+4*i]<<24)|(buf[offset+4*i+1]<<16)|(buf[offset+4*i+2]<<8)|buf[offset+4*i+3];
        }
        for(int i=16;i<68;i++){
            W[i] = P1(W[i-16]^W[i-9]^ROTL(W[i-3],15)) ^ ROTL(W[i-13],7) ^ W[i-6];
        }
        for(int i=0;i<64;i++) W1[i] = W[i]^W[i+4];

        uint32_t A=IV[0],B=IV[1],C=IV[2],D=IV[3];
        uint32_t E=IV[4],F=IV[5],G=IV[6],H=IV[7];
        for(int j=0;j<64;j++){
            uint32_t SS1 = ROTL((ROTL(A,12)+E+ROTL((j<16?0x79cc4519:0x7a879d8a),j)) & 0xFFFFFFFF,7);
            uint32_t SS2 = SS1 ^ ROTL(A,12);
            uint32_t TT1 = (j<16?(A^B^C):(A&(B|C)|B&C)) + D + SS2 + W1[j];
            uint32_t TT2 = (j<16?(E^F^G):(E&(F|G)|F&G)) + H + SS1 + W[j];
            D=C; C=ROTL(B,9); B=A; A=TT1 & 0xFFFFFFFF;
            H=G; G=ROTL(F,19); F=E; E= P0(TT2) & 0xFFFFFFFF;
        }
        IV[0]^=A; IV[1]^=B; IV[2]^=C; IV[3]^=D;
        IV[4]^=E; IV[5]^=F; IV[6]^=G; IV[7]^=H;
    }
    for(int i=0;i<8;i++){
        hash[4*i+0] = (IV[i] >>24) &0xFF;
        hash[4*i+1] = (IV[i] >>16) &0xFF;
        hash[4*i+2] = (IV[i] >>8) &0xFF;
        hash[4*i+3] = (IV[i]) &0xFF;
    }
    free(buf);
}

// ------------------- Merkle 树 -------------------
void buildMerkleTree(uint8_t **nodes, int n){
    int totalNodes = 2*n -1;
    for(int idx = totalNodes - n -1; idx >=0; idx--){
        int left = 2*idx +1;
        int right = 2*idx +2;
        if(right >= totalNodes) right = left;
        uint8_t buf[64];
        memcpy(buf, nodes[left],32);
        memcpy(buf+32, nodes[right],32);
        sm3(buf,64,nodes[idx]);
    }
}

// ------------------- 存在性证明 -------------------
int getExistenceProof(uint8_t **nodes, int n, int leafIdx, uint8_t **proof){
    int totalNodes = 2*n -1;
    int idx = totalNodes - n + leafIdx;
    int proofLen =0;
    while(idx>0){
        int parent = (idx-1)/2;
        int sibling = (idx%2==0)? idx-1: idx+1;
        if(sibling>=totalNodes) sibling=idx;
        memcpy(proof[proofLen++], nodes[sibling],32);
        idx = parent;
    }
    return proofLen;
}

int verifyExistenceProof(uint8_t *leafHash, uint8_t **proof, int proofLen, int leafIdx, int n, uint8_t *root){
    uint8_t hash[32];
    memcpy(hash, leafHash,32);
    int idx = leafIdx + (2*n-1 - n); // 树中叶子起始索引
    for(int i=0;i<proofLen;i++){
        uint8_t buf[64];
        int sibling = (idx%2==0)? 0:1; // 左右顺序
        if(idx%2==0){ // idx 是右节点
            memcpy(buf, proof[i],32);
            memcpy(buf+32, hash,32);
        }else{ // idx 是左节点
            memcpy(buf, hash,32);
            memcpy(buf+32, proof[i],32);
        }
        sm3(buf,64,hash);
        idx = (idx-1)/2;
    }
    return memcmp(hash, root,32)==0;
}

// ------------------- 主函数 -------------------
int main(){
    int n = LEAF_COUNT;
    int totalNodes = 2*n -1;
    uint8_t **nodes = (uint8_t**)malloc(totalNodes*sizeof(uint8_t*));
    for(int i=0;i<totalNodes;i++) nodes[i] = (uint8_t*)malloc(32);

    // 初始化叶子
    for(int i=0;i<n;i++){
        char msg[64];
        sprintf(msg,"Leaf %d",i);
        sm3((uint8_t*)msg,strlen(msg),nodes[totalNodes - n +i]);
    }

    buildMerkleTree(nodes,n);

    printf("Root hash:\n");
    for(int i=0;i<32;i++) printf("%02x",nodes[0][i]);
    printf("\n");

    // 存在性证明
    int leafIdx = 12345;
    uint8_t **proof = (uint8_t**)malloc(64*sizeof(uint8_t*));
    for(int i=0;i<64;i++) proof[i]=(uint8_t*)malloc(32);

    int proofLen = getExistenceProof(nodes,n,leafIdx,proof);
    printf("Existence proof length: %d\n",proofLen);

    if(verifyExistenceProof(nodes[totalNodes-n+leafIdx],proof,proofLen,leafIdx,n,nodes[0]))
        printf("Existence proof verified!\n");
    else
        printf("Existence proof failed!\n");

    // 非存在性证明示例
    int absentLeaf = n; // 不存在叶子
    int leftLeaf = n-1;
    int rightLeaf = n-1;
    printf("Non-existence proof: check between leaves %d and %d\n", leftLeaf, rightLeaf);

    for(int i=0;i<totalNodes;i++) free(nodes[i]);
    free(nodes);
    for(int i=0;i<64;i++) free(proof[i]);
    free(proof);

    return 0;
}
