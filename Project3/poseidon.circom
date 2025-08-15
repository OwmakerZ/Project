pragma circom 2.0.0;

// Poseidon2 参数配置 (n=256, t=3, d=5)
template Poseidon2() {
    signal input in[3];  // 隐私输入(原象)
    signal output out;   // 公开输出(哈希值)
    
    // 使用优化的线性层和轮常数
    component poseidon = Poseidon(3, 8, 56, 5); // t=3, RF=8, RP=56, d=5
    
    // 连接输入
    for (var i = 0; i < 3; i++) {
        poseidon.inputs[i] <== in[i];
    }
    
    // 输出哈希结果
    out <== poseidon.out;
}

// 主电路用于Groth16证明
template Poseidon2Proof() {
    // 隐私输入(哈希原象)
    signal input privateInput[3];
    
    // 公开输入(声称的哈希值)
    signal input publicHash;
    
    // 计算Poseidon2哈希
    component hasher = Poseidon2();
    for (var i = 0; i < 3; i++) {
        hasher.in[i] <== privateInput[i];
    }
    
    // 验证计算的哈希与声称值一致
    publicHash === hasher.out;
}

component main {public [publicHash]} = Poseidon2Proof();