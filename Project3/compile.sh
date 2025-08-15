# 安装依赖
npm install circom circomlib snarkjs

# 编译电路
circom poseidon2.circom --r1cs --wasm --sym

# 生成证明
snarkjs groth16 setup poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_final.zkey --name="First contribution"
snarkjs zkey export verificationkey poseidon2_final.zkey verification_key.json

# 生成 witness 并生成证明
node poseidon2_js/generate_witness.js poseidon2_js/poseidon2.wasm input.json witness.wtns
snarkjs groth16 prove poseidon2_final.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
