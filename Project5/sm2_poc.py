import random
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib
import hmac

class SM2SecurityAnalysis:
    def __init__(self, curve=ec.SECP256K1()):
        """初始化安全分析环境"""
        self.curve = curve
        self.backend = default_backend()
        self._initialize_curve_parameters()
    
    def _initialize_curve_parameters(self):
        """初始化曲线参数"""
        # 生成一个临时私钥获取阶数 n
        temp_private_key = ec.generate_private_key(self.curve, self.backend)
        numbers = temp_private_key.private_numbers().public_numbers.curve
        # SECP256K1 已知阶数
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        # 生成器 G
        self.G = self.curve.generator if hasattr(self.curve, "generator") else None

    # ======================
    # 基本签名/验证实现
    # ======================

    def _point_mul(self, k):
        """计算 k*G 的公钥点"""
        priv = ec.derive_private_key(k, self.curve, self.backend)
        pub = priv.public_key()
        return pub.public_numbers().x, pub.public_numbers().y

    def _hash_msg(self, msg):
        return hashlib.sha256(msg).digest()

    def sm2_sign(self, private_key, msg, k=None):
        """SM2签名实现"""
        if k is None:
            k = random.randint(1, self.n-1)
        e = int.from_bytes(self._hash_msg(msg), 'big')
        x1, y1 = self._point_mul(k)
        r = (e + x1) % self.n
        d = private_key.private_numbers().private_value
        s = (pow(1 + d, -1, self.n) * (k - r * d)) % self.n
        return (r, s), k

    def ecdsa_sign(self, private_key, msg, k=None):
        """ECDSA签名实现"""
        if k is None:
            k = random.randint(1, self.n-1)
        x1, y1 = self._point_mul(k)
        r = x1 % self.n
        e = int.from_bytes(self._hash_msg(msg), 'big')
        d = private_key.private_numbers().private_value
        s = (pow(k, -1, self.n) * (e + r * d)) % self.n
        return (r, s), k

    # ======================
    # 安全漏洞验证
    # ======================

    def k_leakage_attack(self, private_key, msg, k):
        """k值泄露攻击验证"""
        (r, s), _ = self.sm2_sign(private_key, msg, k)
        e = int.from_bytes(self._hash_msg(msg), 'big')
        d_sm2 = ((k - s) * pow(r + s, -1, self.n)) % self.n

        (r_ecdsa, s_ecdsa), _ = self.ecdsa_sign(private_key, msg, k)
        d_ecdsa = ((s_ecdsa * k - e) * pow(r_ecdsa, -1, self.n)) % self.n

        return {
            'real_privkey': private_key.private_numbers().private_value,
            'derived_sm2': d_sm2,
            'derived_ecdsa': d_ecdsa,
            'sm2_valid': private_key.private_numbers().private_value == d_sm2,
            'ecdsa_valid': private_key.private_numbers().private_value == d_ecdsa
        }

    def k_reuse_attack(self, private_key, msg1, msg2, k):
        """k值重用攻击验证"""
        (r1, s1), _ = self.sm2_sign(private_key, msg1, k)
        (r2, s2), _ = self.sm2_sign(private_key, msg2, k)
        numerator = (s2 - s1) % self.n
        denominator = (r1 - r2 + s1 - s2) % self.n
        d_sm2 = numerator * pow(denominator, -1, self.n) % self.n

        (r1e, s1e), _ = self.ecdsa_sign(private_key, msg1, k)
        (r2e, s2e), _ = self.ecdsa_sign(private_key, msg2, k)
        e1 = int.from_bytes(self._hash_msg(msg1), 'big')
        e2 = int.from_bytes(self._hash_msg(msg2), 'big')
        numerator_e = (s2e * e1 - s1e * e2) % self.n
        denominator_e = (s1e * r2e - s2e * r1e) % self.n
        d_ecdsa = numerator_e * pow(denominator_e, -1, self.n) % self.n

        return {
            'real_privkey': private_key.private_numbers().private_value,
            'derived_sm2': d_sm2,
            'derived_ecdsa': d_ecdsa,
            'sm2_valid': private_key.private_numbers().private_value == d_sm2,
            'ecdsa_valid': private_key.private_numbers().private_value == d_ecdsa
        }

    def multi_user_k_share_attack(self, private_keys, msgs, k):
        """多用户k值共用攻击验证"""
        results = []
        for privkey, msg in zip(private_keys, msgs):
            (r, s), _ = self.sm2_sign(privkey, msg, k)
            e = int.from_bytes(self._hash_msg(msg), 'big')
            d_derived = (k - s) * pow(r + s, -1, self.n) % self.n
            results.append({
                'user_id': id(privkey),
                'real_privkey': privkey.private_numbers().private_value,
                'derived_privkey': d_derived,
                'is_valid': privkey.private_numbers().private_value == d_derived
            })
        return results

    # ======================
    # 安全防护实现
    # ======================

    def deterministic_k(self, msg, private_key):
        """RFC 6979风格确定性k值生成"""
        d = private_key.private_numbers().private_value
        h = self._hash_msg(msg)
        v = b'\x01' * 32
        k = b'\x00' * 32
        d_bytes = d.to_bytes(32, 'big')
        k = hmac.new(k, v + b'\x00' + d_bytes + h, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        k = hmac.new(k, v + b'\x01' + d_bytes + h, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        k_num = int.from_bytes(v, 'big') % self.n
        return k_num

    def safe_sm2_sign(self, private_key, msg):
        k = self.deterministic_k(msg, private_key)
        return self.sm2_sign(private_key, msg, k)

    def safe_ecdsa_sign(self, private_key, msg):
        k = self.deterministic_k(msg, private_key)
        return self.ecdsa_sign(private_key, msg, k)

    # ======================
    # 验证工具
    # ======================

    def generate_test_cases(self, num_users=3):
        private_keys = [ec.generate_private_key(self.curve, self.backend) for _ in range(num_users)]
        msgs = [f"message_{i}".encode() for i in range(num_users)]
        fixed_k = random.randint(1, self.n-1)
        return {
            'private_keys': private_keys,
            'msgs': msgs,
            'fixed_k': fixed_k
        }


if __name__ == "__main__":
    analyzer = SM2SecurityAnalysis()

    print("="*50)
    print("SM2/ECDSA签名算法安全分析演示")
    print("="*50 + "\n")

    test_data = analyzer.generate_test_cases()
    privkey1 = test_data['private_keys'][0]
    msg1, msg2 = test_data['msgs'][0], test_data['msgs'][1]
    fixed_k = test_data['fixed_k']

    print("[1] k值泄露攻击验证:")
    leak_result = analyzer.k_leakage_attack(privkey1, msg1, fixed_k)
    print(f"真实私钥: {hex(leak_result['real_privkey'])}")
    print(f"SM2推导私钥: {hex(leak_result['derived_sm2'])} (验证: {leak_result['sm2_valid']})")
    print(f"ECDSA推导私钥: {hex(leak_result['derived_ecdsa'])} (验证: {leak_result['ecdsa_valid']})\n")

    print("[2] k值重用攻击验证:")
    reuse_result = analyzer.k_reuse_attack(privkey1, msg1, msg2, fixed_k)
    print(f"真实私钥: {hex(reuse_result['real_privkey'])}")
    print(f"SM2推导私钥: {hex(reuse_result['derived_sm2'])} (验证: {reuse_result['sm2_valid']})")
    print(f"ECDSA推导私钥: {hex(reuse_result['derived_ecdsa'])} (验证: {reuse_result['ecdsa_valid']})\n")

    print("[3] 多用户k值共用攻击验证:")
    multi_result = analyzer.multi_user_k_share_attack(test_data['private_keys'], test_data['msgs'], fixed_k)
    for res in multi_result:
        print(f"用户 {res['user_id']}:")
        print(f"  真实私钥: {hex(res['real_privkey'])}")
        print(f"  推导私钥: {hex(res['derived_privkey'])} (验证: {res['is_valid']})")
    print()

    print("[4] 安全签名实现演示:")
    safe_sig, used_k = analyzer.safe_sm2_sign(privkey1, msg1)
    print(f"使用确定性k值({used_k})生成的SM2签名: {safe_sig}")
