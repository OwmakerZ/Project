import random
import hashlib
from typing import List, Tuple, Set, Dict

# ------------------------------
# 彩色打印辅助
# ------------------------------

class Colors:
    RESET="\033[0m"; GREEN="\033[92m"; BLUE="\033[94m"; YELLOW="\033[93m"; RED="\033[91m"; BOLD="\033[1m"

def info(msg): print(f"{Colors.BLUE}[INFO]{Colors.RESET} {msg}")
def success(msg): print(f"{Colors.GREEN}[SUCCESS]{Colors.RESET} {msg}")

# ------------------------------
# 群操作和哈希
# ------------------------------

def hash_to_int(x: str, p: int) -> int:
    """哈希到群元素"""
    return int.from_bytes(hashlib.sha256(x.encode()).digest(), 'big') % p

def modexp(base: int, exp: int, p: int) -> int:
    return pow(base, exp, p)

def gen_private_key(p: int) -> int:
    return random.randint(1, p-2)

# ------------------------------
# 简单加法同态加密
# ------------------------------

def generate_he_keypair():
    sk = random.randint(10**5, 10**6)
    pk = sk*3 + 1
    return pk, sk

def he_encrypt(m: int, pk: int) -> int:
    noise = random.randint(1,50)
    return (m*pk + noise) % 10**12

def he_decrypt(c: int, pk: int, sk: int) -> int:
    return (c // pk) % 10**8

def he_add(c1: int, c2: int) -> int:
    return (c1+c2) % 10**12

# ------------------------------
# 参与方1
# ------------------------------

def party1_round1(set_v: Set[str], k1: int, p: int) -> List[int]:
    """第一轮：哈希+指数运算+打乱"""
    vals = [modexp(hash_to_int(v,p), k1, p) for v in set_v]
    random.shuffle(vals)
    info(f"Party1 Round1: 发送值样例 {vals[:3]} ...")
    return vals

def party1_round3(received_from_p2: List[Tuple[int,int]], k1: int, set_v_hashed: Set[int]) -> int:
    """第三轮：计算交集 + 同态加密求和"""
    encrypted_sum = 0
    for h_k2, c in received_from_p2:
        h_k1k2 = modexp(h_k2, k1, p)
        if h_k1k2 in set_v_hashed:
            encrypted_sum = c if encrypted_sum==0 else he_add(encrypted_sum, c)
    success(f"Party1 Round3: 加密交集和 {encrypted_sum}")
    return encrypted_sum

# ------------------------------
# 参与方2
# ------------------------------

def party2_round2(p1_vals: List[int], pairs_wt: List[Tuple[str,int]], k2: int, p: int, pk: int) -> List[Tuple[int,int]]:
    """第二轮：哈希+指数运算+加密+打乱"""
    # 对p1_vals指数运算
    z_vals = [modexp(v, k2, p) for v in p1_vals]
    random.shuffle(z_vals)
    
    # 对自己的集合处理
    result = []
    for w, t in pairs_wt:
        h_w = hash_to_int(w, p)
        h_k2 = modexp(h_w, k2, p)
        c_t = he_encrypt(t, pk)
        result.append((h_k2, c_t))
    random.shuffle(result)
    info(f"Party2 Round2: 发送值样例 {result[:3]} ...")
    return result

# ------------------------------
import random
import hashlib
from tabulate import tabulate

# ------------------------------
# 群操作和哈希
# ------------------------------

def hash_to_int(x: str, p: int) -> int:
    """哈希到群元素"""
    return int.from_bytes(hashlib.sha256(x.encode()).digest(), 'big') % p

def modexp(base: int, exp: int, p: int) -> int:
    return pow(base, exp, p)

def gen_private_key(p: int) -> int:
    return random.randint(1, p-2)

# ------------------------------
# 简单加法同态加密
# ------------------------------

def generate_he_keypair():
    sk = random.randint(10**5, 10**6)
    pk = sk*3 + 1
    return pk, sk

def he_encrypt(m: int, pk: int) -> int:
    noise = random.randint(1,50)
    return (m*pk + noise) % 10**12

def he_decrypt(c: int, pk: int, sk: int) -> int:
    return (c // pk) % 10**8

def he_add(c1: int, c2: int) -> int:
    return (c1 + c2) % 10**12

# ------------------------------
# DDH-based Private Intersection-Sum Protocol
# ------------------------------

def ddh_intersection_sum_table(set_v, pairs_wt, p):
    print("\n===== 协议初始化 =====")
    print(f"Party1输入集合 V = {set_v}")
    print(f"Party2输入集合 W = {pairs_wt}")
    
    k1 = gen_private_key(p)
    k2 = gen_private_key(p)
    print(f"Party1私钥 k1 = {k1}")
    print(f"Party2私钥 k2 = {k2}")
    
    pk, sk = generate_he_keypair()
    print(f"Party2生成同态加密密钥对 (pk={pk}, sk={sk})")

    # ------------------------------
    # Round1(P1)
    # ------------------------------
    print("\n===== Round1: Party1 =====")
    round1_table = []
    h_vi_k1_list = []
    for vi in set_v:
        h_vi = hash_to_int(vi, p)
        h_vi_k1 = modexp(h_vi, k1, p)
        h_vi_k1_list.append(h_vi_k1)
        round1_table.append([vi, h_vi, h_vi_k1])
    random.shuffle(h_vi_k1_list)
    print(tabulate(round1_table, headers=["元素 vi", "H(vi)", "H(vi)^k1"]))
    print(f"Party1发送给Party2（打乱顺序）: {h_vi_k1_list}")

    # ------------------------------
    # Round2(P2)
    # ------------------------------
    print("\n===== Round2: Party2 =====")
    round2_table_z = []
    Z_list = []
    for h in h_vi_k1_list:
        h_k1k2 = modexp(h, k2, p)
        Z_list.append(h_k1k2)
        round2_table_z.append([h, h_k1k2])
    random.shuffle(Z_list)
    print("P1值再次指数计算 (H(vi)^k1)^k2")
    print(tabulate(round2_table_z, headers=["H(vi)^k1", "H(vi)^k1^k2"]))
    print(f"Party2发送Z给Party1（打乱顺序）: {Z_list}")

    # Step2.3: 对P2自己的集合处理
    round2_table_w = []
    w_list = []
    for wj, tj in pairs_wt:
        h_wj = hash_to_int(wj, p)
        h_wj_k2 = modexp(h_wj, k2, p)
        c_tj = he_encrypt(tj, pk)
        w_list.append((h_wj_k2, c_tj))
        round2_table_w.append([wj, tj, h_wj, h_wj_k2, c_tj])
    random.shuffle(w_list)
    print("Party2对自己的集合处理（哈希+指数+加密）")
    print(tabulate(round2_table_w, headers=["元素 wj", "值 tj", "H(wj)", "H(wj)^k2", "AEnc(tj)"]))
    print(f"Party2发送加密后的集合给Party1（打乱顺序）: {w_list}")

    # ------------------------------
    # Round3(P1)
    # ------------------------------
    print("\n===== Round3: Party1 =====")
    set_v_hashed = {modexp(hash_to_int(v, p), k1, p) for v in set_v}
    round3_table = []
    intersection_indices = []
    encrypted_sum = 0
    for idx, (h_wj_k2, c_tj) in enumerate(w_list):
        h_wj_k1k2 = modexp(h_wj_k2, k1, p)
        in_intersection = h_wj_k1k2 in set_v_hashed
        if in_intersection:
            intersection_indices.append(idx)
            encrypted_sum = c_tj if encrypted_sum == 0 else he_add(encrypted_sum, c_tj)
        round3_table.append([idx, h_wj_k2, h_wj_k1k2, c_tj, in_intersection, encrypted_sum])
    print(tabulate(round3_table, headers=["索引", "H(wj)^k2", "(H(wj)^k2)^k1", "AEnc(tj)", "是否交集", "累加同态加密"]))
    print(f"交集索引: {intersection_indices}")
    print(f"交集加密和: {encrypted_sum}")

    # ------------------------------
    # Party2解密
    # ------------------------------
    intersection_sum = he_decrypt(encrypted_sum, pk, sk)
    print("\n===== 输出 =====")
    print(f"Party2解密得到交集和: {intersection_sum}")
    return intersection_sum

# ------------------------------
# 示例运行
# ------------------------------
if __name__=="__main__":
    p = 2147483647  # 大素数
    set_v = {"alice","bob","carol"}
    pairs_wt = [("alice",10), ("dave",20), ("carol",30)]
    ddh_intersection_sum_table(set_v, pairs_wt, p)
