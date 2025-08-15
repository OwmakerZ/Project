import hashlib
import random
from math import ceil

# ======================
# 辅助函数
# ======================

def inverse_mod(k, p):
    """计算 k 在模 p 下的逆元"""
    if k == 0:
        raise ZeroDivisionError('division by zero')
    return pow(k, -1, p)

def hash_msg(msg):
    """SHA256 哈希"""
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big')

# ======================
# SM2 参数（国密推荐的256位椭圆曲线）
# ======================

p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5AEF0D3
gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

G = (gx, gy)

# ======================
# 椭圆曲线运算
# ======================

def is_on_curve(P):
    if P is None:
        return True
    x, y = P
    return (y*y - (x*x*x + a*x + b)) % p == 0

def point_add(P, Q):
    """椭圆曲线点加法"""
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    if P == Q:
        lam = (3*x1*x1 + a) * inverse_mod(2*y1, p) % p
    else:
        lam = (y2 - y1) * inverse_mod(x2 - x1, p) % p
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(k, P):
    """椭圆曲线点乘 k*P"""
    R = None
    addend = P
    while k:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R

# ======================
# SM2 密钥生成
# ======================

def generate_keypair():
    d = random.randint(1, n-1)
    P = point_mul(d, G)
    return d, P

# ======================
# SM2 签名/验签
# ======================

def sm2_sign(msg, d, k=None):
    e = hash_msg(msg) % n
    if k is None:
        k = random.randint(1, n-1)
    x1, y1 = point_mul(k, G)
    r = (e + x1) % n
    if r == 0 or r + k == n:
        return sm2_sign(msg, d)
    s = (inverse_mod(1+d, n)*(k - r*d)) % n
    if s == 0:
        return sm2_sign(msg, d)
    return (r, s), k

def sm2_verify(msg, sig, P):
    r, s = sig
    e = hash_msg(msg) % n
    t = (r + s) % n
    if t == 0:
        return False
    x1, y1 = point_add(point_mul(s, G), point_mul(t, P))
    return r == (e + x1) % n

# ======================
# 演示
# ======================

if __name__ == "__main__":
    # 生成密钥
    d, P = generate_keypair()
    print("私钥 d:", hex(d))
    print("公钥 P:", (hex(P[0]), hex(P[1])))

    # 签名
    msg = b"Hello SM2"
    sig, k = sm2_sign(msg, d)
    print("签名:", sig)
    print("随机 k:", k)

    # 验签
    valid = sm2_verify(msg, sig, P)
    print("验签结果:", valid)
