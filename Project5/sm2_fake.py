import secrets
import binascii
from gmssl import sm3, func

# ------------------------------
# SM2椭圆曲线参数
# ------------------------------
EllipticCurveA = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
EllipticCurveB = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
PrimeModulus = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
OrderN = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
BasePointX = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
BasePointY = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
BasePoint = (BasePointX, BasePointY)

ModularInverseCache = {}
PointAdditionCache = {}

# ------------------------------
# 椭圆曲线基础运算
# ------------------------------
def ModularInverse(value, modulus):
    cacheKey = (value, modulus)
    if cacheKey in ModularInverseCache:
        return ModularInverseCache[cacheKey]

    if value == 0: return 0
    lm, hm = 1, 0
    low, high = value % modulus, modulus
    while low > 1:
        ratio = high // low
        nextM, nextH = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nextM, nextH, lm, low
    result = lm % modulus
    ModularInverseCache[cacheKey] = result
    return result

def Sm2PointAddition(pt1, pt2):
    cacheKey = (pt1, pt2)
    if cacheKey in PointAdditionCache:
        return PointAdditionCache[cacheKey]
    if pt1 == (0, 0): return pt2
    if pt2 == (0, 0): return pt1
    x1, y1 = pt1
    x2, y2 = pt2
    if x1 == x2:
        if y1 == y2:
            slope = (3 * x1 * x1 + EllipticCurveA) * ModularInverse(2 * y1, PrimeModulus)
        else:
            return (0, 0)
    else:
        slope = (y2 - y1) * ModularInverse(x2 - x1, PrimeModulus)
    slope %= PrimeModulus
    x3 = (slope * slope - x1 - x2) % PrimeModulus
    y3 = (slope * (x1 - x3) - y1) % PrimeModulus
    result = (x3, y3)
    PointAdditionCache[cacheKey] = result
    return result

def Sm2ScalarMultiplication(scalar, point):
    result = (0, 0)
    currentPoint = point
    while scalar:
        if scalar & 1:
            result = Sm2PointAddition(result, currentPoint)
        currentPoint = Sm2PointAddition(currentPoint, currentPoint)
        scalar >>= 1
    return result

# ------------------------------
# 用户哈希（ZA）计算
# ------------------------------
def ComputeUserHash(userId, publicKeyX, publicKeyY):
    idBitLen = len(userId.encode('utf-8')) * 8
    components = [
        idBitLen.to_bytes(2, 'big'),
        userId.encode('utf-8'),
        EllipticCurveA.to_bytes(32, 'big'),
        EllipticCurveB.to_bytes(32, 'big'),
        BasePointX.to_bytes(32, 'big'),
        BasePointY.to_bytes(32, 'big'),
        publicKeyX.to_bytes(32, 'big'),
        publicKeyY.to_bytes(32, 'big')
    ]
    dataToHash = b''.join(components)
    return sm3.sm3_hash(func.bytes_to_list(dataToHash))

# ------------------------------
# 密钥生成、签名与验证
# ------------------------------
def GenerateKeypair():
    privateKey = secrets.randbelow(OrderN - 1) + 1
    publicKey = Sm2ScalarMultiplication(privateKey, BasePoint)
    return privateKey, publicKey

def SignWithSm2(privateKey, message, userId, publicKey):
    zaBytes = bytes.fromhex(ComputeUserHash(userId, publicKey[0], publicKey[1]))
    dataForHash = zaBytes + message.encode('utf-8')
    hashResult = sm3.sm3_hash(func.bytes_to_list(dataForHash))
    eVal = int(hashResult, 16)

    while True:
        kVal = secrets.randbelow(OrderN - 1) + 1
        rPoint = Sm2ScalarMultiplication(kVal, BasePoint)
        xR = rPoint[0]
        rVal = (eVal + xR) % OrderN
        if rVal == 0 or rVal + kVal == OrderN:
            continue
        
        invVal = ModularInverse(1 + privateKey, OrderN)
        sVal = (invVal * (kVal - rVal * privateKey)) % OrderN
        if sVal != 0:
            return (rVal, sVal)

def VerifySm2Signature(publicKey, message, userId, signature):
    rVal, sVal = signature
    if not (0 < rVal < OrderN and 0 < sVal < OrderN):
        return False
    
    zaBytes = bytes.fromhex(ComputeUserHash(userId, publicKey[0], publicKey[1]))
    dataForHash = zaBytes + message.encode('utf-8')
    hashResult = sm3.sm3_hash(func.bytes_to_list(dataForHash))
    eVal = int(hashResult, 16)
    
    t = (rVal + sVal) % OrderN
    if t == 0:
        return False
        
    sg = Sm2ScalarMultiplication(sVal, BasePoint)
    tp = Sm2ScalarMultiplication(t, publicKey)
    
    xRPrimePoint = Sm2PointAddition(sg, tp)
    xRPrime = xRPrimePoint[0]
    
    rPrime = (eVal + xRPrime) % OrderN
    return rPrime == rVal

# ------------------------------
# 主程序
# ------------------------------
if __name__ == "__main__":
    print("--- 伪造中本聪的SM2签名 ---")
    
    privateKey, publicKey = GenerateKeypair()
    message = "I am Satoshi Nakamoto and I have generated this SM2 signature."
    userId = "SatoshiNakamoto"
    
    print(f"生成的私钥 (dA): {hex(privateKey)}")
    print(f"生成的公钥 (PA): ({hex(publicKey[0])}, {hex(publicKey[1])})")
    
    signature = SignWithSm2(privateKey, message, userId, publicKey)
    r, s = signature
    
    print("\n--- 签名结果 ---")
    print(f"消息: \"{message}\"")
    print(f"SM2 签名 (r): {hex(r)}")
    print(f"SM2 签名 (s): {hex(s)}")
    
    isValid = VerifySm2Signature(publicKey, message, userId, signature)
    print(f"\n--- 签名验证 ---")
    print(f"使用公钥验证签名: {isValid}")
