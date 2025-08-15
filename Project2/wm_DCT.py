import cv2
import numpy as np
import pywt
import matplotlib.pyplot as plt
import os
import sys
from pathlib import Path
from matplotlib.font_manager import FontProperties

# 定义文件路径
HOST_PATH = "./Pics/test.png"  # 宿主图像路径
WATERMARKED_PATH = "watermarked.jpg"  # 含水印图像保存路径
RESULTS_DIR = "./results"  # 结果目录

def set_chinese_font():
    try:
        # 尝试使用系统中存在的常见中文字体
        font = FontProperties(fname=r"C:\Windows\Fonts\simhei.ttf", size=10)  # 黑体
        plt.rcParams['font.sans-serif'] = ['SimHei']  # 设置默认字体
        plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题
        return font
    except:
        try:
            font = FontProperties(fname=r"C:\Windows\Fonts\simsun.ttc", size=10)  # 宋体
            plt.rcParams['font.sans-serif'] = ['SimSun']
            plt.rcParams['axes.unicode_minus'] = False
            return font
        except:
            # 如果找不到中文字体，使用默认字体
            plt.rcParams['font.sans-serif'] = ['Arial Unicode MS']  # Mac系统
            return FontProperties(size=10)

# 初始化中文字体
chinese_font = set_chinese_font()

def create_host_image():
    """创建512x512的测试宿主图像"""
    img = np.zeros((512, 512), dtype=np.uint8)
    cv2.putText(img, '测试图像', (50, 256), 
               cv2.FONT_HERSHEY_SIMPLEX, 1, 255, 2, cv2.LINE_AA)
    Path(HOST_PATH).parent.mkdir(exist_ok=True)
    cv2.imwrite(HOST_PATH, img)
    return img

def generate_watermark(text="test watermark", size=(128, 128)):
    """生成文字水印"""
    watermark = np.zeros(size, dtype=np.uint8)
    cv2.putText(watermark, text, (10, size[1]//2), 
               cv2.FONT_HERSHEY_SIMPLEX, 0.5, 255, 1, cv2.LINE_AA)
    return watermark

def safe_compute_psnr(orig, embedded):
    """安全的PSNR计算，自动处理尺寸差异"""
    h, w = orig.shape
    embedded = cv2.resize(embedded, (w, h))
    mse = np.mean((orig - embedded) ** 2)
    return 10 * np.log10(255**2/mse) if mse > 0 else float('inf')

def embed_watermark(host, watermark, alpha=0.1):
    """将水印嵌入宿主图像"""
    # 小波分解
    coeffs = pywt.dwt2(host, 'haar')
    LL, (LH, HL, HH) = coeffs
    
    # 调整水印尺寸
    wm_resized = cv2.resize(watermark, (LL.shape[1], LL.shape[0]))
    wm_binary = (wm_resized > 128).astype(np.float32)
    
    # 嵌入低频分量
    LL_embedded = LL + alpha * wm_binary * np.max(LL)
    
    # 重构图像
    reconstructed = pywt.idwt2((LL_embedded, (LH, HL, HH)), 'haar')
    return np.clip(reconstructed, 0, 255).astype(np.uint8)

def extract_watermark(watermarked, original, alpha=0.1):
    """从含水印图像提取水印"""
    # 宿主图像小波分解
    coeffs_orig = pywt.dwt2(original, 'haar')
    LL_orig, _ = coeffs_orig
    
    # 含水印图像小波分解
    coeffs_wm = pywt.dwt2(watermarked, 'haar')
    LL_wm, _ = coeffs_wm
    
    # 提取水印
    extracted = (LL_wm - LL_orig) / (alpha * np.max(LL_orig))
    return (np.clip(extracted, 0, 1) * 255).astype(np.uint8)



def compute_nc(original_wm, extracted_wm):
    """计算归一化相关系数"""
    # 调整尺寸
    h, w = original_wm.shape
    extracted_resized = cv2.resize(extracted_wm, (w, h))
    
    # 归一化处理
    orig_norm = original_wm.astype(np.float32) / 255.0
    extr_norm = extracted_resized.astype(np.float32) / 255.0
    
    # 计算相关系数
    numerator = np.sum(orig_norm * extr_norm)
    denominator = np.sqrt(np.sum(orig_norm**2)) * np.sqrt(np.sum(extr_norm**2))
    return numerator / denominator if denominator > 0 else 0

def apply_attacks(image):
    """应用各种攻击模拟"""
    attacks = {}
    h, w = image.shape[:2]
    
    # 旋转攻击
    M = cv2.getRotationMatrix2D((w/2, h/2), 15, 1)
    attacks['旋转'] = cv2.warpAffine(image, M, (w, h))
    
    # 平移攻击
    M = np.float32([[1, 0, 30], [0, 1, 30]])
    attacks['平移'] = cv2.warpAffine(image, M, (w, h))
    
    # 裁剪攻击
    cropped = image[h//10:h*9//10, w//10:w*9//10]
    attacks['裁剪'] = cv2.resize(cropped, (w, h))
    
    # 对比度增强
    attacks['对比度'] = np.clip(image.astype(np.float32) * 1.5, 0, 255).astype(np.uint8)
    
    # 椒盐噪声
    noise = np.random.choice([0, 255], size=image.shape, p=[0.95, 0.05])
    attacks['噪声'] = np.where(noise == 255, 255, np.where(noise == 0, 0, image))
    
    # 高斯模糊
    attacks['模糊'] = cv2.GaussianBlur(image, (5, 5), 0)
    
    # JPEG压缩
    _, enc = cv2.imencode('.jpg', image, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
    attacks['压缩'] = cv2.imdecode(enc, 0)
    
    # 缩放攻击
    scaled = cv2.resize(image, (w*4//5, h*4//5))
    attacks['缩放'] = cv2.resize(scaled, (w, h))
    
    # 亮度调整
    attacks['亮度'] = np.clip(image.astype(np.float32) + 50, 0, 255).astype(np.uint8)
    
    return attacks

def evaluate_robustness(watermarked, original, watermark):
    """评估水印鲁棒性"""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    results = {}
    
    # 应用攻击
    attacked_images = apply_attacks(watermarked)
    index = 0
    
    for attack_name, attacked_img in attacked_images.items():
        try:
            # 保存攻击后图像
            attack_path = f"{RESULTS_DIR}/{attack_name}.png"
            cv2.imwrite(attack_path, attacked_img)
            
            # 提取水印
            extracted = extract_watermark(attacked_img, original)
            extracted_path = f"{RESULTS_DIR}/{attack_name}_extracted.png"
            cv2.imwrite(extracted_path, extracted)
            
            # 计算NC值
            nc = compute_nc(watermark, extracted)
            results[attack_name] = nc
        except Exception as e:
            print(f"{attack_name}攻击处理失败: {str(e)}")
            results[attack_name] = 0
    
    # 可视化结果
    plt.figure(figsize=(15, 10))
    for i, (name, img) in enumerate(attacked_images.items(), 1):
        extracted_img = cv2.imread(f"{RESULTS_DIR}/{name}_extracted.png", 0)
        plt.subplot(3, 3, i)
        plt.imshow(extracted_img, cmap='gray')
        plt.title(f"{name}\nNC={results[name]:.4f}")
        plt.axis('off')
    
    plt.tight_layout()
    plt.savefig(f"{RESULTS_DIR}/robustness_results.png")
    plt.show()
    
    return results

def visualize_comparison(host, watermarked, watermark, extracted):
    """可视化水印效果"""
    plt.figure(figsize=(15, 10))
    
    # 原始与含水印图像对比
    plt.subplot(2, 3, 1)
    plt.imshow(host, cmap='gray')
    plt.title('原始图像')
    plt.axis('off')
    
    plt.subplot(2, 3, 2)
    plt.imshow(watermarked, cmap='gray')
    plt.title('含水印图像')
    plt.axis('off')
    
    plt.subplot(2, 3, 3)
    diff = np.abs(host.astype(float) - watermarked.astype(float))
    plt.imshow(diff * 10, cmap='hot')
    plt.title('差异图(10x放大)')
    plt.axis('off')
    
    # 水印对比
    plt.subplot(2, 3, 4)
    plt.imshow(watermark, cmap='gray')
    plt.title('原始水印')
    plt.axis('off')
    
    plt.subplot(2, 3, 5)
    plt.imshow(extracted, cmap='gray')
    plt.title('提取水印')
    plt.axis('off')
    
    plt.subplot(2, 3, 6)
    wm_diff = np.abs(watermark.astype(float) - cv2.resize(extracted, watermark.shape[::-1]).astype(float))
    plt.imshow(wm_diff, cmap='hot')
    plt.title('水印差异')
    plt.axis('off')
    
    plt.tight_layout()
    plt.savefig(f"{RESULTS_DIR}/comparison.png")
    plt.show()

def main():
    """主执行函数"""
    # 准备宿主图像
    # 宿主图像处理（自动调整尺寸为偶数）
    host_img = cv2.imread(HOST_PATH, cv2.IMREAD_GRAYSCALE) if os.path.exists(HOST_PATH) else create_host_image()
    host_img = host_img[:host_img.shape[0]//2*2, :host_img.shape[1]//2*2]  # 确保偶数尺寸
    
    # 水印处理
    watermark_img = generate_watermark()
    
    # 嵌入水印（自动尺寸匹配）
    watermarked_img = embed_watermark(host_img, watermark_img)
    watermarked_img = watermarked_img[:host_img.shape[0], :host_img.shape[1]]  # 确保同尺寸
    
    # 安全计算指标
    psnr = safe_compute_psnr(host_img, watermarked_img)
    print(f"PSNR: {psnr:.2f} dB")
    
    # 提取水印
    print("提取水印...")
    extracted_wm = extract_watermark(watermarked_img, host_img)
    
    # 评估提取质量
    nc = compute_nc(watermark_img, extracted_wm)
    print(f"NC: {nc:.4f}")
    
    # 可视化比较
    visualize_comparison(host_img, watermarked_img, watermark_img, extracted_wm)
    
    # 鲁棒性测试
    print("鲁棒性测试...")
    robustness = evaluate_robustness(watermarked_img, host_img, watermark_img)
    
    # 打印测试结果
    print("\n鲁棒性测试结果:")
    for attack, nc_value in robustness.items():
        print(f"{attack:<8}: {nc_value:.4f}")

if __name__ == "__main__":
    main()
    print(f"处理完成! 结果保存在 {RESULTS_DIR} 目录")