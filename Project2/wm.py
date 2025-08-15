from PIL import Image, ImageDraw, ImageFont, ImageEnhance
import numpy as np
import sys
import matplotlib.pyplot as plt

def embedTextWatermarkLSB(imagePath, text, fontSize=50):
    img = Image.open(imagePath).convert("RGB")
    wm = Image.new("1", img.size, 0)
    draw = ImageDraw.Draw(wm)
    try:
        font = ImageFont.truetype("arial.ttf", fontSize)
    except:
        font = ImageFont.load_default()
    draw.text((10, 10), text, fill=1, font=font)
    wmData = np.array(wm)
    imgData = np.array(img)
    for c in range(3):
        imgData[:, :, c] = (imgData[:, :, c] & 0xFE) | wmData
    return Image.fromarray(imgData), wm

def extractWatermarkLSB(watermarkedImage):
    img = watermarkedImage.convert("RGB")
    imgData = np.array(img)
    wmData = imgData[:, :, 0] & 1
    wmData = (wmData * 255).astype(np.uint8)
    return Image.fromarray(wmData, mode="L")

def calcNCC(wm1, wm2):
    arr1 = np.array(wm1, dtype=np.float32)
    arr2 = np.array(wm2, dtype=np.float32)
    numerator = np.sum((arr1 - arr1.mean()) * (arr2 - arr2.mean()))
    denominator = np.sqrt(np.sum((arr1 - arr1.mean())**2) * np.sum((arr2 - arr2.mean())**2))
    return numerator / denominator if denominator != 0 else 0

def testRobustness(watermarkedImage):
    attacks = []
    labels = []
    attacks.append(watermarkedImage.transpose(Image.FLIP_LEFT_RIGHT))
    labels.append("Flip Horizontal")
    attacks.append(watermarkedImage.transpose(Image.FLIP_TOP_BOTTOM))
    labels.append("Flip Vertical")
    attacks.append(watermarkedImage.transform(watermarkedImage.size, Image.AFFINE, (1, 0, 20, 0, 1, 20)))
    labels.append("Translate 20px")
    w, h = watermarkedImage.size
    cropped = watermarkedImage.crop((20, 20, w-20, h-20)).resize((w, h))
    attacks.append(cropped)
    labels.append("Crop & Resize")
    enhancer = ImageEnhance.Contrast(watermarkedImage)
    attacks.append(enhancer.enhance(1.2))
    labels.append("Contrast +50%")
    return attacks, labels

def main():
    imagePath = "./Pics/test.png"
    text = "test watermark"

    watermarkedImage, wmOriginal = embedTextWatermarkLSB(imagePath, text)
    extractedOriginal = extractWatermarkLSB(watermarkedImage)

    attackedImages, labels = testRobustness(watermarkedImage)

    for i, attacked in enumerate(attackedImages):
        wmAttacked = extractWatermarkLSB(attacked)
        ncc = calcNCC(wmOriginal, wmAttacked)

        plt.figure(figsize=(8, 4))
        plt.subplot(1, 2, 1)
        plt.imshow(attacked)
        plt.title(f"Attack: {labels[i]}")
        plt.axis('off')

        plt.subplot(1, 2, 2)
        plt.imshow(wmAttacked, cmap='gray')
        plt.title(f"Extracted WM\nNCC={ncc:.2f}")
        plt.axis('off')

        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    main()