from pathlib import Path

from docx import Document
from PIL import Image, ImageDraw, ImageFont


# =========================
# 只需要修改这里
# =========================
DOCX_PATH = r"D:\temp\input.docx"
OUTPUT_PATH = r"D:\temp\output.png"

# Windows 自带微软雅黑。也可以改成 simsun.ttc、simhei.ttf 等。
FONT_PATH = r"C:\Windows\Fonts\msyh.ttc"

IMAGE_WIDTH = 1440       # 图片宽度
FONT_SIZE = 38           # 字号
MARGIN_X = 100           # 左右边距
MARGIN_Y = 90            # 上下边距
LINE_GAP = 16            # 行间距
PARAGRAPH_GAP = 18       # 段间距
BACKGROUND = "white"
TEXT_COLOR = "black"


def wrap_text(draw, text, font, max_width):
    """按照实际像素宽度换行，适合中文。"""
    if not text:
        return [""]

    lines = []
    current = ""

    for char in text.replace("\t", "    "):
        candidate = current + char

        if current and draw.textlength(candidate, font=font) > max_width:
            lines.append(current)
            current = char
        else:
            current = candidate

    if current:
        lines.append(current)

    return lines


doc = Document(DOCX_PATH)
paragraphs = [paragraph.text for paragraph in doc.paragraphs]

font = ImageFont.truetype(FONT_PATH, FONT_SIZE)

# 临时画布，只用于计算文字尺寸。
temp_image = Image.new("RGB", (IMAGE_WIDTH, 100), BACKGROUND)
temp_draw = ImageDraw.Draw(temp_image)

bbox = temp_draw.textbbox((0, 0), "中文Ag", font=font)
line_height = bbox[3] - bbox[1] + LINE_GAP
text_width = IMAGE_WIDTH - MARGIN_X * 2

# 预先计算每一行的位置。
layout = []
y = MARGIN_Y

for paragraph in paragraphs:
    lines = wrap_text(temp_draw, paragraph, font, text_width)

    for line in lines:
        layout.append((line, y))
        y += line_height

    y += PARAGRAPH_GAP

image_height = y + MARGIN_Y

# 正式绘制。
image = Image.new("RGB", (IMAGE_WIDTH, image_height), BACKGROUND)
draw = ImageDraw.Draw(image)

for line, y in layout:
    draw.text((MARGIN_X, y), line, font=font, fill=TEXT_COLOR)

Path(OUTPUT_PATH).parent.mkdir(parents=True, exist_ok=True)
image.save(OUTPUT_PATH, quality=95)

print(f"已生成：{OUTPUT_PATH}")
print(f"图片尺寸：{IMAGE_WIDTH} × {image_height}")
