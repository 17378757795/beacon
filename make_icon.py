"""生成 Beacon 图标 app.ico（无外部素材，纯代码绘制）。"""

from PIL import Image, ImageDraw

SIZE = 512
BG = (16, 26, 46, 255)
CYAN = (56, 189, 248, 255)
WHITE = (226, 240, 255, 255)

img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
mask = Image.new("L", (SIZE, SIZE), 0)
md = ImageDraw.Draw(mask)
md.rounded_rectangle([0, 0, SIZE - 1, SIZE - 1], radius=112, fill=255)
img.paste(BG, (0, 0), mask)

d = ImageDraw.Draw(img)
cx, cy = SIZE // 2, SIZE // 2 + 26

# 中心信标点
d.ellipse([cx - 34, cy - 34, cx + 34, cy + 34], fill=WHITE)
d.ellipse([cx - 16, cy - 16, cx + 16, cy + 16], fill=BG)

# 三道扩散弧
for i, r in enumerate((92, 148, 204)):
    box = [cx - r, cy - r, cx + r, cy + r]
    d.arc(box, start=208, end=332, fill=CYAN, width=26 - i * 4)

img.save("app.ico", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
print("app.ico written")
