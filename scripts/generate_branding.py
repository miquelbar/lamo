#!/usr/bin/env python3
"""
Generate High-Quality Cinematic Historical Branding Assets using ImageMagick:

1. L'AMO (El Administrador de la Possessió) -> Local Multi-Server Orchestrator CLI:
   - Authentic 19th-century Mallorcan overseer sowing seeds in Tramuntana estate.
   - Assets: assets/lamo-avatar.png (512x512), assets/lamo-logo.png (800x240), assets/lamo-favicon-64x64.png

2. ES BOVER (El Boyero de la Possessió) -> Server Cattle Daemon & Runtime Worker:
   - Traditional 19th-century Mallorcan boyero with his draft oxen, red barretina, and agullada staff.
   - Assets: assets/bover-avatar.png (512x512), assets/bover-logo.png (800x240), assets/bover-favicon-64x64.png
"""

import shutil
import subprocess
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = BASE_DIR / "assets"
MAGICK = shutil.which("magick") or "magick"

def run(cmd_list):
    res = subprocess.run(cmd_list, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"ERROR executing: {' '.join(cmd_list)}\n{res.stderr}")
        raise RuntimeError(res.stderr)
    return res.stdout.strip()

def build_circle_mask(size):
    mask_path = ASSETS_DIR / f"_mask_{size}.png"
    radius = size // 2
    center = size // 2
    cmd = [
        MAGICK, "-size", f"{size}x{size}", "xc:none",
        "-fill", "white", "-draw", f"circle {center},{center} {center},{center - radius + 1}",
        str(mask_path)
    ]
    run(cmd)
    return mask_path

def create_circular_avatar(src_img, crop_w, crop_h, crop_x, crop_y, out_png, label, border_color1, border_color2):
    """Generate 512x512 circular framed avatar with high-end photographic badge & ribbon."""
    inner_size = 484
    mask_file = build_circle_mask(inner_size)
    temp_crop = ASSETS_DIR / "_temp_crop.png"
    temp_circle = ASSETS_DIR / "_temp_circle.png"
    
    # 1. Crop and resize photo to inner_size x inner_size
    cmd_crop = [
        MAGICK, str(src_img),
        "-crop", f"{crop_w}x{crop_h}+{crop_x}+{crop_y}", "+repage",
        "-resize", f"{inner_size}x{inner_size}^", "-gravity", "center", "-extent", f"{inner_size}x{inner_size}",
        str(temp_crop)
    ]
    run(cmd_crop)
    
    # 2. Mask to circle
    cmd_mask = [
        MAGICK, str(temp_crop), str(mask_file),
        "-alpha", "off", "-compose", "CopyOpacity", "-composite",
        str(temp_circle)
    ]
    run(cmd_mask)
    
    offset = (512 - inner_size) // 2  # 14px
    
    # 3. Create 512x512 canvas with luxury outer gold/bronze double rings and shadow
    # In ImageMagick: circle center_x,center_y edge_x,edge_y
    cmd_final = [
        MAGICK, "-size", "512x512", "xc:none",
        # Outer thick luxury ring (radius 250)
        "-stroke", border_color1, "-strokewidth", "6", "-fill", "none",
        "-draw", "circle 256,256 256,6",
        # Middle dark trim (radius 245)
        "-stroke", "#0b0f19", "-strokewidth", "3", "-fill", "none",
        "-draw", "circle 256,256 256,11",
        # Inner fine gold ring (radius 242)
        "-stroke", border_color2, "-strokewidth", "3", "-fill", "none",
        "-draw", "circle 256,256 256,14",
        # Composite circular photo
        str(temp_circle), "-geometry", f"+{offset}+{offset}", "-composite",
        # Bottom label badge pill (dark background with matching border)
        "-fill", "#090d16", "-stroke", border_color1, "-strokewidth", "2.8",
        "-draw", "roundrectangle 146,440 366,488 24,24",
        # Bottom label text
        "-fill", border_color1, "-stroke", "none", "-font", "Helvetica-Bold", "-pointsize", "22",
        "-gravity", "North", "-annotate", "+0+450", label,
        str(out_png)
    ]
    run(cmd_final)
    
    # Clean up temp
    temp_crop.unlink(missing_ok=True)
    temp_circle.unlink(missing_ok=True)
    mask_file.unlink(missing_ok=True)
    print(f"  [✓] Generated {out_png.name}")

def create_horizontal_logo(avatar_png, out_png, prog_name, role_title, subtitle, brand_color):
    """Generate 800x240 banner with circular badge and crisp modern typography."""
    temp_badge = ASSETS_DIR / "_temp_logo_badge.png"
    run([MAGICK, str(avatar_png), "-resize", "196x196", str(temp_badge)])
    
    cmd = [
        MAGICK, "-size", "800x240", "xc:#0b0f19",
        "-stroke", "#1e293b", "-strokewidth", "2", "-fill", "none",
        "-draw", "roundrectangle 1,1 798,238 16,16",
        str(temp_badge), "-geometry", "+22+22", "-composite",
        # Main Title (prog_name)
        "-fill", brand_color, "-stroke", "none", "-font", "Helvetica-Bold", "-pointsize", "72",
        "-gravity", "NorthWest", "-annotate", "+244+36", prog_name,
        # Role Title
        "-fill", "#f8fafc", "-stroke", "none", "-font", "Helvetica-Bold", "-pointsize", "17.5",
        "-gravity", "NorthWest", "-annotate", "+248+128", role_title,
        # Subtitle
        "-fill", "#94a3b8", "-stroke", "none", "-font", "Helvetica", "-pointsize", "12.5",
        "-gravity", "NorthWest", "-annotate", "+248+162", subtitle,
        str(out_png)
    ]
    run(cmd)
    temp_badge.unlink(missing_ok=True)
    print(f"  [✓] Generated {out_png.name}")

def create_favicon(src_img, crop_w, crop_h, crop_x, crop_y, out_png, border_color):
    """Generate 64x64 rounded icon for browser / dashboard."""
    temp_crop = ASSETS_DIR / "_temp_fav_crop.png"
    mask_fav = ASSETS_DIR / "_temp_fav_mask.png"
    
    run([MAGICK, "-size", "64x64", "xc:none", "-fill", "white", "-draw", "roundrectangle 0,0 63,63 14,14", str(mask_fav)])
    run([MAGICK, str(src_img), "-crop", f"{crop_w}x{crop_h}+{crop_x}+{crop_y}", "+repage", "-resize", "64x64^", "-gravity", "center", "-extent", "64x64", str(temp_crop)])
    
    cmd = [
        MAGICK, str(temp_crop), str(mask_fav),
        "-alpha", "off", "-compose", "CopyOpacity", "-composite",
        "-stroke", border_color, "-strokewidth", "2.5", "-fill", "none",
        "-draw", "roundrectangle 1,1 62,62 14,14",
        str(out_png)
    ]
    run(cmd)
    temp_crop.unlink(missing_ok=True)
    mask_fav.unlink(missing_ok=True)
    print(f"  [✓] Generated {out_png.name}")

def main():
    print("=" * 66)
    print(" GENERATING CINEMATIC HISTORICAL BRANDING ASSETS (L'AMO & ES BOVER)")
    print("=" * 66)
    
    lamo_src = ASSETS_DIR / "lamo-photo.jpg"
    bover_src = ASSETS_DIR / "bover-photo.jpg"
    
    # 1. L'AMO ASSETS
    print("\n==> [1/2] Processing L'Amo (Local Estate Orchestrator)...")
    # In lamo-photo.jpg (1376x768): L'Amo is around x=680-1180, y=70-670
    create_circular_avatar(
        src_img=lamo_src,
        crop_w=620, crop_h=620, crop_x=680, crop_y=70,
        out_png=ASSETS_DIR / "lamo-avatar.png",
        label="L'AMO",
        border_color1="#f59e0b",
        border_color2="#d97706"
    )
    create_horizontal_logo(
        avatar_png=ASSETS_DIR / "lamo-avatar.png",
        out_png=ASSETS_DIR / "lamo-logo.png",
        prog_name="lamo",
        role_title="L'AMO :: ESTATE ORCHESTRATOR",
        subtitle="Multi-Server Infrastructure CLI · Cattle Nodes Orchestration",
        brand_color="#f59e0b"
    )
    create_favicon(
        src_img=lamo_src,
        crop_w=380, crop_h=380, crop_x=760, crop_y=80,
        out_png=ASSETS_DIR / "lamo-favicon-64x64.png",
        border_color="#f59e0b"
    )
    
    # 2. ES BOVER ASSETS
    print("\n==> [2/2] Processing Es Bover (Server Cattle Runtime Worker)...")
    # In bover-photo.jpg (1264x848): Bover is centered around x=260-1000, y=40-780
    create_circular_avatar(
        src_img=bover_src,
        crop_w=740, crop_h=740, crop_x=260, crop_y=40,
        out_png=ASSETS_DIR / "bover-avatar.png",
        label="ES BOVER",
        border_color1="#ea580c",
        border_color2="#b45309"
    )
    create_horizontal_logo(
        avatar_png=ASSETS_DIR / "bover-avatar.png",
        out_png=ASSETS_DIR / "bover-logo.png",
        prog_name="bover",
        role_title="ES BOVER :: NODE RUNTIME WORKER",
        subtitle="Zero-Downtime Blue/Green Deployer · Caddy ALB Gateway · Cattle Node Daemon",
        brand_color="#ea580c"
    )
    create_favicon(
        src_img=bover_src,
        crop_w=400, crop_h=400, crop_x=430, crop_y=50,
        out_png=ASSETS_DIR / "bover-favicon-64x64.png",
        border_color="#ea580c"
    )
    
    print("\n✨ All cinematic branding assets generated successfully in assets/!")

if __name__ == "__main__":
    main()
