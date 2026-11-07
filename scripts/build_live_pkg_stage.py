"""Prepare local OpenOrbis PKG input staging; does not build or sign a PKG.

Call only after independent OpenOrbis eboot.bin, param.sfo and icon0.png
have been produced with the user's toolchain. Never invent a signed package.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil
import sys


def stage(eboot: Path, sfo: Path, icon: Path, output: Path) -> None:
    inputs = [(eboot, "eboot.bin"), (sfo, "sce_sys/param.sfo"),
              (icon, "sce_sys/icon0.png")]
    if output.exists() or not output.parent.is_dir():
        raise ValueError("Output staging directory must be new, with existing parent")
    for src, _ in inputs:
        if not src.is_file() or src.stat().st_size == 0 or src.is_symlink():
            raise ValueError("Missing or empty input: " + str(src))
    png = icon.read_bytes()[:26]
    if (len(png) != 26 or png[:8] != b"\x89PNG\r\n\x1a\n" or
            png[12:16] != b"IHDR" or
            int.from_bytes(png[16:20], "big") != 512 or
            int.from_bytes(png[20:24], "big") != 512 or
            png[24:26] != bytes((8, 2))):
        raise ValueError("icon0 must be a 512x512, 8-bit RGB PNG")
    if sfo.read_bytes()[:4] != b"\x00PSF":
        raise ValueError("param.sfo must be a compiled PSF, not a text placeholder")
    if eboot.read_bytes()[:4] != b"\x4f\x15\x3d\x1d":
        raise ValueError("eboot.bin must have a PS4 SELF container header; not an ELF")
    # Avoid claiming that any ELF is a runnable application eboot.
    output.mkdir()
    try:
        for src, rel in inputs:
            dest = output / rel
            dest.parent.mkdir(exist_ok=True)
            shutil.copy2(src, dest)
    except BaseException:
        shutil.rmtree(output)
        raise


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="OpenOrbis homebrew PKG input staging; no PKG output")
    p.add_argument("--eboot", type=Path, required=True)
    p.add_argument("--sfo", type=Path, required=True)
    p.add_argument("--icon", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        stage(args.eboot, args.sfo, args.icon, args.output)
        print("Staging created; now use verified OpenOrbis/LibOrbisPkg tools to build PKG.")
        return 0
    except (OSError, ValueError) as exc:
        print("PKG staging error:", exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
