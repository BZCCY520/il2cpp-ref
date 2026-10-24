#!/usr/bin/env python3
"""
inject_dylib.py — 把 dylib 挂进 IPA 的 Mach-O 主二进制

纯 Python，无需 macOS 工具链。可在 Windows / Linux / macOS 上运行。

做的事：
  1. 解包 IPA
  2. 找到 Payload/*.app/ 下的主可执行文件（读 Info.plist 的 CFBundleExecutable）
  3. 拷贝 dylib 到 .app/Frameworks/
  4. 在主二进制里新增一条 LC_LOAD_DYLIB 指向它
     - 若 __TEXT 头部有足够 padding，直接原地追加（不移动任何已有数据）
     - 否则报错退出（不做危险的段重排）
  5. 删除失效的 _CodeSignature
  6. 重新打包 IPA

注意：产物签名必然失效，安装前必须用你自己的证书重签
      （Sideloadly / AltStore / TrollStore 会自动处理）。
"""
import argparse
import os
import plistlib
import shutil
import struct
import sys
import zipfile

LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C


LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C
LC_CODE_SIGNATURE = 0x1D

# segment_command_64 布局：
#   cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8) fileoff(8) filesize(8) ...
# 所以 fileoff 在段命令内的偏移是 8+16+8+8 = 40
SEG_FILEOFF_OFFSET = 40


def find_main_binary(app_dir: str) -> str:
    plist_path = os.path.join(app_dir, "Info.plist")
    with open(plist_path, "rb") as f:
        info = plistlib.load(f)
    exe = info.get("CFBundleExecutable")
    if not exe:
        raise SystemExit("Info.plist 里没有 CFBundleExecutable")
    path = os.path.join(app_dir, exe)
    if not os.path.exists(path):
        raise SystemExit("主可执行文件不存在: %s" % path)
    return path


def parse_load_commands(data: bytes):
    """返回 (ncmds, sizeofcmds, [ (offset, cmd, cmdsize) ... ])"""
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xFEEDFACF:
        raise SystemExit("不是 64 位 Mach-O (magic=%#x)" % magic)
    ncmds = struct.unpack_from("<I", data, 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, 20)[0]
    cmds = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            raise SystemExit("load command 链损坏 @ %#x" % off)
        cmds.append((off, cmd, cmdsize))
        off += cmdsize
    return ncmds, sizeofcmds, cmds


def first_section_fileoff(data: bytes, cmds):
    """取 __TEXT 里第一个 section 的 file offset —— 这才是 load command 区的真实上界"""
    for off, cmd, cmdsize in cmds:
        if cmd != LC_SEGMENT_64:
            continue
        segname = data[off + 8:off + 24].rstrip(b"\x00").decode("latin-1")
        if segname != "__TEXT":
            continue
        fileoff = struct.unpack_from("<Q", data, off + SEG_FILEOFF_OFFSET)[0]
        nsects = struct.unpack_from("<I", data, off + 64)[0]
        sect_off = off + 72
        best = None
        for _ in range(nsects):
            # section_64: sectname(16) segname(16) addr(8) size(8) offset(4) ...
            s_off = struct.unpack_from("<I", data, sect_off + 48)[0]
            if s_off and (best is None or s_off < best):
                best = s_off
            sect_off += 80
        if best is not None:
            return best
        return fileoff
    raise SystemExit("找不到 __TEXT 段")


def build_load_dylib(path: str) -> bytes:
    """构造一条 LC_LOAD_DYLIB（含 nameoff/timestamp/current_version/compatibility_version）"""
    name = path.encode("utf-8") + b"\x00"
    nameoff = 24                       # dylib_command 头部长度
    cmdsize = nameoff + len(name)
    cmdsize = (cmdsize + 7) & ~7       # 8 字节对齐
    cmd = struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, nameoff, 2, 0x10000, 0x10000)
    payload = cmd + name
    payload += b"\x00" * (cmdsize - len(payload))
    return payload


def inject(binary_path: str, dylib_install_name: str) -> None:
    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    ncmds, sizeofcmds, cmds = parse_load_commands(data)
    print("  主二进制: %d 条 load command, sizeofcmds=%d" % (ncmds, sizeofcmds))

    def lc_name(off, cmdsize):
        nameoff = struct.unpack_from("<I", data, off + 8)[0]
        end = data.find(b"\x00", off + nameoff, off + cmdsize)
        if end < 0:
            return ""
        return bytes(data[off + nameoff:end]).decode("latin-1", "replace")

    # 幂等：已存在同名 LC 就直接返回
    for off, cmd, cmdsize in cmds:
        if cmd in (LC_LOAD_DYLIB, 0x80000018, 0x1F, 0x8000001F):
            if lc_name(off, cmdsize) == dylib_install_name:
                print("  已存在该 LC，跳过注入")
                return

    new_lc = build_load_dylib(dylib_install_name)

    # ---- 策略 A：复用一条「已失效/已清空」的 dylib LC 槽位 ----
    # 典型场景：原包有三方注入 dylib，被剥成 LC_LOAD_WEAK_DYLIB 且路径清零后，
    # 这条命令还占着 cmdsize 字节但名字为空 —— 正好可以原地改指新 dylib，
    # 完全不改变 ncmds / sizeofcmds / 任何 segment 偏移。
    for off, cmd, cmdsize in cmds:
        if cmd not in (0x80000018, 0x8000001F):
            continue
        if lc_name(off, cmdsize) != "":
            continue
        if cmdsize < len(new_lc):
            print("  发现空 WEAK 槽位但太小（%d < %d），跳过" % (cmdsize, len(new_lc)))
            continue
        print("  复用空 WEAK DYLIB 槽位 @ %#x (cmdsize=%d)" % (off, cmdsize))
        data[off:off + cmdsize] = new_lc + b"\x00" * (cmdsize - len(new_lc))
        # 保持 cmdsize 不变，但改成强加载 LC_LOAD_DYLIB
        struct.pack_into("<I", data, off + 4, cmdsize)
        # 清零 LC_CODE_SIGNATURE
        _zero_codesig(data)
        with open(binary_path, "wb") as f:
            f.write(data)
        print("  写入完成（大小不变: %d 字节）" % len(data))
        return

    # ---- 策略 B：在 load command 区尾部追加（需要 padding） ----
    first_sect = first_section_fileoff(data, cmds)
    lc_end = 32 + sizeofcmds
    available = first_sect - lc_end

    if available < len(new_lc):
        raise SystemExit(
            "无法注入：load command 区没有 padding（需要 %d 字节，可用 %d），\n"
            "也没有可复用的空 WEAK DYLIB 槽位。\n"
            "拒绝做段重排以免损坏二进制。" % (len(new_lc), available)
        )

    print("  padding 可用 %d 字节，追加 %d 字节" % (available, len(new_lc)))
    data[lc_end:lc_end + len(new_lc)] = new_lc
    struct.pack_into("<I", data, 16, ncmds + 1)
    struct.pack_into("<I", data, 20, sizeofcmds + len(new_lc))
    _zero_codesig(data)

    with open(binary_path, "wb") as f:
        f.write(data)
    print("  写入完成，大小 %d -> %d" % (len(data) - len(new_lc), len(data)))


def _zero_codesig(data: bytearray) -> None:
    """LC_CODE_SIGNATURE 清零：原签名已失效，重签时由 codesign 重建"""
    try:
        _, _, cmds = parse_load_commands(data)
    except SystemExit:
        return
    for off, cmd, cmdsize in cmds:
        if cmd == LC_CODE_SIGNATURE:
            struct.pack_into("<II", data, off + 8, 0, 0)
            print("  已清空 LC_CODE_SIGNATURE（等待重签）")


def repack(app_dir: str, out_ipa: str) -> None:
    payload_root = os.path.dirname(app_dir)          # .../Payload
    stage = os.path.dirname(payload_root)            # 解包根目录
    if os.path.exists(out_ipa):
        os.remove(out_ipa)
    with zipfile.ZipFile(out_ipa, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for root, _dirs, files in os.walk(payload_root):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, stage).replace("\\", "/")
                z.write(full, rel)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True, help="输入 IPA")
    ap.add_argument("--dylib", required=True, help="要注入的 dylib")
    ap.add_argument("--out", required=True, help="输出 IPA")
    ap.add_argument("--stage", default=None, help="解包临时目录")
    ap.add_argument("--name", default=None, help="dylib 的 install name（默认取文件名）")
    args = ap.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    stage = args.stage or os.path.join(script_dir, "..", "work", "stage")
    stage = os.path.abspath(stage)

    if os.path.isdir(stage):
        shutil.rmtree(stage)
    os.makedirs(stage, exist_ok=True)

    print("[1/6] 解包 %s" % args.ipa)
    with zipfile.ZipFile(args.ipa) as z:
        z.extractall(stage)

    payload = os.path.join(stage, "Payload")
    apps = [d for d in os.listdir(payload) if d.endswith(".app")]
    if not apps:
        raise SystemExit("Payload 下找不到 .app")
    app_dir = os.path.join(payload, apps[0])
    print("[2/6] app bundle: %s" % app_dir)

    binary = find_main_binary(app_dir)
    print("[3/6] 主二进制: %s" % binary)

    fw_dir = os.path.join(app_dir, "Frameworks")
    os.makedirs(fw_dir, exist_ok=True)
    dylib_name = os.path.basename(args.dylib)
    shutil.copy2(args.dylib, os.path.join(fw_dir, dylib_name))
    print("[4/6] 已拷贝 dylib -> Frameworks/%s" % dylib_name)

    install_name = args.name or "@executable_path/Frameworks/%s" % dylib_name
    print("[5/6] 注入 LC_LOAD_DYLIB: %s" % install_name)
    inject(binary, install_name)

    # 清理失效签名
    for root, dirs, _files in os.walk(app_dir):
        for d in list(dirs):
            if d == "_CodeSignature":
                shutil.rmtree(os.path.join(root, d))
                dirs.remove(d)
    macosx = os.path.join(stage, "__MACOSX")
    if os.path.isdir(macosx):
        shutil.rmtree(macosx)

    print("[6/6] 重新打包 -> %s" % args.out)
    repack(app_dir, args.out)
    print("完成: %s (%d bytes)" % (args.out, os.path.getsize(args.out)))
    print()
    print("提醒：签名已失效，安装前用 Sideloadly / AltStore / TrollStore 重签。")


if __name__ == "__main__":
    main()
