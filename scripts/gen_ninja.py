#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
Ninja Manifest Generator for Android Linux 4.14 Kernel (arm64)
Extracts compilation and link DAG from Kbuild .cmd files in out/ and
generates a standalone, deterministic build.ninja manifest.
"""

import argparse
import os
import re
import shutil
import sys
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple


def tokenize_cmd(cmd: str) -> List[str]:
    """Tokenize a shell command line while preserving quotes."""
    tokens = []
    curr = []
    in_quote = None
    for c in cmd:
        if in_quote:
            curr.append(c)
            if c == in_quote:
                in_quote = None
        elif c in ('"', "'"):
            in_quote = c
            curr.append(c)
        elif c.isspace():
            if curr:
                tokens.append("".join(curr))
                curr = []
        else:
            curr.append(c)
    if curr:
        tokens.append("".join(curr))
    return tokens


def translate_path(p: str, out_dir: str = "out") -> str:
    """
    Translate path from out-relative (as executed by Kbuild) to repo-root relative.
    """
    p = p.replace('"', "").replace("'", "")
    if p.startswith("../-I"):
        p = p[3:]
    while p.startswith("-I"):
        p = p[2:]
    if p in ("..", "../"):
        return "."
    elif p.startswith("../"):
        return p[3:]
    elif p in (".", "./"):
        return out_dir
    elif p.startswith("./"):
        return os.path.join(out_dir, p[2:])
    elif not os.path.isabs(p) and not p.startswith("-"):
        return os.path.join(out_dir, p)
    return p


def escape_ninja_path(p: str) -> str:
    """Escape special characters in paths for Ninja syntax."""
    return p.replace("$", "$$").replace(" ", "$ ").replace(":", "$:")


class NinjaGenerator:
    def __init__(self, out_dir: str = "out", output: str = "build.ninja",
                 toolchain_dir: Optional[str] = None, use_ccache: bool = True):
        self.out_dir = out_dir.rstrip("/")
        self.output_path = output
        self.toolchain_dir = toolchain_dir or self._find_toolchain()
        self.use_ccache = use_ccache and bool(shutil.which("ccache"))

        # Binaries
        self.clang = os.path.join(self.toolchain_dir, "clang")
        self.ld = os.path.join(self.toolchain_dir, "ld.lld")
        self.ar = os.path.join(self.toolchain_dir, "llvm-ar")
        self.nm = os.path.join(self.toolchain_dir, "llvm-nm")
        self.objcopy = os.path.join(self.toolchain_dir, "llvm-objcopy")
        self.objdump = os.path.join(self.toolchain_dir, "llvm-objdump")
        self.pahole = shutil.which("pahole") or "/usr/bin/pahole"

        # Host tools in out/ or tree
        self.genksyms = os.path.join(self.out_dir, "scripts/genksyms/genksyms")
        self.kallsyms = os.path.join(self.out_dir, "scripts/kallsyms")
        self.resolve_btfids = os.path.join(self.out_dir, "tools/bpf/resolve_btfids/resolve_btfids")
        self.sortextable = os.path.join(self.out_dir, "scripts/sortextable")
        self.mksysmap = "scripts/mksysmap"
        self.dtc_overlay = "scripts/dtc/dtc_overlay"
        self.vdsomunge = os.path.join(self.out_dir, "arch/arm/vdso/vdsomunge")
        self.pnmtologo = os.path.join(self.out_dir, "scripts/pnmtologo")
        self.genheaders = os.path.join(self.out_dir, "scripts/selinux/genheaders/genheaders")

        # Collector data
        self.cc_targets = []      # list of (target, src, flags)
        self.asm_targets = []     # list of (target, src, flags)
        self.ar_targets = []      # list of (target, inputs)
        self.special_targets = [] # custom edges
        self.lds_targets = []     # list of (target, src, flags)
        self.dtb_targets = []     # list of (target, src, cmd)

        self.global_cflags = []
        self.global_aflags = []

    def _find_toolchain(self) -> str:
        candidates = [
            "/home/zears/clang-wmk/bin",
            "/home/zears/clang-wmk",
            os.path.expanduser("~/clang-wmk/bin"),
        ]
        for c in candidates:
            if os.path.isfile(os.path.join(c, "clang")):
                return c
            if os.path.isfile(os.path.join(c, "bin", "clang")):
                return os.path.join(c, "bin")
        clang_path = shutil.which("clang")
        if clang_path:
            return os.path.dirname(clang_path)
        return "/usr/bin"

    def scan_cmd_files(self):
        """Scan all .cmd files in out_dir."""
        print(f"Scanning .cmd files in {self.out_dir}...")
        c_flags_counter = Counter()
        asm_flags_counter = Counter()

        raw_c = []
        raw_asm = []

        for root, _, files in os.walk(self.out_dir):
            for f in files:
                if not (f.startswith(".") and f.endswith(".cmd")):
                    continue
                filepath = os.path.join(root, f)
                with open(filepath, "r", errors="ignore") as fp:
                    content = fp.read()

                lines = content.split("\n", 2)
                if not lines or not lines[0].startswith("cmd_"):
                    continue

                cmd_line = lines[0]
                target_decl, raw_cmd = cmd_line.split(":=", 1)
                rel_target = target_decl[4:].strip()
                raw_cmd = raw_cmd.strip()

                # Filter out host tools and precursors
                if (rel_target.startswith("/") or
                        rel_target in (
                            "scripts/basic/fixdep", "scripts/basic/bin2c", "scripts/kconfig/conf",
                            "scripts/mod/modpost", "scripts/mod/mk_elfconfig",
                            "scripts/mod/devicetable-offsets.s", "scripts/mod/elfconfig.h",
                            "scripts/genksyms/genksyms", "scripts/sortextable", "scripts/asn1_compiler",
                            "scripts/extract-cert", "scripts/kallsyms", "scripts/pnmtologo",
                            "scripts/dtc/dtc", "scripts/selinux/genheaders/genheaders",
                            "scripts/selinux/mdp/mdp", "lib/gen_crc32table", "usr/gen_init_cpio",
                            "arch/arm64/kernel/asm-offsets.s", "kernel/bounds.s"
                        ) or rel_target.endswith("vdsomunge")):
                    continue

                target = translate_path(rel_target, self.out_dir)

                # Find source if present
                m_src = re.search(r"source_\S+\s*:=\s*(\S+)", content)
                src = translate_path(m_src.group(1), self.out_dir) if m_src else None

                # Classification
                if "scripts/link-vmlinux.sh" in raw_cmd:
                    # Top-level vmlinux handled separately in pipeline
                    continue
                elif "llvm-objcopy" in raw_cmd and "arch/arm64/boot/Image" in target:
                    continue
                elif "gzip" in raw_cmd and "arch/arm64/boot/Image.gz" in target:
                    continue
                elif rel_target.endswith(".lds"):
                    flags = self._extract_cflags(raw_cmd, m_src.group(1) if m_src else "")
                    self.lds_targets.append((target, src, flags))
                elif rel_target.endswith(".dtb"):
                    self.dtb_targets.append((target, src, raw_cmd))
                elif re.search(r"\b(?:llvm-ar|ar)\s+rc", raw_cmd):
                    target_out, inputs = self._parse_ar_cmd(raw_cmd)
                    if target_out:
                        self.ar_targets.append((target_out, inputs))
                elif "lib-ksyms.o" in rel_target:
                    self.special_targets.append(("lib_ksyms", target, [src or target.replace("lib-ksyms.o", "lib.a")]))
                elif "vdso.so.dbg" in rel_target and "vdsomunge" in raw_cmd:
                    raw_in = raw_cmd.split()[-2]
                    self.special_targets.append(("vdso32_munge", target, [translate_path(raw_in, self.out_dir)]))
                elif "gen_vdso_offsets.sh" in raw_cmd:
                    # VDSO offsets header
                    in_dbg = re.search(r"llvm-nm\s+(\S+)", raw_cmd)
                    inp = translate_path(in_dbg.group(1), self.out_dir) if in_dbg else ""
                    self.special_targets.append(("vdso_offsets", target, [inp]))
                elif "vdso.so.raw" in rel_target:
                    inps = self._extract_ld_inputs(raw_cmd)
                    self.special_targets.append(("vdso32_raw", target, inps))
                elif "vdso.so.dbg" in rel_target:
                    inps = self._extract_ld_inputs(raw_cmd)
                    self.special_targets.append(("vdso_dbg", target, inps))
                elif "vdso.so" in rel_target and "llvm-objcopy" in raw_cmd:
                    inps = [translate_path(raw_cmd.split()[-2], self.out_dir)]
                    self.special_targets.append(("vdso_strip", target, inps))
                elif "pnmtologo" in raw_cmd:
                    # Logo C file generator
                    m_logo = re.search(r"-t\s+(\S+)\s+-n\s+(\S+)\s+-o\s+\S+\s+(\S+)", raw_cmd)
                    if m_logo:
                        t_flag, l_name, l_in = m_logo.groups()
                        self.special_targets.append(("pnmtologo", target, [translate_path(l_in, self.out_dir)], t_flag, l_name))
                elif "utf8data.h_shipped" in raw_cmd:
                    self.special_targets.append(("copy", target, ["fs/unicode/utf8data.h_shipped"]))
                elif "config_data.gz" in rel_target:
                    self.special_targets.append(("config_gz", target, [os.path.join(self.out_dir, ".config")]))
                elif "initramfs_data.cpio" in rel_target:
                    self.special_targets.append(("initramfs_cpio", target, []))
                elif "x509_certificate_list" in rel_target:
                    self.special_targets.append(("touch", target, []))
                elif "flask.h" in rel_target:
                    self.special_targets.append(("flask_h", target, [
                        "security/selinux/include/classmap.h",
                        "security/selinux/include/initial_sid_to_string.h"
                    ]))
                elif rel_target.endswith(".o"):
                    if src and not os.path.exists(src) and not os.path.exists(os.path.join(self.out_dir, src)):
                        continue
                    if src and src.endswith(".c"):
                        flags = self._extract_cflags(raw_cmd, m_src.group(1))
                        raw_c.append((target, src, flags))
                        for fl in set(flags):
                            c_flags_counter[fl] += 1
                    elif src and (src.endswith(".S") or src.endswith(".s")):
                        flags = self._extract_aflags(raw_cmd, m_src.group(1))
                        raw_asm.append((target, src, flags))
                        for fl in set(flags):
                            asm_flags_counter[fl] += 1

        # Deduplicate common C flags (present in >= 95% files)
        num_c = len(raw_c)
        if num_c > 0:
            common_c_set = {fl for fl, cnt in c_flags_counter.items() if cnt >= num_c * 0.95}
            self.global_cflags = [fl for fl in raw_c[0][2] if fl in common_c_set]
        else:
            self.global_cflags = []

        global_c_set = set(self.global_cflags)
        for target, src, flags in raw_c:
            extra = [fl for fl in flags if fl not in global_c_set]
            self.cc_targets.append((target, src, extra, flags))

        # Deduplicate common ASM flags (present in >= 90% files)
        num_asm = len(raw_asm)
        if num_asm > 0:
            common_asm_set = {fl for fl, cnt in asm_flags_counter.items() if cnt >= num_asm * 0.90}
            self.global_aflags = [fl for fl in raw_asm[0][2] if fl in common_asm_set]
        else:
            self.global_aflags = []

        global_asm_set = set(self.global_aflags)
        for target, src, flags in raw_asm:
            extra = [fl for fl in flags if fl not in global_asm_set]
            self.asm_targets.append((target, src, extra, flags))

        print(f"Processed {len(self.cc_targets)} C targets, {len(self.asm_targets)} ASM targets, {len(self.ar_targets)} archive targets.")

    def _extract_cflags(self, raw_cmd: str, src_path: str) -> List[str]:
        tokens = tokenize_cmd(raw_cmd)
        flags = []
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok in ("ccache", "clang") or tok == self.clang:
                i += 1
                continue
            if tok == "-c":
                i += 1
                continue
            if tok == "-o":
                i += 2
                continue
            if tok.startswith("-Wp,-MD,"):
                i += 1
                continue
            if tok == src_path:
                i += 1
                continue
            if tok == "-include":
                inc = translate_path(tokens[i + 1], self.out_dir)
                flags.append(f"-include {inc}")
                i += 2
                continue
            if tok == "-isystem":
                inc = translate_path(tokens[i + 1], self.out_dir)
                flags.append(f"-isystem {inc}")
                i += 2
                continue
            if tok.startswith("-I"):
                inc = translate_path(tok[2:], self.out_dir)
                flags.append(f"-I{inc}")
                i += 1
                continue
            if tok.startswith("-fmacro-prefix-map=../="):
                flags.append("-fmacro-prefix-map=./=")
                i += 1
                continue
            if tok.startswith("-DINITRAMFS_IMAGE="):
                flags.append(f"-DINITRAMFS_IMAGE={self.out_dir}/usr/initramfs_data.cpio")
                i += 1
                continue
            flags.append(tok)
            i += 1
        return flags

    def _extract_aflags(self, raw_cmd: str, src_path: str) -> List[str]:
        tokens = tokenize_cmd(raw_cmd)
        flags = []
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok in ("ccache", "clang") or tok == self.clang:
                i += 1
                continue
            if tok == "-c":
                i += 1
                continue
            if tok == "-o":
                i += 2
                continue
            if tok.startswith("-Wp,-MD,"):
                i += 1
                continue
            if tok == src_path:
                i += 1
                continue
            if tok == "-include":
                inc = translate_path(tokens[i + 1], self.out_dir)
                flags.append(f"-include {inc}")
                i += 2
                continue
            if tok == "-isystem":
                inc = translate_path(tokens[i + 1], self.out_dir)
                flags.append(f"-isystem {inc}")
                i += 2
                continue
            if tok.startswith("-I"):
                inc = translate_path(tok[2:], self.out_dir)
                flags.append(f"-I{inc}")
                i += 1
                continue
            if tok.startswith("-DINITRAMFS_IMAGE="):
                flags.append(f"-DINITRAMFS_IMAGE={self.out_dir}/usr/initramfs_data.cpio")
                i += 1
                continue
            flags.append(tok)
            i += 1
        return flags

    def _parse_ar_cmd(self, cmd: str) -> Tuple[Optional[str], List[str]]:
        cmd = cmd.strip()
        m = re.search(r"\b(?:llvm-ar|ar)\s+rc\S*\s+(\S+)\s*(.*?)(?:\s*;|\s*\Z)", cmd)
        if not m:
            return None, []
        out_target = translate_path(m.group(1), self.out_dir)
        raw_inputs = m.group(2).split()
        inputs = []
        for inp in raw_inputs:
            if inp.startswith("-"):
                continue
            inputs.append(translate_path(inp, self.out_dir))
        return out_target, inputs

    def _extract_ld_inputs(self, raw_cmd: str) -> List[str]:
        tokens = tokenize_cmd(raw_cmd)
        inputs = []
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "-T":
                inputs.append(translate_path(tokens[i + 1], self.out_dir))
                i += 2
                continue
            if tok == "-o":
                i += 2
                continue
            if not tok.startswith("-") and (tok.endswith(".o") or tok.endswith(".a") or tok.endswith(".lds")):
                inputs.append(translate_path(tok, self.out_dir))
            i += 1
        return inputs

    def generate(self):
        """Write out build.ninja manifest."""
        print(f"Writing Ninja manifest to {self.output_path}...")
        cc_cmd = f"ccache {self.clang}" if self.use_ccache else self.clang

        with open(self.output_path, "w") as out:
            out.write("# Deterministic Linux Kernel Ninja Manifest\n")
            out.write("# Generated by scripts/gen_ninja.py\n\n")

            out.write(f"out_dir = {self.out_dir}\n")
            out.write(f"clang = {self.clang}\n")
            out.write(f"cc = {cc_cmd}\n")
            out.write(f"as = {cc_cmd}\n")
            out.write(f"ar = {self.ar}\n")
            out.write(f"nm = {self.nm}\n")
            out.write(f"ld = {self.ld}\n")
            out.write(f"objcopy = {self.objcopy}\n")
            out.write(f"objdump = {self.objdump}\n")
            out.write(f"genksyms = {self.genksyms}\n")
            out.write(f"kallsyms = {self.kallsyms}\n")
            out.write(f"resolve_btfids = {self.resolve_btfids}\n")
            out.write(f"sortextable = {self.sortextable}\n")
            out.write(f"mksysmap = {self.mksysmap}\n")
            out.write(f"pahole = {self.pahole}\n")
            out.write("pahole_flags = --skip_encoding_btf_enum64 --skip_encoding_btf_inconsistent_proto --btf_gen_optimized --skip_encoding_btf_type_tag --skip_encoding_btf_decl_tag\n")
            out.write("ldflags = -maarch64linux -O2 -z noexecstack --no-undefined -X -z norelro -shared -Bsymbolic -z notext --no-apply-dynamic-relocs --build-id\n\n")

            order_headers = [
                f"{self.out_dir}/include/generated/autoconf.h",
                f"{self.out_dir}/include/generated/compile.h",
                f"{self.out_dir}/include/generated/asm-offsets.h",
                f"{self.out_dir}/include/generated/bounds.h",
                f"{self.out_dir}/include/generated/timeconst.h",
            ]
            order_only_str = " ".join(escape_ninja_path(p) for p in order_headers)

            out.write(f"cflags = -I{self.out_dir} {' '.join(self.global_cflags)}\n")
            out.write(f"aflags = -I{self.out_dir} {' '.join(self.global_aflags)}\n\n")

            # Rules
            out.write("# --- Compilation & Assembly Rules ---\n")
            out.write("rule cc\n")
            out.write("  command = $cc $cflags $extra_cflags -MD -MF $out.d -c -o $out.tmp $in && "
                      "if $objdump -h $out.tmp | grep -q __ksymtab; then "
                      "$cc -E -D__GENKSYMS__ $cflags $extra_cflags $in | $genksyms -r /dev/null > $out.ver && "
                      "$ld -r -o $out $out.tmp -T $out.ver && rm -f $out.tmp $out.ver; "
                      "else mv -f $out.tmp $out; fi\n")
            out.write("  depfile = $out.d\n")
            out.write("  deps = gcc\n")
            out.write("  description = CC $out\n\n")

            out.write("rule as\n")
            out.write("  command = $as $aflags $extra_aflags -MD -MF $out.d -c -o $out $in\n")
            out.write("  depfile = $out.d\n")
            out.write("  deps = gcc\n")
            out.write("  description = AS $out\n\n")

            out.write("rule cc_vdso32\n")
            out.write("  command = $cc $vdso32_cflags -MD -MF $out.d -c -o $out $in\n")
            out.write("  depfile = $out.d\n")
            out.write("  deps = gcc\n")
            out.write("  description = CC_VDSO32 $out\n\n")

            out.write("rule as_vdso32\n")
            out.write("  command = $as $vdso32_aflags -MD -MF $out.d -c -o $out $in\n")
            out.write("  depfile = $out.d\n")
            out.write("  deps = gcc\n")
            out.write("  description = AS_VDSO32 $out\n\n")

            out.write("rule ar\n")
            out.write("  command = rm -f $out && $ar rcSTPD $out $in\n")
            out.write("  description = AR $out\n\n")

            out.write("rule lds\n")
            out.write("  command = $cc -E -Wp,-MD,$out.d $cflags $extra_cflags -P -Uarm64 -D__ASSEMBLY__ -DLINKER_SCRIPT -o $out $in\n")
            out.write("  depfile = $out.d\n")
            out.write("  deps = gcc\n")
            out.write("  description = LDS $out\n\n")

            out.write("rule dtc\n")
            out.write(f"  command = mkdir -p $$(dirname $out) && $cc -E -Wp,-MD,$out.pre.tmp -nostdinc -Iscripts/dtc/include-prefixes -Iarch/arm64/boot/dts -Iarch/arm64/boot/dts/include -I{self.out_dir}/include/ -I{self.out_dir}/arch/arm64/boot/dts -undef -D__DTS__ -x assembler-with-cpp -o $out.dts.tmp $in && {self.dtc_overlay} -@ -O dtb -o $out -b 0 -iarch/arm64/boot/dts/mediatek/ -iscripts/dtc/include-prefixes -Wno-unit_address_vs_reg -Wno-simple_bus_reg -Wno-unit_address_format -Wno-pci_bridge -Wno-pci_device_bus_num -Wno-pci_device_reg $out.dts.tmp && rm -f $out.dts.tmp $out.pre.tmp\n")
            out.write("  description = DTC $out\n\n")

            out.write("rule lib_ksyms\n")
            out.write("  command = $objdump -h $in | sed -ne '/___ksymtab/s/.*+\\([^ \"]*\\).*/EXTERN(\\1)/p' > $out.lds && echo | $as $aflags -c -o $out.exports.o -x assembler - && $ld -maarch64linux -O2 -z noexecstack -r -o $out -T $out.lds $out.exports.o && rm -f $out.exports.o $out.lds\n")
            out.write("  description = LIB_KSYMS $out\n\n")

            out.write("rule vdso_dbg\n")
            out.write("  command = $ld -maarch64linux -O2 -z noexecstack -shared -nostdlib -soname=linux-vdso.so.1 --hash-style=sysv --build-id -n -T $lds $in -o $out\n")
            out.write("  description = VDSO_DBG $out\n\n")

            out.write("rule vdso_strip\n")
            out.write("  command = $objcopy -S $in $out\n")
            out.write("  description = VDSO_STRIP $out\n\n")

            out.write("rule vdso_offsets\n")
            out.write("  command = $nm $in | arch/arm64/kernel/vdso/gen_vdso_offsets.sh | LC_ALL=C sort > $out\n")
            out.write("  description = VDSO_OFFSETS $out\n\n")

            out.write("rule vdso32_raw\n")
            out.write("  command = $ld -Bsymbolic --no-undefined -soname=linux-vdso.so.1 -z max-page-size=4096 -z common-page-size=4096 -nostdlib -shared --hash-style=sysv --build-id -T $lds $in -o $out\n")
            out.write("  description = VDSO32_RAW $out\n\n")

            out.write("rule vdso32_munge\n")
            out.write(f"  command = {self.vdsomunge} $in $out\n")
            out.write("  description = VDSO32_MUNGE $out\n\n")

            out.write("rule initramfs_cpio\n")
            out.write(f"  command = cd {self.out_dir} && /bin/sh ../scripts/gen_initramfs_list.sh -o usr/initramfs_data.cpio -d\n")
            out.write("  description = GEN_INITRAMFS $out\n\n")

            out.write("rule config_gz\n")
            out.write("  command = cat $in | gzip -n -f -9 > $out\n")
            out.write("  description = GZIP $out\n\n")

            out.write("rule copy\n")
            out.write("  command = cp -f $in $out\n")
            out.write("  description = COPY $out\n\n")

            out.write("rule touch\n")
            out.write("  command = touch $out\n")
            out.write("  description = TOUCH $out\n\n")

            out.write("rule flask_h\n")
            out.write(f"  command = mkdir -p $$(dirname $out) && {self.genheaders} $out {self.out_dir}/security/selinux/av_permissions.h\n")
            out.write("  description = FLASK_H $out\n\n")

            out.write("rule pnmtologo\n")
            out.write(f"  command = {self.pnmtologo} -t $t_flag -n $l_name -o $out $in\n")
            out.write("  description = PNMTOLOGO $out\n\n")

            out.write("# --- Kernel Link & Packaging Rules ---\n")
            out.write("rule ld_vmlinux\n")
            out.write("  command = $ld $ldflags -o $out -T $lds --whole-archive $builtin --no-whole-archive --start-group $libs --end-group $extra_objs\n")
            out.write("  description = LD_VMLINUX $out\n\n")

            out.write("rule gen_btf\n")
            out.write("  command = $ld $ldflags -o $out.tmp -T $lds --whole-archive $builtin --no-whole-archive --start-group $libs --end-group && LLVM_OBJCOPY=$objcopy $pahole -J $pahole_flags $out.tmp && $objcopy --only-section=.BTF --set-section-flags .BTF=alloc,readonly --strip-all $out.tmp $out && printf '\\1\\0' | dd of=$out conv=notrunc bs=1 seek=16 status=none && rm -f $out.tmp\n")
            out.write("  description = GEN_BTF $out\n\n")

            out.write("rule kallsyms\n")
            out.write("  command = $nm -n $in | $kallsyms --all-symbols --base-relative > $out.S && $as $aflags -c -o $out $out.S && rm -f $out.S\n")
            out.write("  description = KALLSYMS $out\n\n")

            out.write("rule ld_vmlinux_final\n")
            out.write(f"  command = $ld $ldflags -o $out -T $lds --whole-archive $builtin --no-whole-archive --start-group $libs --end-group $extra_objs && $resolve_btfids $out && $sortextable $out && NM=$nm $mksysmap $out {self.out_dir}/System.map\n")
            out.write("  description = LD_VMLINUX_FINAL $out\n\n")

            out.write("rule objcopy_image\n")
            out.write("  command = $objcopy -O binary -R .note -R .note.gnu.build-id -R .comment -S $in $out\n")
            out.write("  description = OBJCOPY_IMAGE $out\n\n")

            out.write("rule gzip_image\n")
            out.write("  command = cat $in | gzip -n -f -9 > $out\n")
            out.write("  description = GZIP_IMAGE $out\n\n")

            # Build statements
            out.write("# --- Special and Generated Targets ---\n")
            for item in self.special_targets:
                rule_name = item[0]
                target = item[1]
                inputs = item[2]
                in_str = " ".join(escape_ninja_path(p) for p in inputs)
                t_str = escape_ninja_path(target)
                if rule_name == "pnmtologo":
                    t_flag, l_name = item[3], item[4]
                    out.write(f"build {t_str}: pnmtologo {in_str}\n")
                    out.write(f"  t_flag = {t_flag}\n")
                    out.write(f"  l_name = {l_name}\n")
                elif rule_name in ("vdso_dbg", "vdso32_raw"):
                    lds_f = [p for p in inputs if p.endswith(".lds")]
                    objs = [p for p in inputs if not p.endswith(".lds")]
                    out.write(f"build {t_str}: {rule_name} {' '.join(objs)}\n")
                    if lds_f:
                        out.write(f"  lds = {lds_f[0]}\n")
                else:
                    out.write(f"build {t_str}: {rule_name} {in_str}\n")
            out.write("\n")

            out.write("# --- Linker Scripts ---\n")
            for target, src, flags in self.lds_targets:
                t_str = escape_ninja_path(target)
                s_str = escape_ninja_path(src) if src else ""
                out.write(f"build {t_str}: lds {s_str} || {order_only_str}\n")
                if flags:
                    out.write(f"  extra_cflags = {' '.join(flags)}\n")
            out.write("\n")

            out.write("# --- Device Tree Blobs ---\n")
            for target, src, raw_cmd in self.dtb_targets:
                t_str = escape_ninja_path(target)
                s_str = escape_ninja_path(src) if src else ""
                out.write(f"build {t_str}: dtc {s_str} || {order_only_str}\n")
            out.write("\n")

            out.write("# --- C Compilations ---\n")
            for target, src, extra, full_flags in self.cc_targets:
                t_str = escape_ninja_path(target)
                s_str = escape_ninja_path(src)

                if target == f"{self.out_dir}/arch/arm64/kernel/vdso32/vgettimeofday.o":
                    out.write(f"build {t_str}: cc_vdso32 {s_str} || {order_only_str}\n")
                    out.write(f"  vdso32_cflags = {' '.join(full_flags)}\n")
                    continue

                extra_deps = []
                if target == f"{self.out_dir}/kernel/kheaders.o":
                    extra_deps.append(f"{self.out_dir}/kernel/kheaders_data.tar.xz")
                if target.startswith(f"{self.out_dir}/security/selinux/") and not target.endswith("flask.h"):
                    extra_deps.append(f"{self.out_dir}/security/selinux/flask.h")
                if target in (f"{self.out_dir}/arch/arm64/kernel/vdso.o",
                              f"{self.out_dir}/arch/arm64/kernel/signal.o",
                              f"{self.out_dir}/arch/arm64/kernel/signal32.o"):
                    extra_deps.extend([
                        f"{self.out_dir}/include/generated/vdso-offsets.h",
                        f"{self.out_dir}/include/generated/vdso32-offsets.h"
                    ])

                extra_deps_str = (" " + " ".join(escape_ninja_path(d) for d in extra_deps)) if extra_deps else ""
                out.write(f"build {t_str}: cc {s_str} || {order_only_str}{extra_deps_str}\n")
                if extra:
                    out.write(f"  extra_cflags = {' '.join(extra)}\n")
            out.write("\n")

            out.write("# --- Assembly Compilations ---\n")
            for target, src, extra, full_flags in self.asm_targets:
                t_str = escape_ninja_path(target)
                s_str = escape_ninja_path(src)

                if target == f"{self.out_dir}/arch/arm64/kernel/vdso32/sigreturn.o":
                    out.write(f"build {t_str}: as_vdso32 {s_str} || {order_only_str}\n")
                    out.write(f"  vdso32_aflags = {' '.join(full_flags)}\n")
                    continue

                implicit_deps = []
                if target == f"{self.out_dir}/arch/arm64/kernel/vdso/vdso.o":
                    implicit_deps.append(f"{self.out_dir}/arch/arm64/kernel/vdso/vdso.so")
                elif target == f"{self.out_dir}/arch/arm64/kernel/vdso32/vdso.o":
                    implicit_deps.append(f"{self.out_dir}/arch/arm64/kernel/vdso32/vdso.so")
                elif target == f"{self.out_dir}/certs/system_certificates.o":
                    implicit_deps.append(f"{self.out_dir}/certs/x509_certificate_list")
                elif target == f"{self.out_dir}/usr/initramfs_data.o":
                    implicit_deps.append(f"{self.out_dir}/usr/initramfs_data.cpio")

                implicit_str = (" | " + " ".join(escape_ninja_path(d) for d in implicit_deps)) if implicit_deps else ""
                out.write(f"build {t_str}: as {s_str}{implicit_str} || {order_only_str}\n")
                if extra:
                    out.write(f"  extra_aflags = {' '.join(extra)}\n")
            out.write("\n")

            out.write("# --- Subdirectory Archives ---\n")
            for target, inputs in self.ar_targets:
                t_str = escape_ninja_path(target)
                in_str = " ".join(escape_ninja_path(p) for p in inputs)
                out.write(f"build {t_str}: ar {in_str}\n")
            out.write("\n")

            candidate_top_dirs = [
                "init",
                "usr",
                "arch/arm64/kernel",
                "arch/arm64/mm",
                "arch/arm64/net",
                "arch/arm64/crypto",
                "kernel",
                "certs",
                "mm",
                "fs",
                "ipc",
                "security",
                "crypto",
                "block",
                "arch/arm64/lib",
                "lib",
                "drivers",
                "sound",
                "firmware",
                "net",
                "virt",
            ]
            top_builtin_components = [f"{self.out_dir}/arch/arm64/kernel/head.o"]
            ar_targets_set = {target for target, _ in self.ar_targets}
            for d in candidate_top_dirs:
                a_path = f"{self.out_dir}/{d}/built-in.a"
                if a_path in ar_targets_set or os.path.exists(a_path):
                    if a_path not in top_builtin_components:
                        top_builtin_components.append(a_path)
            top_ar_in = " ".join(top_builtin_components)
            out.write(f"build {self.out_dir}/built-in.a: ar {top_ar_in}\n\n")

            vmlinux_lds = f"{self.out_dir}/arch/arm64/kernel/vmlinux.lds"
            vmlinux_builtin = f"{self.out_dir}/built-in.a"
            vmlinux_libs = f"{self.out_dir}/arch/arm64/lib/lib.a {self.out_dir}/lib/lib.a"

            # Pass 0: Generate .btf.vmlinux.bin.o
            out.write(f"build {self.out_dir}/.btf.vmlinux.bin.o: gen_btf {vmlinux_lds} {vmlinux_builtin} {vmlinux_libs}\n")
            out.write(f"  lds = {vmlinux_lds}\n")
            out.write(f"  builtin = {vmlinux_builtin}\n")
            out.write(f"  libs = {vmlinux_libs}\n\n")

            # Pass 1: .tmp_vmlinux1 -> .tmp_kallsyms1.o
            out.write(f"build {self.out_dir}/.tmp_vmlinux1: ld_vmlinux {vmlinux_lds} {vmlinux_builtin} {vmlinux_libs} {self.out_dir}/.btf.vmlinux.bin.o\n")
            out.write(f"  lds = {vmlinux_lds}\n")
            out.write(f"  builtin = {vmlinux_builtin}\n")
            out.write(f"  libs = {vmlinux_libs}\n")
            out.write(f"  extra_objs = {self.out_dir}/.btf.vmlinux.bin.o\n\n")

            out.write(f"build {self.out_dir}/.tmp_kallsyms1.o: kallsyms {self.out_dir}/.tmp_vmlinux1 || {order_only_str}\n\n")

            # Pass 2: .tmp_vmlinux2 -> .tmp_kallsyms2.o
            out.write(f"build {self.out_dir}/.tmp_vmlinux2: ld_vmlinux {vmlinux_lds} {vmlinux_builtin} {vmlinux_libs} {self.out_dir}/.tmp_kallsyms1.o {self.out_dir}/.btf.vmlinux.bin.o\n")
            out.write(f"  lds = {vmlinux_lds}\n")
            out.write(f"  builtin = {vmlinux_builtin}\n")
            out.write(f"  libs = {vmlinux_libs}\n")
            out.write(f"  extra_objs = {self.out_dir}/.tmp_kallsyms1.o {self.out_dir}/.btf.vmlinux.bin.o\n\n")

            out.write(f"build {self.out_dir}/.tmp_kallsyms2.o: kallsyms {self.out_dir}/.tmp_vmlinux2 || {order_only_str}\n\n")

            # Final vmlinux link & post-processing
            out.write(f"build {self.out_dir}/vmlinux: ld_vmlinux_final {vmlinux_lds} {vmlinux_builtin} {vmlinux_libs} {self.out_dir}/.tmp_kallsyms2.o {self.out_dir}/.btf.vmlinux.bin.o\n")
            out.write(f"  lds = {vmlinux_lds}\n")
            out.write(f"  builtin = {vmlinux_builtin}\n")
            out.write(f"  libs = {vmlinux_libs}\n")
            out.write(f"  extra_objs = {self.out_dir}/.tmp_kallsyms2.o {self.out_dir}/.btf.vmlinux.bin.o\n\n")

            # Final kernel packaging
            out.write(f"build {self.out_dir}/arch/arm64/boot/Image: objcopy_image {self.out_dir}/vmlinux\n")
            out.write(f"build {self.out_dir}/arch/arm64/boot/Image.gz: gzip_image {self.out_dir}/arch/arm64/boot/Image\n\n")

            # Default targets
            out.write(f"default {self.out_dir}/arch/arm64/boot/Image {self.out_dir}/arch/arm64/boot/Image.gz\n")

        print(f"Successfully generated {self.output_path} ({os.path.getsize(self.output_path):,} bytes).")


def main():
    parser = argparse.ArgumentParser(description="Generate deterministic build.ninja from out/ .cmd files.")
    parser.add_argument("--out-dir", default="out", help="Kernel build output directory (default: out)")
    parser.add_argument("--output", default="build.ninja", help="Output ninja manifest (default: build.ninja)")
    parser.add_argument("--toolchain-dir", default=None, help="Path to Clang/LLVM toolchain bin directory")
    parser.add_argument("--no-ccache", action="store_true", help="Disable ccache wrapper")
    args = parser.parse_args()

    gen = NinjaGenerator(
        out_dir=args.out_dir,
        output=args.output,
        toolchain_dir=args.toolchain_dir,
        use_ccache=not args.no_ccache,
    )
    gen.scan_cmd_files()
    gen.generate()


if __name__ == "__main__":
    main()
