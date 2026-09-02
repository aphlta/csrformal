"""Spike 反例定性：形式化找到反例后，用同一组输入问 Spike 的 CSR 权限。

不穷举。缺 spike / 工具链时跳过，不假装跑过。
"""
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

from . import config

# 本机常见位置；真正能不能跑还要 --help 探测（glibc 不对会在这里失败）。
_CANDIDATES = (
    os.environ.get("CSRFORMAL_SPIKE", ""),
    shutil.which("spike") or "",
    "/ssdhome/maoweiming/riscv64-ai-agent/third_party/tools/riscv-toolchain-stub/bin/spike",
)

SPIKE_SRC = os.environ.get(
    "CSRFORMAL_SPIKE_SRC",
    "/ssdhome/maoweiming/xiangshan-work/issues/1872/riscv-isa-sim")


@dataclass
class CexAccess:
    """一次 CSR 访问的语义化输入，够 Spike 定性即可。"""
    pid: str
    addr: int
    prvm: int
    v: bool
    wen: bool
    ren: bool
    menvcfg_stce: bool
    rtl: str = ""
    spec: str = ""


@dataclass
class SpikeVote:
    pid: str
    access: CexAccess
    spike: Optional[str]          # II / VI / NONE；None = 没跑
    skipped: str = ""             # 跳过原因
    reading: str = ""             # 三方判读


def find_spike() -> Optional[str]:
    for p in _CANDIDATES:
        if not p or not os.path.isfile(p):
            continue
        try:
            r = subprocess.run([p, "--help"], capture_output=True, text=True,
                               timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0 or "Spike RISC-V" in (r.stdout + r.stderr):
            return p
    return None


def _parse_hex_prefix(s: str) -> Optional[int]:
    m = re.match(r"\s*(0x[0-9a-fA-F]+)", s)
    if m:
        return int(m.group(1), 16)
    m = re.match(r"\s*(\d+)", s)
    return int(m.group(1)) if m else None


def _parse_bool(s: str, default: bool = False) -> bool:
    t = str(s).strip().lower()
    if t in ("true", "1", "yes"):
        return True
    if t in ("false", "0", "no"):
        return False
    return default


def parse_cex(pid: str, cex: Dict[str, str], outputs: Optional[Dict] = None) -> Optional[CexAccess]:
    """从 compliance.json 的 counterexample 抽出 priv/addr/wen/STCE。"""
    addr = None
    if "译.addr" in cex:
        addr = _parse_hex_prefix(cex["译.addr"])
    elif "io_in_csrAccess_addr" in cex:
        addr = _parse_hex_prefix(cex["io_in_csrAccess_addr"])
    if addr is None:
        return None

    prvm, v = 1, False
    if "译.priv" in cex:
        name = cex["译.priv"].strip()
        table = {"M": (3, False), "HS": (1, False), "HU": (0, False),
                 "VS": (1, True), "VU": (0, True)}
        if name in table:
            prvm, v = table[name]
    else:
        raw = cex.get("io_in_privState_PRVM", "0x1")
        prvm = _parse_hex_prefix(raw) if _parse_hex_prefix(raw) is not None else 1
        v = _parse_bool(cex.get("io_in_privState_V", "False"))

    wen = _parse_bool(cex.get("io_in_csrAccess_wen", "False"))
    ren = _parse_bool(cex.get("io_in_csrAccess_ren", "False"))
    if "译.acc" in cex:
        acc = cex["译.acc"]
        wen = "w" in acc
        ren = "r" in acc or acc.strip() == "r"

    menv_stce = True
    if "译.STCE" in cex:
        m = re.search(r"menvcfg\.STCE=(\d)", cex["译.STCE"])
        if m:
            menv_stce = m.group(1) == "1"
    elif "io_in_xenvcfg_menvcfg" in cex:
        val = _parse_hex_prefix(cex["io_in_xenvcfg_menvcfg"])
        if val is not None:
            menv_stce = bool((val >> 63) & 1)

    rtl, spec = "", ""
    if "译.rtl" in cex:
        rtl = cex["译.rtl"].strip()
    elif outputs:
        if _parse_bool(str(outputs.get("io_out_EX_II", "False"))):
            rtl = "II"
        elif _parse_bool(str(outputs.get("io_out_EX_VI", "False"))):
            rtl = "VI"
        else:
            rtl = "NONE"
    if "译.spec" in cex:
        spec = cex["译.spec"].strip()

    return CexAccess(pid=pid, addr=addr, prvm=prvm, v=v, wen=wen, ren=ren,
                     menvcfg_stce=menv_stce, rtl=rtl, spec=spec)


def classify(rtl: str, spec: str, spike: Optional[str]) -> str:
    if not spike:
        return "Spike 未跑，只留 RTL/spec 双方"
    if rtl and spec and rtl != spec and spike == spec:
        return "RTL bug（Spike 与 spec 一致、与 RTL 不一致）"
    if rtl and spec and rtl != spec and spike == rtl:
        return "规格可疑（Spike 与 RTL 一致、与 spec 不一致）"
    if rtl and spec and rtl == spec and spike != spec:
        return "Spike 分歧（RTL 与 spec 一致）"
    if rtl and spec and rtl == spec and spike == spec:
        return "三方一致"
    return f"RTL={rtl or '—'} spec={spec or '—'} Spike={spike}"


def _mode_name(prvm: int, v: bool) -> str:
    if prvm == 3 and not v:
        return "M"
    if prvm == 1 and not v:
        return "HS"
    if prvm == 0 and not v:
        return "HU"
    if prvm == 1 and v:
        return "VS"
    if prvm == 0 and v:
        return "VU"
    return f"PRVM={prvm},V={int(v)}"


def manual_steps(acc: CexAccess) -> str:
    """本机没有能跑的 spike 时，给出同一组输入的手工复现步骤。"""
    mode = _mode_name(acc.prvm, acc.v)
    accs = "w" if acc.wen and not acc.ren else (
        "rw" if acc.wen and acc.ren else ("r" if acc.ren else "—"))
    src = os.path.join(SPIKE_SRC, "riscv", "csrs.cc")
    return (
        f"输入：{_mode_name(acc.prvm, acc.v)} addr=0x{acc.addr:03x} "
        f"acc={accs} menvcfg.STCE={int(acc.menvcfg_stce)}\n"
        f"  1. 用 riscv64-unknown-elf-gcc 编一段裸机：M 态写 menvcfg.STCE="
        f"{int(acc.menvcfg_stce)}，再 mret 进 {mode}，"
        f"{'csrw' if acc.wen else 'csrr'} 0x{acc.addr:03x}。\n"
        f"  2. spike --isa=rv64gch_sstc <elf>，看 mcause：2=II，22=VI。\n"
        f"  3. 源码对照（不跑也能定性）：{src}\n"
        f"     stimecmp_csr_t::verify_permissions 第一项："
        f"menvcfg.STCE=0 且 prv<M → illegal_instruction。"
        f"vstimecmp 与 stimecmp 共用此类。\n"
        f"  已知 S3（HS, 0x24D, STCE=0）：按源码 Spike=II，"
        f"与恢复后 spec 一致、与 b90dbba RTL 不一致 → RTL bug。"
        f"本环境若 spike 因 glibc 跑不起来，不要把这句写成实测数字。"
    )


_ASM_TEMPLATE = r"""
# 最小裸机：M 态设 menvcfg.STCE，再 mret 到目标特权，访问指定 CSR。
# 陷入则把 mcause 写入 tohost（spike 退出码）；没陷入写 0。
    .option norvc
    .section .text
    .globl _start
_start:
    la   t0, _mtvec
    csrw mtvec, t0
    li   t0, {menv}
    csrw menvcfg, t0
    # mstatus.MPP = {mpp}（bits 12:11）；MPV = {mpv}（bit 39）
    li   t0, {mstatus}
    csrw mstatus, t0
    la   t0, _guest
    csrw mepc, t0
    mret

_guest:
    {csr_insn} t0, {addr}
    li   t0, 0
    j    _exit

_mtvec:
    csrr t0, mcause
_exit:
    la   t1, tohost
    sd   t0, 0(t1)
1:  j    1b

    .section .tohost, "aw", @progbits
    .align 6
    .globl tohost
tohost:
    .dword 0
"""


def _find_gcc() -> Optional[str]:
    env = os.environ.get("CSRFORMAL_RISCV_GCC")
    if env and os.path.isfile(env):
        return env
    w = shutil.which("riscv64-unknown-elf-gcc")
    if w:
        return w
    known = "/ssdhome/maoweiming/alearn/boot/toolchains/sysroot/usr/bin/riscv64-unknown-elf-gcc"
    return known if os.path.isfile(known) else None


def _mcause_to_verdict(cause: int) -> str:
    # 最高位是中断标志；CSR 权限失败是同步异常。
    code = cause & 0xFF
    if code == 2:
        return "II"
    if code == 22:
        return "VI"
    if cause == 0:
        return "NONE"
    return f"mcause={cause}"


def _run_baremetal(acc: CexAccess, spike: str, gcc: str) -> SpikeVote:
    """编一小段裸机，子进程跑 spike。失败就跳过，不装作成绩。"""
    mpp = 3 if acc.prvm == 3 else (1 if acc.prvm == 1 else 0)
    mpv = 1 if acc.v else 0
    mstatus = (mpp << 11) | (mpv << 39)
    menv = 0 if not acc.menvcfg_stce else (1 << 63)
    csr_insn = "csrw" if acc.wen else "csrr"
    asm = _ASM_TEMPLATE.format(
        menv=hex(menv), mpp=mpp, mpv=mpv, mstatus=hex(mstatus),
        csr_insn=csr_insn, addr=hex(acc.addr))
    work = os.path.join(config.OUT_DIR, "spike-cex")
    os.makedirs(work, exist_ok=True)
    sfile = os.path.join(work, "cex.S")
    elf = os.path.join(work, "cex.elf")
    with open(sfile, "w", encoding="utf-8") as f:
        f.write(asm)
    ld = (
        "OUTPUT_ARCH(riscv)\nENTRY(_start)\nSECTIONS { "
        ". = 0x80000000; .text : { *(.text) } "
        ". = 0x80001000; .tohost : { *(.tohost) } }\n"
    )
    lfile = os.path.join(work, "cex.ld")
    with open(lfile, "w", encoding="utf-8") as f:
        f.write(ld)
    c = subprocess.run(
        [gcc, "-nostdlib", "-nostartfiles", "-march=rv64gch", "-mabi=lp64",
         "-T", lfile, sfile, "-o", elf],
        capture_output=True, text=True, timeout=30)
    if c.returncode != 0:
        return SpikeVote(acc.pid, acc, None,
                         skipped=f"交叉编译失败：{(c.stderr or c.stdout).strip()[:200]}",
                         reading=classify(acc.rtl, acc.spec, None))
    r = subprocess.run(
        [spike, "--isa=rv64gch_zicsr_sstc", elf],
        capture_output=True, text=True, timeout=20)
    # spike 把 tohost 当退出码；有的版本打印 tohost。两边都认。
    cause = r.returncode
    m = re.search(r"tohost\s*=\s*(0x[0-9a-fA-F]+|\d+)", r.stdout + r.stderr)
    if m:
        cause = int(m.group(1), 0)
    verdict = _mcause_to_verdict(cause)
    return SpikeVote(acc.pid, acc, verdict, skipped="",
                     reading=classify(acc.rtl, acc.spec, verdict))


def query_spike(acc: CexAccess) -> SpikeVote:
    """尝试对这一组输入跑 Spike。编不了 / 找不到二进制就跳过。"""
    spike = find_spike()
    if spike is None:
        return SpikeVote(acc.pid, acc, None,
                         skipped="本机没有能运行的 spike（未安装，或 glibc 不够）",
                         reading=classify(acc.rtl, acc.spec, None))
    gcc = _find_gcc()
    if not gcc:
        return SpikeVote(acc.pid, acc, None,
                         skipped=f"找到 spike={spike}，但没有 riscv64-unknown-elf-gcc",
                         reading=classify(acc.rtl, acc.spec, None))
    try:
        return _run_baremetal(acc, spike, gcc)
    except (OSError, subprocess.TimeoutExpired) as e:
        return SpikeVote(acc.pid, acc, None,
                         skipped=f"spike 子进程失败：{e}",
                         reading=classify(acc.rtl, acc.spec, None))


def votes_from_report(doc: dict) -> List[SpikeVote]:
    out = []
    for p in doc.get("properties", []):
        if p.get("status") != "VIOLATED":
            continue
        acc = parse_cex(p.get("pid", "?"), p.get("counterexample") or {},
                        p.get("outputs") or {})
        if acc is None:
            continue
        if not acc.spec:
            # case 层没有译.spec：S3 的期望就是 II
            if p.get("prove") == "io_out_EX_II":
                acc.spec = "II"
            elif "EX_VI" in (p.get("prove") or ""):
                acc.spec = "VI"
        if not acc.rtl:
            outs = p.get("outputs") or {}
            if str(outs.get("io_out_EX_II", "")).lower() == "true":
                acc.rtl = "II"
            elif str(outs.get("io_out_EX_VI", "")).lower() == "true":
                acc.rtl = "VI"
            else:
                acc.rtl = "NONE"
        out.append(query_spike(acc))
    return out


def print_votes(votes: List[SpikeVote]) -> None:
    if not votes:
        print("没有可解析的 VIOLATED 反例。")
        return
    for v in votes:
        a = v.access
        print(f"  {v.pid}: {_mode_name(a.prvm, a.v)} 0x{a.addr:03x} "
              f"STCE={int(a.menvcfg_stce)}  RTL={a.rtl or '—'} "
              f"spec={a.spec or '—'}  Spike={v.spike or '未跑'}")
        print(f"    判读：{v.reading}")
        if v.skipped:
            print(f"    跳过：{v.skipped}")
        print("    手工步骤：")
        for ln in manual_steps(a).splitlines():
            print("    " + ln)
