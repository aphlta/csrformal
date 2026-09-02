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

# 只认环境变量和 PATH。缺二进制则跳过，不假装存在一份本机安装。
_CANDIDATES = (
    os.environ.get("CSRFORMAL_SPIKE", ""),
    shutil.which("spike") or "",
)

SPIKE_SRC = os.environ.get("CSRFORMAL_SPIKE_SRC", "")


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
    src = (os.path.join(SPIKE_SRC, "riscv", "csrs.cc")
           if SPIKE_SRC else "riscv-isa-sim/riscv/csrs.cc")
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
        f"  已知 S3（HS, 0x24D, STCE=0）：Docker 实测 Spike=II，"
        f"见 docs/spike-crosscheck.md。本机若 spike 因 glibc 跑不起来，"
        f"跳过即可，不要把源码阅读写成实测。"
    )


# menvcfg 用地址 0x30A：Ubuntu 22.04 自带 binutils 2.35 还不认这个名字。
# tohost 必须带 fromhost，否则 fesvr 直接放弃 HTIF，裸机死循环。
# fesvr 把 tohost 低 48 位的奇数当退出码（payload>>1）；写成偶数会被当成
# syscall 参数块地址。所以把 mcause 编成 (mcause<<1)|1，进程退出码才是 mcause。
_ASM_TEMPLATE = r"""
# 最小裸机：M 态设 menvcfg.STCE，再 mret 到目标特权，访问指定 CSR。
    .option norvc
    .section .text
    .globl _start
_start:
    la   t0, _mtvec
    csrw mtvec, t0
    li   t0, {menv}
    csrw 0x30A, t0
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
    slli t0, t0, 1
    ori  t0, t0, 1
    la   t1, tohost
    sd   t0, 0(t1)
1:  j    1b

    .section .tohost, "aw", @progbits
    .align 6
    .globl tohost
tohost:
    .dword 0
    .align 6
    .globl fromhost
fromhost:
    .dword 0
"""


def _find_gcc() -> Optional[str]:
    env = os.environ.get("CSRFORMAL_RISCV_GCC")
    if env and os.path.isfile(env):
        return env
    return shutil.which("riscv64-unknown-elf-gcc")


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
    # KEEP：避免空 .tohost 被 gc。fromhost 与 tohost 同段，fesvr 两个都要。
    ld = (
        "OUTPUT_ARCH(riscv)\nENTRY(_start)\nSECTIONS { "
        ". = 0x80000000; .text : { *(.text) } "
        ". = 0x80001000; .tohost : { KEEP(*(.tohost)) } }\n"
    )
    lfile = os.path.join(work, "cex.ld")
    with open(lfile, "w", encoding="utf-8") as f:
        f.write(ld)
    # 汇编只用到 csr/mret，不需要 H。gcc 10 / 9 的 -march 还不认 h。
    compile_err = ""
    compiled = False
    for march in ("rv64gch", "rv64gc"):
        c = subprocess.run(
            [gcc, "-nostdlib", "-nostartfiles", f"-march={march}", "-mabi=lp64",
             "-T", lfile, sfile, "-o", elf],
            capture_output=True, text=True, timeout=30)
        if c.returncode == 0:
            compiled = True
            break
        compile_err = (c.stderr or c.stdout).strip()[:200]
    if not compiled:
        return SpikeVote(acc.pid, acc, None,
                         skipped=f"交叉编译失败：{compile_err}",
                         reading=classify(acc.rtl, acc.spec, None))
    # zicsr 在部分 spike 是隐含的；认不出就去掉再试一次。
    r = None
    run_err = ""
    for isa in ("rv64gch_zicsr_sstc", "rv64gch_sstc"):
        try:
            r = subprocess.run(
                [spike, f"--isa={isa}", elf],
                capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as e:
            run_err = str(e)
            continue
        log = (r.stdout or "") + (r.stderr or "")
        if "unsupported" in log.lower() or "invalid isa" in log.lower():
            run_err = log.strip()[:200]
            continue
        break
    if r is None:
        return SpikeVote(acc.pid, acc, None,
                         skipped=f"spike 子进程失败：{run_err}",
                         reading=classify(acc.rtl, acc.spec, None))
    log_path = os.path.join(work, "run.log")
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"# spike {' '.join(r.args)}\n# returncode={r.returncode}\n")
        f.write(r.stdout or "")
        f.write(r.stderr or "")
    # fesvr 退出码是 mcause；失败时还会印 "*** FAILED *** (tohost = N)"。
    cause = r.returncode
    m = re.search(r"tohost\s*=\s*(0x[0-9a-fA-F]+|\d+)",
                  (r.stdout or "") + (r.stderr or ""))
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
