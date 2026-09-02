"""精化：Chisel 源码 → CHIRRTL → SystemVerilog。

为什么不精化整核
----------------
目标模块（CSRPermitModule / TrapHandleModule / InterruptFilter …）都是普通
`Module`，可以脱离 NewCSR 顶层单独实例化。用一个最小 harness 把它当 top，
精化只要秒级（TrapHandle ~3s，CSRPermit ~4s，MStatus ~17s，Mip ~54s）。
只有 trait 里的匿名 mixin 才必须走「精化整个 NewCSR 再切片」的贵路径。

为什么可以不跑 mill
------------------
cp.txt 里的 classpath 已经指向 XiangShan-b90dbba 编译好的 out/*。
要检查一个被改过（例如注入了变异）的源文件时，只用 scalac 单独编译它，
把产物目录放 classpath **最前面**覆盖同名 class 即可。

⚠️ 这里有个历史坑：scalac 静默失败时产物目录是空的，classpath 会回退到
原始 class，于是「注入的缺陷根本没进 RTL」，变异测试全部假通过，
从而得出「性质很强」的错误结论。所以必须硬校验退出码 **和** 产出的
.class 数量，两者缺一不可。
"""
import os
import shutil
import subprocess
from typing import List, Optional

from . import config

FIRTOOL_OPTS = [
    "--format=fir",
    "--lowering-options=disallowLocalVariables,disallowPackedArrays",
    # layer specialization 不 disable 的话，firtool 会把 Verification layer
    # 的内容留成 bind/`ifdef，yosys 读进来就是悬空模块。
    "--default-layer-specialization=disable",
    "--disable-all-randomization",
    "--strip-debug-info",
]


def _run(cmd: List[str], log: Optional[str] = None, cwd: Optional[str] = None):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if log:
        with open(log, "w") as f:
            f.write(r.stdout + "\n" + r.stderr)
    return r


def build_harness_classes(force: bool = False) -> str:
    """编译 csrformal 自带的 Elab2 harness（只需一次）。"""
    dest = config.HARNESS_CLASSES
    stamp = os.path.join(dest, ".ok")
    if os.path.exists(stamp) and not force:
        return dest
    os.makedirs(dest, exist_ok=True)
    cp = config.classpath()
    src = os.path.join(config.HARNESS_SRC, "eqcheck", "Elab2.scala")
    r = _run([config.JAVA, "-Xmx8g", "-cp", cp, "scala.tools.nsc.Main",
              f"-Xplugin:{config.CHISEL_PLUGIN}", "-language:reflectiveCalls",
              "-Ymacro-annotations", "-Ytasty-reader", "-classpath", cp,
              "-d", dest, src],
             log=os.path.join(config.OUT_DIR, "harness-compile.log"))
    n = sum(1 for _, _, fs in os.walk(dest) for f in fs if f.endswith(".class"))
    if r.returncode != 0 or n == 0:
        raise SystemExit(f"harness 编译失败 (rc={r.returncode}, classes={n})，"
                         f"见 {config.OUT_DIR}/harness-compile.log")
    open(stamp, "w").write(str(n))
    return dest


def elaborate(module: str, tag: str, overrides: Optional[List[str]] = None,
              force: bool = False, verbose: bool = True) -> str:
    """精化 `module`，产出 out/<tag>/m.sv 并返回其路径。

    overrides: 需要覆盖编译的 .scala 绝对路径列表（变异测试用）。
    """
    d = os.path.join(config.OUT_DIR, tag)
    sv = os.path.join(d, "m.sv")
    if os.path.exists(sv) and not force:
        return sv
    os.makedirs(d, exist_ok=True)

    harness = build_harness_classes()
    cp = config.classpath()
    cp_parts = [harness, cp]

    if overrides:
        odir = os.path.join(d, "classes")
        shutil.rmtree(odir, ignore_errors=True)
        os.makedirs(odir)
        if verbose:
            print(f"  覆盖编译 {len(overrides)} 个源文件 …", flush=True)
        r = _run([config.JAVA, "-Xmx8g", "-cp", cp, "scala.tools.nsc.Main",
                  f"-Xplugin:{config.CHISEL_PLUGIN}", "-language:reflectiveCalls",
                  "-Ymacro-annotations", "-Ytasty-reader", "-classpath", cp,
                  "-d", odir] + list(overrides),
                 log=os.path.join(d, "compile.log"))
        n = sum(1 for _, _, fs in os.walk(odir) for f in fs if f.endswith(".class"))
        # 双重硬校验，见模块 docstring
        if r.returncode != 0:
            raise SystemExit(f"scalac 失败 (rc={r.returncode})，见 {d}/compile.log")
        if n == 0:
            raise SystemExit(f"scalac 退出码为 0 但没产出任何 .class —— "
                             f"覆盖编译静默失败，拒绝继续（见 {d}/compile.log）")
        if verbose:
            print(f"    classes={n}", flush=True)
        cp_parts.insert(0, odir)

    fir = os.path.join(d, "m.fir")
    r = _run([config.JAVA, "-Xmx8g", "-cp", ":".join(cp_parts),
              "eqcheck.Elab2", module, fir], log=os.path.join(d, "elab.log"))
    if r.returncode != 0 or not os.path.exists(fir):
        raise SystemExit(f"精化 {module} 失败，见 {d}/elab.log")

    r = _run([config.FIRTOOL, fir] + FIRTOOL_OPTS + ["-o", sv],
             log=os.path.join(d, "firtool.log"))
    if r.returncode != 0 or not os.path.exists(sv):
        raise SystemExit(f"firtool 失败，见 {d}/firtool.log")
    if verbose:
        with open(sv) as f:
            print(f"    {sv} ({sum(1 for _ in f)} 行)", flush=True)
    return sv
