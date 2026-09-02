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
import hashlib
import json
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


# 模块名 → 相对 XS_TREE 的关键 .scala。换树 / 换提交必须让 SV 缓存失效，
# 否则报告会写新 XS_COMMIT 却复用旧网表。
_KEY_SCALA = {
    "CSRPermitModule":
        "src/main/scala/xiangshan/backend/fu/NewCSR/CSRPermitModule.scala",
    "TrapHandleModule":
        "src/main/scala/xiangshan/backend/fu/NewCSR/TrapHandleModule.scala",
    "TrapEntryMEventModule":
        "src/main/scala/xiangshan/backend/fu/NewCSR/CSREvents/TrapEntryMEvent.scala",
    "TrapEntryHSEventModule":
        "src/main/scala/xiangshan/backend/fu/NewCSR/CSREvents/TrapEntryHSEvent.scala",
    "TrapEntryVSEventModule":
        "src/main/scala/xiangshan/backend/fu/NewCSR/CSREvents/TrapEntryVSEvent.scala",
    "TrapEntryDEventModule":
        "src/main/scala/xiangshan/backend/fu/NewCSR/CSREvents/TrapEntryDEvent.scala",
    "TrapEntryMNEventModule":
        "src/main/scala/xiangshan/backend/fu/NewCSR/CSREvents/TrapEntryMNEvent.scala",
}


def _git_head(tree: str) -> str:
    if not tree or not os.path.isdir(tree):
        return ""
    r = subprocess.run(["git", "-C", tree, "rev-parse", "HEAD"],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def _file_fp(path: str) -> bytes:
    """路径 + mtime + size + 内容哈希。文件不存在也编进键，避免空树撞车。"""
    if not os.path.isfile(path):
        return b"missing:" + path.encode()
    st = os.stat(path)
    h = hashlib.sha256()
    h.update(f"{st.st_mtime_ns}:{st.st_size}:".encode())
    with open(path, "rb") as f:
        h.update(f.read())
    return h.digest()


def key_scala_paths(module: str) -> List[str]:
    rel = _KEY_SCALA.get(module)
    if not rel or not config.XS_TREE:
        return []
    return [os.path.join(config.XS_TREE, rel)]


def rtl_identity(module: str, overrides: Optional[List[str]] = None,
                 source_files: Optional[List[str]] = None) -> str:
    """RTL 树身份：路径、XS_COMMIT、git HEAD、关键/覆盖源文件。

    只按模块名缓存会在换 CSRFORMAL_XS_TREE / 换 commit / 换变异体源时
    静默复用旧 SV。12 位 hex 够分目录，也方便对照报告。
    """
    h = hashlib.sha256()
    tree = os.path.realpath(config.XS_TREE) if config.XS_TREE else ""
    h.update(b"tree:" + tree.encode())
    h.update(b"\0commit:" + (config.XS_COMMIT or "").encode())
    h.update(b"\0git:" + _git_head(config.XS_TREE).encode())
    h.update(b"\0module:" + module.encode())
    files = list(source_files or [])
    files.extend(key_scala_paths(module))
    if overrides:
        files.extend(overrides)
    for p in sorted(set(files)):
        real = os.path.realpath(p) if os.path.exists(p) else p
        h.update(b"\0file:" + real.encode())
        h.update(_file_fp(p))
    return h.hexdigest()[:12]


def cache_dir(tag: str, module: str, overrides: Optional[List[str]] = None,
              source_files: Optional[List[str]] = None) -> str:
    """out/<tag>/<rtl_id>/ —— 换树换源自动换目录，不靠 --rebuild。"""
    return os.path.join(config.OUT_DIR, tag,
                        rtl_identity(module, overrides, source_files))


def cache_hit(module: str, tag: str, overrides: Optional[List[str]] = None,
              source_files: Optional[List[str]] = None,
              force: bool = False) -> Optional[str]:
    """命中带身份戳的 SV 缓存则返回路径，否则 None。"""
    if force:
        return None
    key = rtl_identity(module, overrides, source_files)
    d = os.path.join(config.OUT_DIR, tag, key)
    sv = os.path.join(d, "m.sv")
    stamp = os.path.join(d, ".rtl_id")
    if os.path.exists(sv) and os.path.exists(stamp):
        with open(stamp, encoding="utf-8") as f:
            if f.read().strip() == key:
                return sv
    return None


def _run(cmd: List[str], log: Optional[str] = None, cwd: Optional[str] = None):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if log:
        with open(log, "w") as f:
            f.write(r.stdout + "\n" + r.stderr)
    return r


def build_harness_classes(force: bool = False) -> str:
    """编译 csrformal 自带的 Elab2 harness（只需一次）。

    harness 编过 XS classpath，换树不能复用旧 class。
    """
    dest = os.path.join(config.HARNESS_CLASSES, rtl_identity("harness"))
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
    with open(stamp, "w") as f:
        f.write(str(n))
    return dest


def elaborate(module: str, tag: str, overrides: Optional[List[str]] = None,
              force: bool = False, verbose: bool = True) -> str:
    """精化 `module`，产出 out/<tag>/<rtl_id>/m.sv 并返回其路径。

    overrides: 需要覆盖编译的 .scala 绝对路径列表（变异测试用）。
    缓存键含树路径 / commit / 关键源文件，换树不 --rebuild 也不会复用旧 SV。
    """
    hit = cache_hit(module, tag, overrides, force=force)
    if hit:
        if verbose:
            print(f"    缓存命中 {hit} (rtl_id={os.path.basename(os.path.dirname(hit))})",
                  flush=True)
        return hit
    d = cache_dir(tag, module, overrides)
    sv = os.path.join(d, "m.sv")
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
    key = rtl_identity(module, overrides)
    with open(os.path.join(d, ".rtl_id"), "w", encoding="utf-8") as f:
        f.write(key + "\n")
    # 给人看：这份 SV 是哪棵树精化出来的，避免报告写新 commit、磁盘却是旧网表。
    with open(os.path.join(d, ".rtl_meta.json"), "w", encoding="utf-8") as f:
        json.dump({
            "rtl_id": key,
            "xs_tree": config.XS_TREE,
            "xs_commit": config.XS_COMMIT,
            "git_head": _git_head(config.XS_TREE),
            "module": module,
            "tag": tag,
            "overrides": list(overrides or []),
        }, f, ensure_ascii=False, indent=2)
    if verbose:
        with open(sv) as f:
            print(f"    {sv} ({sum(1 for _ in f)} 行, rtl_id={key})", flush=True)
    return sv
