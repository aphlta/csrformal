"""全局路径与外部工具配置。

所有路径集中在这里，方便别人 clone 到别的机器后只改一处。
环境变量优先，便于 CI / 其它机器覆盖而不改代码。
"""
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---- 外部工具 ----
YOSYS = os.environ.get(
    "CSRFORMAL_YOSYS", "/ssdhome/maoweiming/anaconda3/envs/eqcheck/bin/yosys")
FIRTOOL = os.environ.get(
    "CSRFORMAL_FIRTOOL",
    "/ssdhome/maoweiming/xiangshan-work/firtool-cache/llvm-firtool/1.135.0/bin/firtool")
JAVA = os.environ.get("CSRFORMAL_JAVA", shutil.which("java") or "java")

# ---- XiangShan 工作树与 classpath ----
# cp.txt 是一份「已编译好的 XiangShan 全量 classpath」（74 条，指向
# XiangShan-b90dbba/out/* 与 coursier 缓存）。有了它就不必跑 mill 全量编译：
# 只用 scalac 重编被改动的单个 .scala，把产物目录放在 classpath 最前面覆盖即可。
# 这是把「一次精化」从分钟级压到秒级的关键。
XS_TREE = os.environ.get(
    "CSRFORMAL_XS_TREE", "/ssdhome/maoweiming/xiangshan-work/XiangShan-b90dbba")
XS_COMMIT = os.environ.get("CSRFORMAL_XS_COMMIT", "b90dbba4")
CLASSPATH_FILE = os.path.join(ROOT, "cp.txt")
CHISEL_PLUGIN = os.environ.get(
    "CSRFORMAL_CHISEL_PLUGIN",
    "/ssdhome/maoweiming/eqcheck-scratch/jars2/chisel-plugin_2.13.17-7.3.0.jar")

# ---- 目录 ----
OUT_DIR = os.environ.get("CSRFORMAL_OUT", os.path.join(ROOT, "out"))
SPEC_DIR = os.path.join(ROOT, "spec")
SPEC_CACHE = os.path.join(SPEC_DIR, "cache")
BASELINE_JSON = os.path.join(SPEC_DIR, "baseline.json")
HARNESS_SRC = os.path.join(ROOT, "src")
HARNESS_CLASSES = os.path.join(OUT_DIR, "_harness_classes")
MUTANT_SRC_DIR = os.path.join(ROOT, "mutants-src")

# ---- 规范仓库 ----
SPEC_REPO = "riscv/riscv-isa-manual"
# 基线固定在 2026-06-14（f20aa35）：这是香山 PR #6129（2026-06-24 改实现）
# 之前最后一次动 machine.adoc 的提交，代表「实现作者当时看到的规范文本」。
BASELINE_REF = "f20aa35ff0890991f8213a667658c7768f581bd1"


def classpath() -> str:
    with open(CLASSPATH_FILE) as f:
        return f.read().strip()
