"""全局路径与外部工具配置。

默认不写本机绝对路径：clone 到另一台机器时用环境变量，不要改源码。
精化仍须自备已编译的香山树；CI / Docker 不提供 classpath。
"""
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _tool(env_name: str, exe: str) -> str:
    return os.environ.get(env_name) or shutil.which(exe) or exe


# ---- 外部工具（PATH 或环境变量；版本见 scripts/versions.txt）----
YOSYS = _tool("CSRFORMAL_YOSYS", "yosys")
FIRTOOL = _tool("CSRFORMAL_FIRTOOL", "firtool")
JAVA = _tool("CSRFORMAL_JAVA", "java")

# ---- XiangShan 工作树与 classpath ----
# cp.txt 是本机「已编译好的 XiangShan classpath」，指向 $CSRFORMAL_XS_TREE/out/*
# 与 coursier 缓存。有了它不必跑 mill 全量编译：只用 scalac 重编被改动的单个
# .scala，把产物目录放在 classpath 最前面覆盖即可。
# cp.txt 含绝对路径，不进仓库；用 scripts/gen-cp.sh 生成。
XS_TREE = os.environ.get("CSRFORMAL_XS_TREE", "")
XS_COMMIT = os.environ.get("CSRFORMAL_XS_COMMIT", "b90dbba4")
CLASSPATH_FILE = os.path.join(ROOT, "cp.txt")
CHISEL_PLUGIN = os.environ.get("CSRFORMAL_CHISEL_PLUGIN", "")

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
# 权威基线钉在恢复后的 menvcfg_stce_op2（含 or vstimecmp）。
# 2026-08-24 PR #3344 恢复原文；此处钉 2026-09-02 的 main，避免
# spec-baseline 默认把 EQ 规格拧回误删版。
BASELINE_REF = "a5be4cfb5aa9d4d325e43e066ce4aa0713b4a5c7"
# 误删了 “or vstimecmp” 的时点。只给 demo-spec-drift.sh 用，
# 不是 EQ 权威；禁止写入 spec/baseline.json。
DELETED_STCE_REF = "f20aa35ff0890991f8213a667658c7768f581bd1"


def classpath() -> str:
    if not os.path.exists(CLASSPATH_FILE):
        raise SystemExit(
            f"缺少 {CLASSPATH_FILE}。设 CSRFORMAL_XS_TREE 后运行 "
            "scripts/gen-cp.sh，或按 cp.txt.example 手工生成。"
            "不要把含本机绝对路径的 cp.txt 提交进仓库。")
    with open(CLASSPATH_FILE) as f:
        return f.read().strip()
