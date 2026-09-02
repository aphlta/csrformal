#!/usr/bin/env bash
# 自证 demo：复现「规范漂移检测」的真实案例。
#
# 案例：norm:menvcfg_stce_op2（Sstc 的 menvcfg.STCE 门控）
#
#   2025-12-16  riscv-isa-manual PR #2504 误删了 “or vstimecmp”
#   2026-06-24  提交 94a4b91a 按被删后文本去掉 vstimecmp 门控，经 #6243 进 v3。
#               PR #6129 Closed 未 merge（与 NEMU #1093 同时段提出，不是进树路径）。
#   2026-08-20  isa-manual issue #3329 指出这是编辑事故
#   2026-08-24  PR #3344 恢复原文
#
# f20aa35 是误删文本，只给本 demo 用，不是 EQ / spec-baseline 的权威。
# 权威基线钉在恢复后的原文（spec/baseline.json，含 or vstimecmp）。
# 本脚本把 demo 基线写到 out/demo-baseline.json，不覆盖权威文件。
#
# 对照非 40 位 sha 的 ref（默认 main）需要宿主机 gh。Docker 镜像故意不装 gh。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CF="$ROOT/bin/csrformal"
REF="${1:-main}"
DEMO_BL="$ROOT/out/demo-baseline.json"

if ! command -v gh >/dev/null 2>&1; then
  if [[ ! "$REF" =~ ^[0-9a-f]{40}$ ]]; then
    echo "错误：找不到 gh，无法解析 ref=${REF}。" >&2
    echo "Docker 镜像故意不装 gh（避免镜像膨胀）。" >&2
    echo "请在宿主机安装 gh，或传入 40 位 sha：" >&2
    echo "  ./bin/demo-spec-drift.sh <40-char-sha>" >&2
    exit 1
  fi
fi

echo "步骤 1/3：把 demo 基线固定在误删时点 f20aa35（旁路文件，不是权威）"
"$CF" spec-baseline --ref f20aa35ff0890991f8213a667658c7768f581bd1 \
      --output "$DEMO_BL"

echo
echo "步骤 2/3：与 $REF 比对，检测规范漂移"
set +e
"$CF" spec-drift --ref "$REF" --baseline "$DEMO_BL" \
      --json "$ROOT/out/reports/spec-drift.json"
set -e

echo
echo "步骤 3/3：用当前 RTL 重跑受影响的性质"
set +e
"$CF" check all --review "$ROOT/out/reports/spec-drift.json" \
      --report "$ROOT/out/reports/drift-review.md"
rc=$?
set -e

echo
echo "demo 结束。若 CSRPermit/S3 或 EQ-permit 报反例，说明规范已恢复"
echo "or vstimecmp，而当前 RTL 仍是被删后的写法。"
exit $rc
