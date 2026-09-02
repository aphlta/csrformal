#!/usr/bin/env bash
# 自证 demo：复现「规范漂移检测」的真实案例。
#
# 案例：norm:menvcfg_stce_op2（Sstc 的 menvcfg.STCE 门控）
#
#   2025-12-16  riscv-isa-manual PR #2504 误删了 “or vstimecmp”
#   2026-06-24  XiangShan PR #6129 / NEMU PR #1093 照着被删后的文本改了实现
#   2026-08-20  isa-manual issue #3329 指出这是编辑事故
#   2026-08-24  PR #3344 恢复原文
#
# f20aa35 是误删文本，只给本 demo 用，不是 EQ / spec-baseline 的权威。
# 权威基线钉在恢复后的原文（spec/baseline.json，含 or vstimecmp）。
# 本脚本把 demo 基线写到 out/demo-baseline.json，不覆盖权威文件。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CF="$ROOT/bin/csrformal"
REF="${1:-main}"
DEMO_BL="$ROOT/out/demo-baseline.json"

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
