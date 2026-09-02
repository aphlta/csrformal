#!/usr/bin/env bash
# ============================================================================
# 自证 demo：一条命令复现「规范漂移检测」的真实案例
#
# 案例：norm:menvcfg_stce_op2（Sstc 的 menvcfg.STCE 门控）
#
#   2025-12-16  riscv-isa-manual PR #2504（纯文本搬运）**误删**了 "or vstimecmp"
#   2026-06-24  XiangShan PR #6129 与 NEMU PR #1093（同一作者，相隔 22 分钟）
#               照着被删后的文本改了实现：menvcfg.STCE 不再门控 vstimecmp
#   2026-08-20  riscv-isa-manual issue #3329 指出这是编辑事故
#   2026-08-24  PR #3344 恢复原文，当前 main 已是恢复后的文本
#
# 于是「照规范改的实现」被规范勘误反转，现在不合规了。这类事故靠人盯不住，
# 但只要每条性质记了规则 id + 原文哈希，工具就能机械地把它翻出来。
#
# 本脚本做三件事：
#   1. 把基线固定在 2026-06-14（f20aa35，实现作者当时看到的文本）
#   2. 跑 spec-drift 与当前 main 比对 → 应报出 norm:menvcfg_stce_op2 变了
#   3. 把「需要重新审阅」的性质拿去重跑当前 RTL → CSRPermit/S3 给出反例
# ============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CF="$ROOT/bin/csrformal"
REF="${1:-main}"

echo "########## 步骤 1/3：把规范基线固定在 2026-06 时点 ##########"
"$CF" spec-baseline --ref f20aa35ff0890991f8213a667658c7768f581bd1

echo
echo "########## 步骤 2/3：与 $REF 比对，检测规范漂移 ##########"
# spec-drift 发现漂移时退出码为 1，这里是预期结果，不能让 set -e 打断
set +e
"$CF" spec-drift --ref "$REF" --json "$ROOT/out/reports/spec-drift.json"
set -e

echo
echo "########## 步骤 3/3：用当前 RTL 重跑受影响的性质 ##########"
set +e
"$CF" check all --review "$ROOT/out/reports/spec-drift.json" \
      --report "$ROOT/out/reports/drift-review.md"
rc=$?
set -e

echo
echo "########## demo 结束 ##########"
echo "若 CSRPermit/S3 报出反例，说明：规范恢复了 'or vstimecmp'，"
echo "而 XiangShan 的 CSRPermitModule.scala:228-230 仍是被删后的写法，实现不再符合规范。"
exit $rc
