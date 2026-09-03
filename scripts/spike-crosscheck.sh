#!/usr/bin/env bash
# 同一套 cex.S / 同一 --isa= 上跑 Spike 对照：M 态读 0x24D（NONE）以及
# HS+STCE=0 读 stimecmp（II）。需要报告时改用：
#   ./bin/csrformal spike-cex out/reports/compliance.json
# 宿主机 glibc 不够就进 docs/spike-crosscheck.md 里的具名容器。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/bin/csrformal" spike-cex --controls-only "$@"
