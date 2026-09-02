#!/usr/bin/env bash
# 从已编译的 XiangShan 工作树和 coursier 缓存拼出本机 cp.txt。
# 原因：classpath 全是绝对路径，进仓库对别人没用，还会暴露本机目录。
# 换机器仍需一份 mill 编过的香山树；本脚本不跑 mill，也不假装能一键精化。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${CSRFORMAL_CP:-$ROOT/cp.txt}"

if [[ -z "${CSRFORMAL_XS_TREE:-}" ]]; then
  echo "请设置 CSRFORMAL_XS_TREE，指向一份已编译的 XiangShan 工作树（含 out/）。" >&2
  exit 1
fi

XS="$(cd "$CSRFORMAL_XS_TREE" && pwd)"
if [[ ! -d "$XS/out" ]]; then
  echo "CSRFORMAL_XS_TREE=$XS 下没有 out/。先在香山树里 mill 编译，再跑本脚本。" >&2
  exit 1
fi

# coursier 缓存：环境变量优先，其次常见默认位置，再试香山树旁边的 firtool-cache。
CACHE_CANDIDATES=()
[[ -n "${COURSIER_CACHE:-}" ]] && CACHE_CANDIDATES+=("$COURSIER_CACHE")
CACHE_CANDIDATES+=("${HOME}/.cache/coursier/v1")
CACHE_CANDIDATES+=("${HOME}/Library/Caches/Coursier/v1")
[[ -n "${CSRFORMAL_COURSIER:-}" ]] && CACHE_CANDIDATES+=("$CSRFORMAL_COURSIER")

entries=()

# 香山 mill 产物：class 与 resource。排序保证可复现的拼接顺序。
while IFS= read -r d; do
  entries+=("$d")
done < <(find "$XS/out" -type d \( -name 'compile.dest' -o -path '*/compile.dest/classes' -o -name 'resources.dest' \) | sort)

# find 可能只命中 compile.dest 本身；优先用 classes 子目录。
refined=()
for d in "${entries[@]+"${entries[@]}"}"; do
  if [[ -d "$d/classes" ]]; then
    refined+=("$d/classes")
  else
    refined+=("$d")
  fi
done
entries=("${refined[@]+"${refined[@]}"}")

# 额外 jar 目录（scala-library / chisel-plugin 等，若不在 coursier 里）。
if [[ -n "${CSRFORMAL_JARS_DIR:-}" && -d "$CSRFORMAL_JARS_DIR" ]]; then
  while IFS= read -r j; do
    entries+=("$j")
  done < <(find "$CSRFORMAL_JARS_DIR" -type f -name '*.jar' | sort)
fi

found_cache=""
for c in "${CACHE_CANDIDATES[@]}"; do
  if [[ -d "$c" ]]; then
    found_cache="$c"
    break
  fi
done

if [[ -n "$found_cache" ]]; then
  # 只收 maven 坐标下的 jar，避免把无关缓存全塞进去。
  while IFS= read -r j; do
    entries+=("$j")
  done < <(find "$found_cache" -type f -name '*.jar' | sort)
fi

if [[ ${#entries[@]} -eq 0 ]]; then
  echo "没有收集到任何 classpath 条目。检查 $XS/out 和 coursier 缓存。" >&2
  exit 1
fi

IFS=':'
printf '%s\n' "${entries[*]}" > "$OUT"
unset IFS

n="${#entries[@]}"
echo "已写入 $OUT（$n 条）。这是本机绝对路径，不要 git add。"
if ! printf '%s\n' "${entries[@]}" | grep -q 'chisel-plugin'; then
  echo "警告：未找到 chisel-plugin jar。精化时请设 CSRFORMAL_CHISEL_PLUGIN。" >&2
fi
if ! printf '%s\n' "${entries[@]}" | grep -q 'scala-library'; then
  echo "警告：未找到 scala-library。把 jar 放到 CSRFORMAL_JARS_DIR 或 COURSIER_CACHE。" >&2
fi
if [[ -z "$found_cache" ]]; then
  echo "警告：未找到 coursier 缓存。可设 COURSIER_CACHE 或 CSRFORMAL_JARS_DIR。" >&2
fi
