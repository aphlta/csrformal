"""规范规则库：从 riscv-isa-manual 的 asciidoc 里机械提取「规则 id → 原文」。

为什么需要这个模块
------------------
形式化性质本身没有权威性 —— 它的权威性完全来自「它忠实翻译了规范的哪一句话」。
如果性质只写一句中文注释「依据 machine.adoc」，那么：

  * 规范改了，没人知道哪些性质该重新审阅；
  * 性质写错了（把规范读歪），没有任何机制能发现；
  * 出报告时无法向第三方证明「这条判定的依据是什么」。

所以每条性质强制携带 (rule_id, 源文件, commit, 原文, 原文 sha256)。
原文哈希是核心：规范是活文档，一次纯文本搬运就可能悄悄改掉语义
（本工具的 demo 案例 norm:menvcfg_stce_op2 正是如此）。

asciidoc 里的两种锚点
--------------------
1) 行内锚点  ``[#norm:xxx]#规则正文…#``   —— 正文就在紧跟的一对 ``#`` 之间，
   可以跨行，以下一个未转义的 ``#`` 结束。
2) 块锚点    ``[[norm:xxx]]`` 独占一行 —— 规则正文是紧随其后的整个段落
   （到下一个空行 / 下一个锚点 / 下一个块指令为止）。

两种都要支持：hypervisor.adoc 的 hcounteren 用的是块锚点，
machine.adoc 的 menvcfg 用的是行内锚点。
"""
import hashlib
import json
import os
import re
import subprocess
import tarfile
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from . import config

INLINE_RE = re.compile(r"\[#(norm:[A-Za-z0-9_]+)\]#")
BLOCK_RE = re.compile(r"^\[\[(norm:[A-Za-z0-9_]+)\]\]\s*$")


def normalize(text: str) -> str:
    """比较用的规范化：折叠所有空白。

    asciidoc 的换行位置随编辑器折行而变，若不折叠空白，一次纯排版改动
    就会产生假的「规范漂移」告警，工具很快会被当成狼来了而无人理会。
    折叠后剩下的差异才是真正的用词变化。
    """
    return re.sub(r"\s+", " ", text).strip()


def text_hash(text: str) -> str:
    return hashlib.sha256(normalize(text).encode()).hexdigest()[:16]


@dataclass
class Rule:
    rule_id: str
    file: str          # 相对 src/ 的路径，如 priv/machine.adoc
    line: int          # 1-based
    text: str          # 原文（保留换行）
    kind: str          # inline | block

    @property
    def sha(self) -> str:
        return text_hash(self.text)


def extract_rules_from_text(src: str, relpath: str) -> Dict[str, Rule]:
    rules: Dict[str, Rule] = {}
    lines = src.splitlines()
    # 行号索引：为把字符偏移换算成行号
    offsets = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1

    def line_of(off: int) -> int:
        lo, hi = 0, len(offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if offsets[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    # --- 行内锚点 ---
    for m in INLINE_RE.finditer(src):
        rid = m.group(1)
        start = m.end()
        end = src.find("#", start)
        if end < 0:
            continue
        rules[rid] = Rule(rid, relpath, line_of(m.start()), src[start:end], "inline")

    # --- 块锚点 ---
    for i, ln in enumerate(lines):
        m = BLOCK_RE.match(ln)
        if not m:
            continue
        rid = m.group(1)
        if rid in rules:
            continue
        body: List[str] = []
        for nxt in lines[i + 1:]:
            if not nxt.strip():
                break
            if nxt.startswith("[[") or nxt.startswith("[#") or nxt.startswith("=="):
                break
            body.append(nxt)
        if body:
            rules[rid] = Rule(rid, relpath, i + 2, "\n".join(body), "block")
    return rules


# ---------------------------------------------------------------- 取源码树

def _tarball_path(ref: str) -> str:
    return os.path.join(config.SPEC_CACHE, f"{ref}.tar.gz")


def resolve_ref(ref: str) -> str:
    """把 main / 分支名 / tag 解析成 40 位 commit sha（已经是 sha 就原样返回）。"""
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return ref
    out = subprocess.run(
        ["gh", "api", f"repos/{config.SPEC_REPO}/commits/{ref}", "--jq", ".sha"],
        capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise SystemExit(f"无法解析 ref={ref}: {out.stderr.strip()}")
    return out.stdout.strip()


def commit_date(sha: str) -> str:
    out = subprocess.run(
        ["gh", "api", f"repos/{config.SPEC_REPO}/commits/{sha}",
         "--jq", ".commit.committer.date"],
        capture_output=True, text=True, timeout=120)
    return out.stdout.strip() if out.returncode == 0 else "?"


def ensure_tree(sha: str, quiet: bool = False) -> str:
    """确保 spec/cache/<sha>/ 下有解包好的 src/**.adoc，返回该目录。

    走 codeload tarball 而不是 git clone：这台机器上 git-over-HTTPS 到 github
    会超时，而 codeload 的 tar.gz 直链和 gh api 都通。
    """
    dest = os.path.join(config.SPEC_CACHE, sha)
    if os.path.isdir(os.path.join(dest, "src")):
        return dest
    os.makedirs(config.SPEC_CACHE, exist_ok=True)
    tb = _tarball_path(sha)
    if not os.path.exists(tb):
        if not quiet:
            print(f"  下载 {config.SPEC_REPO}@{sha[:12]} tarball …")
        url = f"https://codeload.github.com/{config.SPEC_REPO}/tar.gz/{sha}"
        r = subprocess.run(["curl", "-sSL", "-o", tb, url], timeout=600)
        if r.returncode != 0 or not os.path.exists(tb):
            raise SystemExit(f"下载失败: {url}")
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(tb) as tf:
        for m in tf.getmembers():
            parts = m.name.split("/", 1)
            if len(parts) != 2 or not parts[1].endswith(".adoc"):
                continue
            if not parts[1].startswith("src/"):
                continue
            m.name = parts[1]
            tf.extract(m, dest)
    return dest


def load_rules(sha: str, quiet: bool = False) -> Dict[str, Rule]:
    """把某个 commit 下 src/**/*.adoc 里的全部 norm: 规则读成 {id: Rule}。"""
    tree = ensure_tree(sha, quiet=quiet)
    root = os.path.join(tree, "src")
    rules: Dict[str, Rule] = {}
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".adoc"):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            with open(full, encoding="utf-8", errors="replace") as f:
                rules.update(extract_rules_from_text(f.read(), rel))
    return rules


# ---------------------------------------------------------------- 基线快照

@dataclass
class BaselineEntry:
    rule_id: str
    file: str
    line: int
    sha256: str
    text: str
    properties: List[str] = field(default_factory=list)


def write_baseline(ref: str, referenced: Dict[str, List[str]], path: str) -> dict:
    """把 `referenced`（rule_id → 引用它的性质 id 列表）在 ref 时点的原文快照下来。

    只快照被引用到的规则，不快照全部 726 条：基线文件是要进版本库、
    被人 review 的，塞进无关规则只会淹没信号。

    权威路径 spec/baseline.json 必须是恢复后的 menvcfg_stce_op2
    （含 vstimecmp）。误删时点 f20aa35 只能写到旁路文件。
    """
    sha = resolve_ref(ref)
    official = os.path.abspath(config.BASELINE_JSON)
    if os.path.abspath(path) == official:
        if sha.startswith(config.DELETED_STCE_REF[:12]) or \
                str(ref).startswith(config.DELETED_STCE_REF[:12]):
            raise SystemExit(
                "拒绝：f20aa35 是误删了 or vstimecmp 的文本，不是 EQ 权威基线。"
                "demo 请用 --output 写到旁路文件。")
    rules = load_rules(sha)
    entries, missing = {}, []
    for rid, props in sorted(referenced.items()):
        r = rules.get(rid)
        if r is None:
            missing.append(rid)
            continue
        entries[rid] = asdict(BaselineEntry(rid, r.file, r.line, r.sha, r.text, sorted(props)))
    if os.path.abspath(path) == official:
        stce = entries.get("norm:menvcfg_stce_op2")
        if stce is not None and "vstimecmp" not in stce["text"]:
            raise SystemExit(
                "拒绝：权威基线的 norm:menvcfg_stce_op2 必须含 vstimecmp"
                "（恢复后文本）。当前 ref 像是误删版。")
    doc = {
        "spec_repo": config.SPEC_REPO,
        "commit": sha,
        "commit_date": commit_date(sha),
        "rule_count": len(entries),
        "rules": entries,
        "unresolved": missing,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return doc


def load_baseline(path: Optional[str] = None) -> dict:
    path = path or config.BASELINE_JSON
    if not os.path.exists(path):
        raise SystemExit(f"基线不存在: {path}\n先跑: csrformal spec-baseline")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------- 漂移比对

@dataclass
class Drift:
    rule_id: str
    status: str        # CHANGED | REMOVED | MOVED | SAME
    old_text: str
    new_text: str
    old_sha: str
    new_sha: str
    old_loc: str
    new_loc: str
    properties: List[str]


def diff_against(baseline: dict, ref: str) -> (str, List[Drift]):
    sha = resolve_ref(ref)
    now = load_rules(sha)
    drifts: List[Drift] = []
    for rid, e in sorted(baseline["rules"].items()):
        cur = now.get(rid)
        old_loc = f"{e['file']}:{e['line']}"
        if cur is None:
            drifts.append(Drift(rid, "REMOVED", e["text"], "", e["sha256"], "",
                                old_loc, "-", e.get("properties", [])))
            continue
        new_loc = f"{cur.file}:{cur.line}"
        if cur.sha != e["sha256"]:
            st = "CHANGED"
        elif cur.file != e["file"]:
            st = "MOVED"
        else:
            st = "SAME"
        drifts.append(Drift(rid, st, e["text"], cur.text, e["sha256"], cur.sha,
                            old_loc, new_loc, e.get("properties", [])))
    return sha, drifts


def word_diff(old: str, new: str) -> str:
    """给出词级差异摘要，让人一眼看到「多了/少了哪几个词」。"""
    import difflib
    a, b = normalize(old).split(), normalize(new).split()
    out = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b).get_opcodes():
        if tag == "equal":
            continue
        if tag in ("delete", "replace"):
            out.append("- " + " ".join(a[i1:i2]))
        if tag in ("insert", "replace"):
            out.append("+ " + " ".join(b[j1:j2]))
    return "\n".join(out) if out else "(无词级差异)"
