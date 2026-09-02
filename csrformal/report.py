"""结构化结果 → JSON + 人可读的 Markdown 符合性报告。

摘要第一屏显式给出真空条数：只报「N 条全部通过」无法区分其中有多少条什么都没验证。
"""
import json
import os
import time
from typing import Dict, List

from . import runner
from .runner import Result

STATUS_CN = {
    runner.HOLDS: "通过",
    runner.VIOLATED: "反例",
    runner.VACUOUS: "真空（判为失败）",
    runner.UNKNOWN: "未知",
    runner.ERROR: "错误",
}


def to_json(results: List[Result], meta: Dict) -> Dict:
    return {
        "meta": meta,
        "summary": runner.summarize(results),
        "solver_seconds": round(runner.total_seconds(results), 3),
        "properties": [{
            "pid": r.prop.pid,
            "title": r.prop.title,
            "module": r.prop.module,
            "kind": r.prop.kind,
            "rule_id": r.prop.ref.rule_id,
            "rule_doc": r.prop.ref.doc,
            "rule_note": r.prop.ref.note,
            "status": r.status,
            "seconds": round(r.seconds, 4),
            "vacuity_seconds": round(r.vacuity_seconds, 4),
            "prove": r.prop.prove,
            "counterexample": r.counterexample,
            "outputs": r.outputs,
            "message": r.message,
        } for r in results],
    }


def write_json(results: List[Result], meta: Dict, path: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_json(results, meta), f, ensure_ascii=False, indent=2)
    return path


def write_markdown(results: List[Result], meta: Dict, path: str) -> str:
    s = runner.summarize(results)
    n = len(results)
    L = []
    L.append("# CSR 形式化规范符合性报告")
    L.append("")
    L.append(f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- RTL 工作树：`{meta.get('xs_tree')}` @ `{meta.get('xs_commit')}`")
    L.append(f"- 规范基线：`{meta.get('spec_repo')}` @ `{meta.get('spec_commit', '?')[:12]}`"
             f"（{meta.get('spec_date', '?')}）")
    L.append(f"- 被检查模块：{', '.join(meta.get('modules', []))}")
    L.append(f"- 求解器累计耗时：{runner.total_seconds(results):.2f} s；"
             f"壁钟总耗时：{meta.get('wall_seconds', 0):.1f} s")
    L.append("")
    L.append("## 摘要")
    L.append("")
    L.append("| 结论 | 条数 |")
    L.append("|---|---|")
    for k in (runner.HOLDS, runner.VIOLATED, runner.VACUOUS, runner.UNKNOWN, runner.ERROR):
        L.append(f"| {STATUS_CN[k]} | {s[k]} |")
    L.append(f"| **合计** | **{n}** |")
    L.append("")
    if s[runner.VACUOUS]:
        L.append(f"> 真空性门禁：{s[runner.VACUOUS]} 条性质假设集自相矛盾，判为失败。"
                 f"真空的性质不验证任何东西，需修好假设集后重跑。")
    else:
        L.append("> 真空性门禁：0 条真空，每一条「通过」的假设集均可满足。")
    L.append("")

    # ---- 规范追溯表 ----
    L.append("## 规范规则追溯")
    L.append("")
    by_rule: Dict[str, List[Result]] = {}
    for r in results:
        by_rule.setdefault(r.prop.ref.label(), []).append(r)
    L.append("| 规则 id / 出处 | 性质数 | 通过 | 未通过 |")
    L.append("|---|---|---|---|")
    for k in sorted(by_rule):
        grp = by_rule[k]
        ok = sum(1 for r in grp if r.ok)
        L.append(f"| `{k}` | {len(grp)} | {ok} | {len(grp) - ok} |")
    L.append("")
    noid = [r for r in results if r.prop.ref.rule_id is None]
    if noid:
        L.append(f"其中 {len(noid)} 条性质没有可机械追溯的规则 id，原因如下："
                 f"（不凑 id，错误的 id 会让 `spec-drift` 比对错误的段落）")
        L.append("")
        seen = set()
        for r in noid:
            key = (r.prop.ref.doc, r.prop.ref.note)
            if key in seen:
                continue
            seen.add(key)
            cnt = sum(1 for x in noid if (x.prop.ref.doc, x.prop.ref.note) == key)
            L.append(f"- **{r.prop.ref.doc}**（{cnt} 条）：{r.prop.ref.note}")
        L.append("")

    # ---- 未通过详情 ----
    bad = [r for r in results if not r.ok]
    L.append("## 未通过的性质")
    L.append("")
    if not bad:
        L.append("无。")
    for r in bad:
        L.append(f"### `{r.prop.pid}` — {r.prop.title}")
        L.append("")
        L.append(f"- 结论：**{STATUS_CN[r.status]}**")
        L.append(f"- 规范依据：`{r.prop.ref.label()}`"
                 + (f" — {r.prop.ref.note}" if r.prop.ref.note else ""))
        L.append(f"- 待证公式：`{r.prop.prove}`")
        if r.message:
            L.append(f"- 说明：{r.message}")
        if r.counterexample:
            L.append("")
            L.append("反例（仅列非默认输入）：")
            L.append("")
            L.append("```")
            for k, v in r.counterexample.items():
                L.append(f"  {k} = {v}")
            L.append("  ---- 输出 ----")
            for k, v in r.outputs.items():
                L.append(f"  {k} = {v}")
            L.append("```")
        L.append("")

    # ---- 全量清单 ----
    L.append("## 全部性质清单")
    L.append("")
    L.append("| pid | 结论 | 秒 | 规则 id | 说明 |")
    L.append("|---|---|---|---|---|")
    for r in results:
        rid = r.prop.ref.rule_id or "—"
        L.append(f"| `{r.prop.pid}` | {STATUS_CN[r.status]} | {r.seconds:.2f} "
                 f"| `{rid}` | {r.prop.title} |")
    L.append("")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    return path
