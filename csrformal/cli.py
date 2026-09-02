"""csrformal 命令行入口。

  csrformal check <模块|all>     精化 → 转 SMT → 跑全部性质 → 出报告
  csrformal list [模块]          列出已注册的性质
  csrformal rules                列出被引用的规范规则 id 及其原文
  csrformal lint                 静态自检：性质元数据是否齐全、规则 id 是否真存在
  csrformal spec-baseline        把当前被引用的规则原文快照成基线
  csrformal spec-drift           基线 vs 指定版本的规范漂移检测
  csrformal self-test            变异回归：注入已知缺陷，确认对应性质能杀死它
  csrformal spike                多参照交叉检查（Spike）—— 目前只有接口与设计说明
"""
import argparse
import json
import os
import sys
import time

from . import config, elaborate, modules, report, runner, specdb


def _smt2_path(tag: str) -> str:
    return os.path.join(config.OUT_DIR, tag, "c.smt2")


def _select(props, only, pids=None):
    """--pids 走精确匹配，是给 spec-drift 的产物直接喂进来用的；
    --only 走子串匹配，是给人手工调试用的。"""
    if pids:
        want = set(pids)
        return [p for p in props if p.pid in want]
    if not only:
        return props
    sel = [p for p in props if only.lower() in p.pid.lower()]
    if not sel:
        raise SystemExit(f"--only {only!r} 没有匹配到任何性质；用 `csrformal list` 查看")
    return sel


# ------------------------------------------------------------------ check

def cmd_check(args):
    names = sorted(modules.all_modules()) if args.module == "all" else [args.module]
    pids = None
    if args.review:
        # 直接消费 spec-drift 的产物：只重跑「因规范变化而需要重新审阅」的性质。
        with open(args.review, encoding="utf-8") as f:
            pids = json.load(f)["affected_properties"]
        print(f"从 {args.review} 读到 {len(pids)} 条待重新审阅的性质")
    wall0 = time.time()
    all_results, meta_mods = [], []
    for name in names:
        spec = modules.get(name)
        props = _select(spec.props, args.only, pids)
        if not props:
            continue
        print(f"\n=== {name} ({len(props)} 条性质) ===", flush=True)
        print("  精化 …", flush=True)
        sv = elaborate.elaborate(name, f"base_{name}", force=args.rebuild)
        r = runner.ModuleRunner(sv, name, _smt2_path(f"base_{name}"))
        all_results += r.run(props)
        meta_mods.append(name)

    s = runner.summarize(all_results)
    wall = time.time() - wall0
    baseline = {}
    if os.path.exists(config.BASELINE_JSON):
        baseline = specdb.load_baseline()
    meta = {
        "xs_tree": config.XS_TREE, "xs_commit": config.XS_COMMIT,
        "spec_repo": config.SPEC_REPO,
        "spec_commit": baseline.get("commit", "(无基线)"),
        "spec_date": baseline.get("commit_date", "?"),
        "modules": meta_mods, "wall_seconds": wall,
    }
    md = args.report or os.path.join(config.OUT_DIR, "reports", "compliance.md")
    js = os.path.splitext(md)[0] + ".json"
    report.write_markdown(all_results, meta, md)
    report.write_json(all_results, meta, js)

    print(f"\n==== 共 {len(all_results)} 条：通过 {s[runner.HOLDS]}，"
          f"反例 {s[runner.VIOLATED]}，真空 {s[runner.VACUOUS]}，"
          f"未知 {s[runner.UNKNOWN]}，错误 {s[runner.ERROR]} ====")
    print(f"求解器累计 {runner.total_seconds(all_results):.2f}s，壁钟 {wall:.1f}s")
    print(f"报告：{md}\n结构化结果：{js}")
    for r in all_results:
        if not r.ok:
            print(f"\n---- {r.status} {r.prop.pid}: {r.prop.title}")
            print(f"     规范依据 {r.prop.ref.label()}")
            if r.message:
                print(f"     {r.message}")
            for k, v in list(r.counterexample.items())[:40]:
                print(f"       {k} = {v}")
            for k, v in r.outputs.items():
                print(f"       [out] {k} = {v}")
    return 1 if (s[runner.VIOLATED] or s[runner.VACUOUS] or s[runner.ERROR]) else 0


# ------------------------------------------------------------------ list / rules / lint

def cmd_list(args):
    for name, spec in sorted(modules.all_modules().items()):
        if args.module and args.module != name:
            continue
        print(f"\n=== {name} — {spec.doc}  ({len(spec.props)} 条) ===")
        for p in spec.props:
            print(f"  {p.pid:36s} [{p.ref.rule_id or '无规则 id'}] {p.title}")
    return 0


def referenced_rules():
    """rule_id → 引用它的性质 pid 列表。"""
    out = {}
    for p in modules.all_properties():
        if p.ref.rule_id:
            out.setdefault(p.ref.rule_id, []).append(p.pid)
    return out


def cmd_rules(args):
    ref = referenced_rules()
    bl = specdb.load_baseline() if os.path.exists(config.BASELINE_JSON) else {"rules": {}}
    print(f"被引用的规范规则：{len(ref)} 条（基线 {bl.get('commit', '-')[:12]}）\n")
    for rid, pids in sorted(ref.items()):
        e = bl["rules"].get(rid)
        loc = f"{e['file']}:{e['line']}" if e else "(不在基线里)"
        print(f"{rid}  [{loc}]  ← {len(pids)} 条性质")
        if e and args.text:
            print("    " + specdb.normalize(e["text"])[:300])
    noid = [p for p in modules.all_properties() if not p.ref.rule_id]
    print(f"\n无规则 id 的性质：{len(noid)} 条")
    seen = set()
    for p in noid:
        if p.ref.doc in seen:
            continue
        seen.add(p.ref.doc)
        print(f"  - {p.ref.doc}: {p.ref.note}")
    return 0


def cmd_lint(args):
    """静态自检：元数据齐全性 + 规则 id 是否在规范里真实存在。

    这是 spec-drift 能工作的前提：一个拼错的规则 id 会静默地永远 “没漂移”。
    """
    bad = 0
    props = modules.all_properties()
    seen = set()
    for p in props:
        if p.pid in seen:
            print(f"  [重复 pid] {p.pid}")
            bad += 1
        seen.add(p.pid)
        if p.ref.rule_id is None and not p.ref.note:
            print(f"  [缺 note] {p.pid}")
            bad += 1
    sha = specdb.resolve_ref(args.ref)
    rules = specdb.load_rules(sha)
    for rid, pids in sorted(referenced_rules().items()):
        if rid not in rules:
            print(f"  [规则 id 不存在于 {args.ref}] {rid}  ← {len(pids)} 条性质")
            bad += 1
    print(f"\n性质 {len(props)} 条，引用规则 {len(referenced_rules())} 条，"
          f"规范 {args.ref[:12]} 共 {len(rules)} 条规则。问题 {bad} 处。")
    return 1 if bad else 0


# ------------------------------------------------------------------ 规范基线 / 漂移

def cmd_spec_baseline(args):
    doc = specdb.write_baseline(args.ref, referenced_rules(), config.BASELINE_JSON)
    print(f"基线已写入 {config.BASELINE_JSON}")
    print(f"  {config.SPEC_REPO} @ {doc['commit'][:12]}  ({doc['commit_date']})")
    print(f"  快照规则 {doc['rule_count']} 条")
    if doc["unresolved"]:
        print(f"  ⚠️ 有 {len(doc['unresolved'])} 条规则 id 在该版本里不存在："
              f"{', '.join(doc['unresolved'])}")
    return 0


def cmd_spec_drift(args):
    bl = specdb.load_baseline()
    print(f"基线： {config.SPEC_REPO} @ {bl['commit'][:12]}  ({bl['commit_date']})")
    sha, drifts = specdb.diff_against(bl, args.ref)
    print(f"对照： {config.SPEC_REPO} @ {sha[:12]}  ({specdb.commit_date(sha)})")
    changed = [d for d in drifts if d.status in ("CHANGED", "REMOVED", "MOVED")]
    print(f"\n检查 {len(drifts)} 条被引用规则，发现 {len(changed)} 条发生变化。\n")
    affected = set()
    for d in changed:
        print("=" * 78)
        print(f"[{d.status}] {d.rule_id}")
        print(f"  基线位置 {d.old_loc}  sha={d.old_sha}")
        print(f"  当前位置 {d.new_loc}  sha={d.new_sha or '-'}")
        print("  --- 词级差异（- 基线 / + 当前）---")
        for ln in specdb.word_diff(d.old_text, d.new_text).splitlines():
            print("    " + ln)
        print("  --- 当前原文 ---")
        print("    " + specdb.normalize(d.new_text)[:600])
        print(f"  --- 受影响、需要重新审阅的性质（{len(d.properties)} 条）---")
        for pid in d.properties:
            print(f"    * {pid}")
        affected |= set(d.properties)
    if changed:
        print("=" * 78)
        print(f"\n结论：{len(changed)} 条规则文本已变化，{len(affected)} 条性质需要重新审阅。")
        print("下一步：`csrformal check <模块> --only <pid>` 用当前 RTL 重跑这些性质，"
              "确认实现是否仍然符合改后的规范。")
    else:
        print("结论：所有被引用规则的文本与基线一致，无需重新审阅。")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"baseline": bl["commit"], "against": sha,
                       "drifts": [d.__dict__ for d in drifts],
                       "affected_properties": sorted(affected)},
                      f, ensure_ascii=False, indent=2)
        print(f"\n结构化结果：{args.json}")
    return 1 if changed else 0


# ------------------------------------------------------------------ 变异回归

def cmd_self_test(args):
    """变异测试回归：注入已知缺陷，要求**意图对应的那条性质**报出反例。

    没有这一步，「无反例」永远可能是「工具坏了」。只检查 “有性质挂了” 也不够：
    挂的必须是设计上应该抓住它的那条，否则对照本身就失效了。
    """
    total = killed = 0
    rows = []
    for name in sorted(modules.all_modules()):
        spec = modules.get(name)
        if args.module and args.module != name:
            continue
        muts = [m for m in spec.mutants if not args.only or args.only in m.mid]
        if not muts:
            continue
        base_props = spec.props
        for m in muts:
            total += 1
            print(f"\n=== 变异体 {m.mid} [{name}] {m.desc} ===", flush=True)
            src = dict(spec.sources)
            src[m.module] = m.patch
            sv = elaborate.elaborate(name, f"mut_{m.mid}",
                                     overrides=list(src.values()), force=args.rebuild)
            r = runner.ModuleRunner(sv, name, _smt2_path(f"mut_{m.mid}"))
            # 只跑「预期能杀死它的」那批性质：跑全套没有额外信息，只是慢
            keys = m.expect_fix if m.kind == "fix" else m.expect_kill
            want = [p for p in base_props
                    if any(p.pid.split("/", 1)[1].startswith(k) for k in keys)]
            if not want:
                raise SystemExit(f"变体 {m.mid} 的 expect_{m.kind}={keys} 没匹配到性质")
            res = r.run(want, progress=False)
            fails = [x for x in res if x.status == runner.VIOLATED]
            vac = [x for x in res if x.status == runner.VACUOUS]
            if m.kind == "fix":
                # 修复对照：要求全部转为通过（且不能靠真空蒙混过关）
                ok = not fails and not vac
                verdict = "FIXED ✔" if ok else "NOT FIXED ✘"
            else:
                ok = bool(fails) and not vac
                verdict = "KILLED ✔" if ok else "SURVIVED ✘"
            killed += ok
            print(f"  相关性质 {len(want)} 条 → 反例 {len(fails)} 条，真空 {len(vac)} 条"
                  f"  ⇒ {verdict}")
            for x in (fails[:3] if m.kind == "defect" else res[:3]):
                print(f"     - [{x.status}] {x.prop.pid}: {x.prop.title}")
            rows.append((m.mid, name, m.kind, m.desc, len(want), len(fails), ok))

    print(f"\n==== 变异回归：{killed}/{total} 符合预期 ====")
    print(f"{'变异体':8s} {'类型':7s} {'模块':20s} {'性质':>5s} {'反例':>5s}  结果")
    for mid, name, kind, desc, nw, nf, ok in rows:
        v = ("KILLED" if ok else "SURVIVED") if kind == "defect" else \
            ("FIXED" if ok else "NOT FIXED")
        print(f"{mid:8s} {kind:7s} {name:20s} {nw:5d} {nf:5d}  {v}  {desc}")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write("# 变异回归（阳性对照 + 修复对照）\n\n")
            f.write(f"{killed}/{total} 个变体的行为符合预期。\n\n")
            f.write("- **defect**（阳性对照）：注入已知缺陷，要求对应性质报出反例；"
                    "全部被杀死才说明性质集有效。\n")
            f.write("- **fix**（修复对照）：打入候选修复，要求当前报反例的性质转为通过。\n\n")
            f.write("| 变体 | 类型 | 模块 | 内容 | 相关性质数 | 反例数 | 结果 |\n")
            f.write("|---|---|---|---|---|---|---|\n")
            for mid, name, kind, desc, nw, nf, ok in rows:
                v = ("KILLED" if ok else "**SURVIVED**") if kind == "defect" else \
                    ("FIXED" if ok else "**NOT FIXED**")
                f.write(f"| `{mid}` | {kind} | {name} | {desc} | {nw} | {nf} | {v} |\n")
        print(f"报告：{args.report}")
    return 0 if killed == total else 1


# ------------------------------------------------------------------ Spike（P2 占位）

def cmd_spike(args):
    doc = os.path.join(config.ROOT, "docs", "spike-crosscheck.md")
    print(open(doc, encoding="utf-8").read() if os.path.exists(doc)
          else "设计说明缺失：docs/spike-crosscheck.md")
    return 0


# ------------------------------------------------------------------ main

def main(argv=None):
    ap = argparse.ArgumentParser(prog="csrformal",
                                 description="XiangShan CSR 子系统的形式化规范符合性检查")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check", help="跑一个/全部模块的性质并出报告")
    p.add_argument("module", help="模块名或 all")
    p.add_argument("--only", help="只跑 pid 里包含该子串的性质（调试用）")
    p.add_argument("--review", metavar="DRIFT_JSON",
                   help="只重跑 spec-drift 标记为需重新审阅的性质")
    p.add_argument("--rebuild", action="store_true", help="强制重新精化")
    p.add_argument("--report", help="Markdown 报告路径")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("list", help="列出已注册的性质")
    p.add_argument("module", nargs="?")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("rules", help="列出被引用的规范规则")
    p.add_argument("--text", action="store_true", help="同时打印原文")
    p.set_defaults(fn=cmd_rules)

    p = sub.add_parser("lint", help="静态自检：元数据齐全性 + 规则 id 真实性")
    p.add_argument("--ref", default=config.BASELINE_REF)
    p.set_defaults(fn=cmd_lint)

    p = sub.add_parser("spec-baseline", help="快照当前被引用规则的原文为基线")
    p.add_argument("--ref", default=config.BASELINE_REF)
    p.set_defaults(fn=cmd_spec_baseline)

    p = sub.add_parser("spec-drift", help="规范漂移检测")
    p.add_argument("--ref", default="main", help="与哪个版本比（默认 main）")
    p.add_argument("--json", help="结构化结果输出路径")
    p.set_defaults(fn=cmd_spec_drift)

    p = sub.add_parser("self-test", help="变异回归（阳性对照）")
    p.add_argument("--module")
    p.add_argument("--only", help="只跑某个变异体")
    p.add_argument("--rebuild", action="store_true")
    p.add_argument("--report")
    p.set_defaults(fn=cmd_self_test)

    p = sub.add_parser("spike", help="Spike 交叉检查（接口与设计说明）")
    p.set_defaults(fn=cmd_spike)

    args = ap.parse_args(argv)
    os.makedirs(config.OUT_DIR, exist_ok=True)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
