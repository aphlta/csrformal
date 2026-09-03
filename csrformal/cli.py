"""csrformal 命令行入口。

  csrformal check <模块|all>     精化 → 转 SMT → 跑全部性质 → 出报告
  csrformal list [模块]          列出已注册的性质
  csrformal rules                列出被引用的规范规则 id 及其原文
  csrformal lint                 静态自检：性质元数据是否齐全、规则 id 是否真存在
  csrformal spec-baseline        把当前被引用的规则原文快照成基线
  csrformal spec-drift           基线 vs 指定版本的规范漂移检测
  csrformal self-test            变异回归：注入已知缺陷，确认对应性质能杀死它
  csrformal spec-selfcheck       规格自洽：permit / trap_entry 的 Python 与 SMT 必须一致
  csrformal spike                打印 Spike 交叉检查说明
  csrformal spike-cex            对已有报告里的反例问 Spike（缺二进制则跳过）
"""
import argparse
import json
import os
import sys
import time

from . import config, elaborate, modules, report, runner, specdb

# check 门禁：这四种都是失败。UNKNOWN 不是「暂时放过」，
# 否则求解器超时/给不出结论会被 CI 当成全绿。
CHECK_FAIL = (runner.VIOLATED, runner.VACUOUS, runner.UNKNOWN, runner.ERROR)
# 变异对照只认明确结论。UNKNOWN/VACUOUS/ERROR 既不是 FIXED 也不是 KILLED。
SELFTEST_CONCLUSIVE = (runner.HOLDS, runner.VIOLATED)


def _smt2_beside(sv: str) -> str:
    """SMT2 必须和这次精化的 SV 在同一目录，才能跟 RTL 身份缓存键对齐。"""
    return os.path.join(os.path.dirname(sv), "c.smt2")


def _select(props, only, pids=None):
    """--pids 走精确匹配，是给 spec-drift 的产物直接喂进来用的；
    --only 走子串匹配，是给人手工调试用的。"""
    if pids is not None:
        # 空列表也是「精确匹配 0 条」，不能当成「不过滤」——
        # 否则 --review 空 JSON 会跑完全部性质并静默当通过。
        want = set(pids)
        return [p for p in props if p.pid in want]
    if not only:
        return props
    # 单个模块 0 命中不在这里退出：`check all --only S3` 时其它模块本来就
    # 不该匹配。拼错 / 全局 0 条由调用方按空 --review 同一原则拒绝。
    return [p for p in props if only.lower() in p.pid.lower()]


def check_failed(summary: dict) -> bool:
    """反例 / 真空 / 未知 / 错误 → 失败。全 HOLDS 才通过。"""
    return any(summary.get(s) for s in CHECK_FAIL)


def pid_suffix(pid: str) -> str:
    """`Module/local` → `local`。无斜杠时原样返回，方便单测喂裸后缀。"""
    return pid.split("/", 1)[1] if "/" in pid else pid


def expect_key_matches(pid: str, key: str) -> bool:
    """expect_kill / expect_fix 是否选中这条性质。

    精确：`TrapEntryM/EQ-tval` 对 key `EQ-tval`。
    族：`TrapHandle/D2[e=8,HS]` 对 key `D2`（后缀以 `D2[` 开头）。

    不用 `startswith(key)`：否则 `EQ-tval` 会吃到 `EQ-tval-data`，
    te1 与 te2 的对照会串台；`S3` 也会误伤 `S3b`。
    """
    suffix = pid_suffix(pid)
    return suffix == key or suffix.startswith(key + "[")


def select_expect_props(props, keys):
    """按 expect_kill/fix 的 key 选出应对的性质。"""
    return [p for p in props
            if any(expect_key_matches(p.pid, k) for k in keys)]


def selftest_ok(kind: str, statuses) -> bool:
    """变异对照是否符合预期。

    只有明确的 HOLDS / VIOLATED 才算对照成功：
      * fix：全部 HOLDS（UNKNOWN 不得当 FIXED）
      * defect：至少一条 VIOLATED，且没有非结论状态（UNKNOWN 不得当 KILLED）
    """
    if not statuses:
        return False
    if any(s not in SELFTEST_CONCLUSIVE for s in statuses):
        return False
    if kind == "fix":
        return all(s == runner.HOLDS for s in statuses)
    return any(s == runner.VIOLATED for s in statuses)


def _require_linux():
    """精化 / SMT2 缓存需要 Linux 上的 fcntl 文件锁；不是 Windows 移植。

    只在即将精化或写 SMT 缓存时调用。list / lint / spec-selfcheck
    以及 check --review/--only 空匹配不得走这里。
    """
    try:
        import fcntl  # noqa: F401
    except ImportError:
        raise SystemExit(
            "csrformal 仅支持 Linux（需要 fcntl 文件锁）。"
            "不要在 Windows 上跑；请用 Linux 主机或 Docker。"
        )


# ------------------------------------------------------------------ check

def cmd_check(args):
    names = sorted(modules.all_modules()) if args.module == "all" else [args.module]
    pids = None
    if args.review:
        # 直接消费 spec-drift 的产物：只重跑「因规范变化而需要重新审阅」的性质。
        with open(args.review, encoding="utf-8") as f:
            pids = json.load(f)["affected_properties"]
        print(f"从 {args.review} 读到 {len(pids)} 条待重新审阅的性质")
    selected = []
    for name in names:
        spec = modules.get(name)
        selected.append((name, _select(spec.props, args.only, pids)))
    # --review / --only 空匹配必须失败：0 条性质跑完 summarize 全 0，会静默当通过。
    nsel = sum(len(p) for _, p in selected)
    if args.review is not None and nsel == 0:
        print(f"--review {args.review}: 0 条性质，拒绝当作通过")
        return 1
    if args.only is not None and nsel == 0:
        print(f"--only {args.only!r}: 0 条性质，拒绝当作通过；用 `csrformal list` 查看")
        return 1
    # 过了 0 匹配门禁才需要 fcntl / 精化。空 --review/--only 的 unittest 不该被拦。
    _require_linux()
    wall0 = time.time()
    all_results, meta_mods = [], []
    for name, props in selected:
        if not props:
            continue
        print(f"\n=== {name} ({len(props)} 条性质) ===", flush=True)
        print("  精化 …", flush=True)
        sv = elaborate.elaborate(name, f"base_{name}", force=args.rebuild)
        r = runner.ModuleRunner(sv, name, _smt2_beside(sv))
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
    if getattr(args, "spike", False):
        from . import spike_oracle
        print("\n---- Spike 反例定性（不穷举；缺 spike 则跳过）----")
        doc = {
            "properties": [{
                "pid": r.prop.pid, "status": r.status, "prove": r.prop.prove,
                "counterexample": r.counterexample, "outputs": r.outputs,
            } for r in all_results if r.status == runner.VIOLATED]
        }
        spike_oracle.print_votes(spike_oracle.votes_from_report(doc))
    return 1 if check_failed(s) else 0


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
    """rule_id → 引用它的性质 pid 列表。

    合取型主定理的条款写在 extra_refs 里，必须一并收入，否则
    spec-drift 会漏掉等价性层真正依赖的段落。
    """
    out = {}
    for p in modules.all_properties():
        refs = [p.ref, *list(p.extra_refs or [])]
        for ref in refs:
            if ref.rule_id:
                out.setdefault(ref.rule_id, []).append(p.pid)
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
    if os.path.exists(config.BASELINE_JSON):
        bl = specdb.load_baseline()
        if str(bl.get("commit", "")).startswith(config.DELETED_STCE_REF[:12]):
            print("  [权威基线] commit 是 f20aa35（误删时点），不是 EQ 权威")
            bad += 1
        stce = bl.get("rules", {}).get("norm:menvcfg_stce_op2")
        if stce is not None and "vstimecmp" not in stce.get("text", ""):
            print("  [权威基线] menvcfg_stce_op2 缺少 vstimecmp，像是误删文本")
            bad += 1
        # EQ 的 extra_refs 必须进基线 properties，否则 spec-drift 看不见等价性层。
        stce_props = (stce or {}).get("properties") or []
        if "CSRPermit/EQ-permit" not in stce_props:
            print("  [权威基线] norm:menvcfg_stce_op2.properties 漏了 CSRPermit/EQ-permit")
            bad += 1
    print(f"\n性质 {len(props)} 条，引用规则 {len(referenced_rules())} 条，"
          f"规范 {args.ref[:12]} 共 {len(rules)} 条规则。问题 {bad} 处。")
    return 1 if bad else 0


# ------------------------------------------------------------------ 规范基线 / 漂移

def cmd_spec_baseline(args):
    path = args.output or config.BASELINE_JSON
    doc = specdb.write_baseline(args.ref, referenced_rules(), path)
    print(f"基线已写入 {path}")
    print(f"  {config.SPEC_REPO} @ {doc['commit'][:12]}  ({doc['commit_date']})")
    print(f"  快照规则 {doc['rule_count']} 条")
    if doc["unresolved"]:
        print(f"  ⚠️ 有 {len(doc['unresolved'])} 条规则 id 在该版本里不存在："
              f"{', '.join(doc['unresolved'])}")
    return 0


def cmd_spec_drift(args):
    bl = specdb.load_baseline(args.baseline) if args.baseline else specdb.load_baseline()
    print(f"基线： {config.SPEC_REPO} @ {bl['commit'][:12]}  ({bl['commit_date']})")
    sha, drifts = specdb.diff_against(bl, args.ref)
    print(f"对照： {config.SPEC_REPO} @ {sha[:12]}  ({specdb.commit_date(sha)})")
    changed = [d for d in drifts if d.status in ("CHANGED", "REMOVED", "MOVED")]
    print(f"\n检查 {len(drifts)} 条被引用规则，发现 {len(changed)} 条发生变化。\n")
    affected = set()
    for d in changed:
        print(f"[{d.status}] {d.rule_id}")
        print(f"  基线位置 {d.old_loc}  sha={d.old_sha}")
        print(f"  当前位置 {d.new_loc}  sha={d.new_sha or '-'}")
        print("  词级差异（- 基线 / + 当前）")
        for ln in specdb.word_diff(d.old_text, d.new_text).splitlines():
            print("    " + ln)
        print("  当前原文")
        print("    " + specdb.normalize(d.new_text)[:600])
        print(f"  受影响、需要重新审阅的性质（{len(d.properties)} 条）")
        for pid in d.properties:
            print(f"    * {pid}")
        affected |= set(d.properties)
        print()
    if changed:
        print(f"结论：{len(changed)} 条规则文本已变化，{len(affected)} 条性质需要重新审阅。")
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
    jobs = []
    wall0 = time.time()
    for name in sorted(modules.all_modules()):
        spec = modules.get(name)
        if args.module and args.module != name:
            continue
        muts = [m for m in spec.mutants if not args.only or args.only in m.mid]
        for m in muts:
            jobs.append((name, spec, m))
    # --only 拼错 / 匹配 0 条不得当成功。和空 --review 同一原则。
    if args.only is not None and not jobs:
        print(f"--only {args.only!r}: 0 个变异体，拒绝当作通过")
        return 1
    _require_linux()
    for name, spec, m in jobs:
        total += 1
        print(f"\n=== 变异体 {m.mid} [{name}] {m.desc} ===", flush=True)
        src = dict(spec.sources)
        src[m.module] = m.patch
        sv = elaborate.elaborate(name, f"mut_{m.mid}",
                                 overrides=list(src.values()), force=args.rebuild)
        r = runner.ModuleRunner(sv, name, _smt2_beside(sv))
        # 只跑「预期能杀死它的」那批性质：跑全套没有额外信息，只是慢
        keys = m.expect_fix if m.kind == "fix" else m.expect_kill
        want = select_expect_props(spec.props, keys)
        if not want:
            raise SystemExit(f"变体 {m.mid} 的 expect_{m.kind}={keys} 没匹配到性质")
        res = r.run(want, progress=False)
        fails = [x for x in res if x.status == runner.VIOLATED]
        vac = [x for x in res if x.status == runner.VACUOUS]
        unk = [x for x in res if x.status == runner.UNKNOWN]
        err = [x for x in res if x.status == runner.ERROR]
        # 修复对照 / 阳性对照都只认明确 HOLDS/VIOLATED；
        # UNKNOWN 既不能当 FIXED，也不能当 KILLED。
        ok = selftest_ok(m.kind, [x.status for x in res])
        if m.kind == "fix":
            verdict = "FIXED ✔" if ok else "NOT FIXED ✘"
        else:
            verdict = "KILLED ✔" if ok else "SURVIVED ✘"
        killed += ok
        print(f"  相关性质 {len(want)} 条 → 反例 {len(fails)} 条，真空 {len(vac)} 条"
              f"，未知 {len(unk)} 条，错误 {len(err)} 条  ⇒ {verdict}")
        for x in (fails[:3] if m.kind == "defect" else res[:3]):
            print(f"     - [{x.status}] {x.prop.pid}: {x.prop.title}")
        rows.append((m.mid, name, m.kind, m.desc, len(want), len(fails), ok))

    wall = time.time() - wall0
    print(f"\n==== 变异回归：{killed}/{total} 符合预期 ====")
    print(f"壁钟 {wall:.1f}s")
    print(f"{'变异体':8s} {'类型':7s} {'模块':20s} {'性质':>5s} {'反例':>5s}  结果")
    for mid, name, kind, desc, nw, nf, ok in rows:
        v = ("KILLED" if ok else "SURVIVED") if kind == "defect" else \
            ("FIXED" if ok else "NOT FIXED")
        print(f"{mid:8s} {kind:7s} {name:20s} {nw:5d} {nf:5d}  {v}  {desc}")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write("# 变异回归（阳性对照 + 修复对照）\n\n")
            f.write(f"{killed}/{total} 个变体的行为符合预期。壁钟 {wall:.1f}s。\n\n")
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


# ------------------------------------------------------------------ 规格自洽 / Spike

def cmd_spec_selfcheck(args):
    from .spec_selfcheck import run_selfcheck
    return run_selfcheck(n_random=args.random)


def cmd_spike(args):
    doc = os.path.join(config.ROOT, "docs", "spike-crosscheck.md")
    print(open(doc, encoding="utf-8").read() if os.path.exists(doc)
          else "设计说明缺失：docs/spike-crosscheck.md")
    return 0


def cmd_spike_cex(args):
    from . import spike_oracle
    path = args.report
    if not os.path.exists(path):
        raise SystemExit(f"报告不存在: {path}")
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    votes = spike_oracle.votes_from_report(doc)
    spike_oracle.print_votes(votes)
    # 缺 spike 是跳过，不是失败。真跑了且需要当门禁时看 --strict。
    if args.strict and any(v.spike is None for v in votes):
        return 1
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
    p.add_argument("--spike", action="store_true",
                   help="对 VIOLATED 反例问 Spike（缺二进制则跳过，不穷举）")
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
    p.add_argument("--output", help="写入路径（默认 spec/baseline.json；"
                   "demo 必须写旁路，禁止把 f20aa35 写进权威基线）")
    p.set_defaults(fn=cmd_spec_baseline)

    p = sub.add_parser("spec-drift", help="规范漂移检测")
    p.add_argument("--ref", default="main", help="与哪个版本比（默认 main）")
    p.add_argument("--baseline", help="基线 JSON 路径（默认 spec/baseline.json）")
    p.add_argument("--json", help="结构化结果输出路径")
    p.set_defaults(fn=cmd_spec_drift)

    p = sub.add_parser("spec-selfcheck",
                       help="规格自洽：permit / trap_entry 的 Python 与 SMT 必须一致")
    p.add_argument("--random", type=int, default=64,
                   help="补充随机具体化点数（默认 64）")
    p.set_defaults(fn=cmd_spec_selfcheck)

    p = sub.add_parser("self-test", help="变异回归（阳性对照）")
    p.add_argument("--module")
    p.add_argument("--only", help="只跑某个变异体")
    p.add_argument("--rebuild", action="store_true")
    p.add_argument("--report")
    p.set_defaults(fn=cmd_self_test)

    p = sub.add_parser("spike", help="Spike 交叉检查说明")
    p.set_defaults(fn=cmd_spike)

    p = sub.add_parser("spike-cex", help="对报告里的反例问 Spike（缺则跳过）")
    p.add_argument("report", help="compliance.json 路径")
    p.add_argument("--strict", action="store_true",
                   help="缺 spike 也当失败（默认跳过，退出码 0）")
    p.set_defaults(fn=cmd_spike_cex)

    args = ap.parse_args(argv)
    # list / lint / rules / spec-selfcheck / spike 是纯逻辑：不碰 fcntl、
    # 不精化、不写 SMT 缓存。CI 与 unittest 必须能跑。
    # check / self-test 的 _require_linux 放在各自 0 匹配门禁之后，
    # 否则空 --review / 拼错 --only 的两则单测会被误伤。
    _PURE = {"list", "rules", "lint", "spike", "spec-selfcheck"}
    if args.cmd not in _PURE:
        os.makedirs(config.OUT_DIR, exist_ok=True)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
