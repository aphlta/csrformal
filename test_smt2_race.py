#!/usr/bin/env python3
"""sv_to_smt2 缓存竞态的回归测试（old vs new 对比）。

与 csr-hunt/if/test_smt2_race.py 同构：用一个慢速 stub yosys 把
「文件已存在但内容不完整」的窗口放大到秒级，并错开各进程的启动时刻，
使竞态每次必然发生。

判据：
  1) 完整性 —— 每个进程读到的文件行数必须完整且末行是哨兵；
  2) 无重复生成 —— stub 只应被调用一次。

用法: python3 test_smt2_race.py both
"""
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

NLINES = 40000
SENTINEL = "; yosys-smt2-END-OF-FILE"

STUB = f'''#!/usr/bin/env python3
import os, re, sys, tempfile, time
NLINES = {NLINES}
SENTINEL = {SENTINEL!r}
out = re.search(r"write_smt2\\s+(\\S+)", sys.argv[-1]).group(1)
tempfile.mkstemp(prefix="call.", dir=os.environ["MARKER_DIR"])
with open(out, "w") as f:
    for chunk in range(40):
        for j in range(NLINES // 40):
            f.write(f"; yosys-smt2-input port_{{chunk}}_{{j}} 1\\n")
        f.flush(); os.fsync(f.fileno()); time.sleep(0.05)
    f.write(SENTINEL + "\\n")
'''


def to_smt2_old(sv_path, top, out_path, force=False):
    """修复前的实现，逐字保留，用作阳性对照。

    yosys 路径走与现行代码相同的 CSRFORMAL_YOSYS 覆盖，否则 stub 进不去，
    「old 必现竞态」对照本身会失效。
    """
    from csrformal import smt
    if os.path.exists(out_path) and not force and \
            os.path.getmtime(out_path) > os.path.getmtime(sv_path):
        return out_path
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    script = (f"read_verilog -sv {sv_path}; prep -top {top} -flatten; "
              f"memory_map; write_smt2 {out_path}")
    r = subprocess.run([smt.yosys_bin(), "-q", "-p", script],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("yosys 失败:\n" + r.stdout + r.stderr)
    return out_path


def _worker(args):
    impl, sv, cache, idx = args
    time.sleep(0.12 * idx)
    from csrformal import smt
    fn = smt.sv_to_smt2 if impl == "new" else to_smt2_old
    try:
        with open(fn(sv, "Dummy", cache)) as f:
            lines = f.read().splitlines()
    except Exception as e:                                  # noqa: BLE001
        return (idx, "EXC", repr(e))
    if not lines or lines[-1] != SENTINEL:
        return (idx, "TRUNCATED",
                f"{len(lines)} 行，末行={lines[-1] if lines else '<空>'!r}")
    if len(lines) != NLINES + 1:
        return (idx, "SHORT", f"{len(lines)} 行，期望 {NLINES + 1}")
    return (idx, "OK", f"{len(lines)} 行")


def run(impl, nproc=16):
    work = tempfile.mkdtemp(prefix=f"csrformal-race-{impl}-")
    marker = os.path.join(work, "markers")
    os.makedirs(marker)
    stub = os.path.join(work, "yosys")
    with open(stub, "w") as f:
        f.write(STUB)
    os.chmod(stub, 0o755)
    sv = os.path.join(work, "dummy.sv")
    with open(sv, "w") as f:
        f.write("module Dummy(); endmodule\n")

    # 覆盖必须走 CSRFORMAL_YOSYS（与 config.py 一致）。旧名 YOSYS 无效。
    # 故意不写 config.YOSYS：sv_to_smt2 必须运行时读环境变量，import 之后也能覆盖。
    os.environ["CSRFORMAL_YOSYS"] = stub
    os.environ.pop("YOSYS", None)
    os.environ["MARKER_DIR"] = marker
    from csrformal import config, smt
    used = smt.yosys_bin()
    if used != stub:
        shutil.rmtree(work, ignore_errors=True)
        raise SystemExit(
            f"CSRFORMAL_YOSYS 未覆盖 yosys：yosys_bin()={used!r} "
            f"config.YOSYS={config.YOSYS!r} stub={stub!r}"
        )

    with mp.Pool(nproc) as pool:
        res = pool.map(_worker, [(impl, sv, os.path.join(work, "m.smt2"), i)
                                 for i in range(nproc)])

    ncalls = len(os.listdir(marker))
    tally = {}
    for _, tag, _ in res:
        tally[tag] = tally.get(tag, 0) + 1
    ok = tally.get("OK", 0) == nproc and ncalls == 1

    print(f"\n=== csrformal impl={impl}  并发 {nproc} 进程 ===")
    print(f"stub yosys 被调用次数 = {ncalls}  (期望 1)")
    for tag, n in sorted(tally.items()):
        print(f"  {tag:10s} {n}")
    for idx, tag, info in res:
        if tag != "OK":
            print(f"  #{idx}: {tag} -> {info}")
    print(f"结论: {'PASS' if ok else 'FAIL'}")
    shutil.rmtree(work, ignore_errors=True)
    return ok


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    results = {i: run(i) for i in (["old", "new"] if which == "both" else [which])}
    print("\n==== 汇总 ====")
    for impl, ok in results.items():
        print(f"{impl}: {'PASS' if ok else 'FAIL'}")
    if which == "both":
        sys.exit(0 if (results["old"] is False and results["new"] is True) else 1)
