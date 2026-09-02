"""SystemVerilog → SMT2 → z3 求解。

流水线（已验证可行的那条路，别再试 `firtool --btor2`：它不支持 n 元 `comb.and`）：

    最小 harness 把目标模块当 top
      → firtool 出 SystemVerilog（必须 --default-layer-specialization=disable，
        否则 layer 里的断言会带进不可综合的结构）
      → yosys read_verilog -sv; prep -top M -flatten; memory_map; write_smt2
      → z3

性能设计
--------
朴素做法是「每条性质起一个进程、重跑一遍 yosys + 重新 parse 整个电路」。
189 条性质 ×2 次求解（真空性 + 本体）就是 378 次重复解析，绝大部分时间花在
解析上而不是求解上。这里改成：

  * 每个模块只跑一次 yosys，SMT2 缓存到磁盘；
  * 每个 **进程** 只 parse 一次电路，拿到端口常量的句柄；
  * 之后每条性质只 parse 它自己那几十字节的表达式（通过 z3 的 `decls=` 复用句柄），
    并用 solver.push()/pop() 隔离。

实测把 CSRPermitModule 全套从「分钟级 × N」压到单进程十几秒。
"""
import fcntl
import os
import re
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from . import config

PORT_RE = re.compile(r";\s*yosys-smt2-(input|output|register|wire)\s+(\S+)\s+(\d+)")


def _cache_fresh(sv_path: str, out_path: str) -> bool:
    return os.path.exists(out_path) and \
        os.path.getmtime(out_path) > os.path.getmtime(sv_path)


def sv_to_smt2(sv_path: str, top: str, out_path: str, force: bool = False) -> str:
    """把 .sv 降成 yosys 的 SMT2 转移关系描述。结果带缓存，多进程并发安全。

    并发保护（性质会被切片成多个进程同时跑，它们共用同一个 out_path）：
      * 排他文件锁把「查缓存」和「建缓存」合成一个临界区，避免多个进程
        同时判定缓存缺失、同时跑 yosys 写同一个文件；
      * yosys 写临时文件，再用 os.replace 原子改名就位。yosys 的输出是
        流式的，若直接写 out_path，别的进程可能 open 到一个只写了一半的
        文件，解析出残缺电路，导致性质假失败。
    """
    if _cache_fresh(sv_path, out_path) and not force:
        return out_path

    out_dir = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(out_dir, exist_ok=True)
    with open(out_path + ".lock", "w") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        # 等锁期间别的进程可能已经生成好了，重新检查一次。
        if _cache_fresh(sv_path, out_path) and not force:
            return out_path
        fd, tmp = tempfile.mkstemp(prefix=os.path.basename(out_path) + ".",
                                   suffix=".tmp", dir=out_dir)
        os.close(fd)
        try:
            script = (f"read_verilog -sv {sv_path}; prep -top {top} -flatten; "
                      f"memory_map; write_smt2 {tmp}")
            r = subprocess.run([config.YOSYS, "-q", "-p", script],
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise SystemExit("yosys 失败:\n" + r.stdout + r.stderr)
            os.replace(tmp, out_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return out_path


def parse_port_table(smt2_path: str) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int]]:
    ins, outs, regs = {}, {}, {}
    with open(smt2_path) as f:
        for line in f:
            m = PORT_RE.match(line)
            if not m:
                continue
            kind, name, w = m.group(1), m.group(2), int(m.group(3))
            if kind == "input":
                ins[name] = w
            elif kind == "output":
                outs[name] = w
            elif kind == "register":
                regs[name] = w
    return ins, outs, regs


def _decl(name: str, w: int) -> str:
    return f"(declare-const {name} {'Bool' if w == 1 else f'(_ BitVec {w})'})"


class Circuit:
    """一份已经 parse 进 z3 的电路，可反复 push/pop 地问不同性质。

    `instances` 决定开几份实例：单实例用 `[""]`（端口名即变量名），
    关系型用 `["A_", "B_"]`（变量名加前缀）。
    """

    def __init__(self, smt2_path: str, top: str, instances: Optional[List[str]] = None):
        import z3
        self.z3 = z3
        self.top = top
        self.prefixes = instances or [""]
        self.ins, self.outs, self.regs = parse_port_table(smt2_path)

        body = [open(smt2_path).read()]
        for pfx in self.prefixes:
            body.append(f"(declare-const {pfx}__S |{top}_s|)")
            for grp in (self.ins, self.outs):
                for n, w in sorted(grp.items()):
                    body.append(_decl(f"{pfx}{n}", w))
                    body.append(f"(assert (= {pfx}{n} (|{top}_n {n}| {pfx}__S)))")
        base = "\n".join(body)

        self.solver = z3.Solver()
        asserts = z3.parse_smt2_string(base)
        self.solver.add(asserts)
        # 从「端口 = 电路取值」这批绑定断言里回收端口常量的句柄。
        # 之所以要回收而不是自己 z3.BitVec() 造：parse_smt2_string 在自己的
        # 符号表里建常量，Python 侧另造一个同名常量并不是同一个 AST 节点。
        self.decls = {}
        for a in asserts:
            if a.decl().name() == "=" and a.num_args() == 2:
                lhs = a.arg(0)
                if lhs.num_args() == 0 and lhs.decl().name() in self._all_names():
                    self.decls[lhs.decl().name()] = lhs

    def _all_names(self):
        if not hasattr(self, "_names"):
            self._names = {f"{p}{n}" for p in self.prefixes
                           for n in list(self.ins) + list(self.outs)}
        return self._names

    def _expr(self, text: str):
        v = self.z3.parse_smt2_string(f"(assert {text})", decls=self.decls)
        return self.z3.And([x for x in v]) if len(v) > 1 else v[0]

    def _conj(self, texts: List[str]):
        """把一批假设合成**一次** parse。

        每次 parse_smt2_string 都要重建一遍符号表，成本与 `decls` 的规模成正比
        （这里有几十上百个端口）。逐条 parse 一条性质的 40 个假设，
        解析开销会比求解本身高两个数量级 —— 实测全套 295 条性质
        从 143 s 降到 4 s 就是靠这一处。
        """
        if not texts:
            return self.z3.BoolVal(True)
        if len(texts) == 1:
            return self._expr(texts[0])
        return self._expr("(and " + " ".join(texts) + ")")

    def check(self, assumes: List[str], prove: str,
              want_model: bool = True) -> Tuple[str, float, Dict[str, object]]:
        """返回 (结论, 耗时秒, 反例模型)。

        结论：HOLDS（unsat，即在假设下性质恒真）/ VIOLATED（sat，给出反例）
              / UNKNOWN。
        """
        z3 = self.z3
        self.solver.push()
        try:
            self.solver.add(self._conj(assumes))
            self.solver.add(z3.Not(self._expr(prove)))
            t0 = time.time()
            r = self.solver.check()
            dt = time.time() - t0
            if r == z3.unsat:
                return "HOLDS", dt, {}
            if r != z3.sat:
                return "UNKNOWN", dt, {}
            model = {}
            if want_model:
                m = self.solver.model()
                for d in m.decls():
                    model[d.name()] = m[d]
            return "VIOLATED", dt, model
        finally:
            self.solver.pop()

    def satisfiable(self, assumes: List[str]) -> Tuple[bool, float]:
        """真空性自检：假设集自身是否可满足。

        为什么这是**强制门禁**而不是可选检查：
        若假设集自相矛盾（unsat），那么 `assumes ∧ ¬prove` 必然也 unsat，
        求解器返回 unsat，工具会把它当成「性质成立」。这是**假通过**——
        什么都没验证却报绿。上一轮 68 条性质里有 30+ 条栽在这里
        （CLEAN 写 mcounteren=0xffffffff，被测条款却要求 mcounteren[i]=0）。
        所以：假设集不可满足 → 报 VACUOUS（视为失败），绝不报 HOLDS。
        """
        z3 = self.z3
        self.solver.push()
        try:
            self.solver.add(self._conj(assumes))
            t0 = time.time()
            r = self.solver.check()
            return r == z3.sat, time.time() - t0
        finally:
            self.solver.pop()


def fmt_value(v) -> str:
    import z3
    if z3.is_bv_value(v):
        w, n = v.size(), v.as_long()
        return f"0x{n:0{(w + 3) // 4}x} ({w}'b{n:0{w}b})" if w <= 12 else f"0x{n:0{(w + 3) // 4}x}"
    return str(v)


def is_default(v) -> bool:
    import z3
    return str(v) == "False" or (z3.is_bv_value(v) and v.as_long() == 0)
