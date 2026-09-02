"""性质执行器：真空性门禁 + 求解 + 结构化结果。

每条性质走两步，**顺序不可颠倒**：

  1. 真空性自检 —— 单独问「假设集本身可满足吗」。
     不可满足 ⇒ 结果 VACUOUS（**记为失败**，不是通过）。
  2. 本体求解 —— 问「假设集 ∧ ¬结论」是否可满足。
     unsat ⇒ HOLDS；sat ⇒ VIOLATED，带完整反例输入取值。

为什么第 1 步是强制的而不是可选的
--------------------------------
若假设集自相矛盾，第 2 步必定 unsat，工具会报「性质成立」。这不是成立，
是**什么都没验证**。上一轮第一版性质集 68 条里有 30+ 条栽在这个坑：
CLEAN 写 `mcounteren=0xffffffff`，被测条款却要求 `mcounteren[i]=0`，
假设集不可满足，于是「全部通过」是假的。真空性检查的代价只有一次
额外求解（毫秒级），换来的是「绿灯」这个信号本身可信。
"""
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import smt
from .props import Property

HOLDS, VIOLATED, VACUOUS, UNKNOWN, ERROR = "HOLDS", "VIOLATED", "VACUOUS", "UNKNOWN", "ERROR"


@dataclass
class Result:
    prop: Property
    status: str
    seconds: float = 0.0
    vacuity_seconds: float = 0.0
    counterexample: Dict[str, str] = field(default_factory=dict)
    outputs: Dict[str, str] = field(default_factory=dict)
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status == HOLDS


class ModuleRunner:
    """针对一个已精化好的 .sv，跑一批性质。

    单实例电路与关系型（A/B 双实例）电路分别缓存，因为二者的 SMT2 变量
    命名空间不同，不能共用一个 solver。
    """

    def __init__(self, sv_path: str, top: str, smt2_path: str):
        self.sv, self.top = sv_path, top
        self.smt2 = smt.sv_to_smt2(sv_path, top, smt2_path)
        self._single: Optional[smt.Circuit] = None
        self._rel: Optional[smt.Circuit] = None

    def circuit(self, kind: str) -> smt.Circuit:
        if kind == "relational":
            if self._rel is None:
                self._rel = smt.Circuit(self.smt2, self.top, ["A_", "B_"])
            return self._rel
        if self._single is None:
            self._single = smt.Circuit(self.smt2, self.top)
        return self._single

    def _assumes(self, p: Property, c: smt.Circuit) -> List[str]:
        if p.kind != "relational":
            return p.assumes
        # 关系型：未被 --free 标记的输入必须在 A/B 两份实例上对齐。
        # 这是「同一 CSR 状态、同一次访问」的形式化；漏掉它，两份实例
        # 就是完全无关的电路，任何关系性质都会被轻易证伪。
        free = set(p.free)
        align = [f'(= A_{n} B_{n})' for n in sorted(c.ins) if n not in free]
        missing = free - set(c.ins)
        if missing:
            raise SystemExit(f"{p.pid}: free 里的端口不存在: {sorted(missing)}")
        return align + p.assumes

    def run_one(self, p: Property) -> Result:
        try:
            c = self.circuit(p.kind)
            asm = self._assumes(p, c)
            sat, vdt = c.satisfiable(asm)
            if not sat:
                return Result(p, VACUOUS, vacuity_seconds=vdt,
                              message="假设集不可满足：该性质是真空成立，未验证任何东西")
            prove = p.prove_fn(c) if p.prove_fn is not None else p.prove
            status, dt, model = c.check(asm, prove)
            r = Result(p, status, seconds=dt, vacuity_seconds=vdt)
            if status == VIOLATED:
                pfx = ["A_", "B_"] if p.kind == "relational" else [""]
                for q in pfx:
                    for n in sorted(c.ins):
                        v = model.get(q + n)
                        if v is None:
                            continue
                        # 反例里默认值（0/false）通常是求解器随手填的，
                        # 只保留非默认输入，人才看得清哪些位真正相关。
                        if smt.is_default(v) and p.kind != "relational":
                            continue
                        r.counterexample[q + n] = smt.fmt_value(v)
                    for n in sorted(c.outs):
                        v = model.get(q + n)
                        if v is not None:
                            r.outputs[q + n] = smt.fmt_value(v)
                # 等价性反例里 STCE=0 正好是「默认值」，会被上面滤掉；
                # explain_fn 把 addr / 特权 / STCE / 两侧判决译成可读字段。
                if p.explain_fn is not None:
                    r.counterexample = {**p.explain_fn(model, c), **r.counterexample}
            return r
        except SystemExit:
            raise
        except Exception as e:                                   # noqa: BLE001
            return Result(p, ERROR, message=f"{type(e).__name__}: {e}")

    def run(self, props: List[Property], progress: bool = True) -> List[Result]:
        out = []
        for i, p in enumerate(props, 1):
            r = self.run_one(p)
            out.append(r)
            if progress:
                mark = {HOLDS: "  ok", VIOLATED: "FAIL", VACUOUS: "VACU",
                        UNKNOWN: " unk", ERROR: " ERR"}[r.status]
                print(f"  [{i:3d}/{len(props)}] {mark}  {r.prop.pid:34s} "
                      f"{r.seconds:5.2f}s  {r.prop.title}", flush=True)
        return out


def summarize(results: List[Result]) -> Dict[str, int]:
    s = {HOLDS: 0, VIOLATED: 0, VACUOUS: 0, UNKNOWN: 0, ERROR: 0}
    for r in results:
        s[r.status] += 1
    return s


def total_seconds(results: List[Result]) -> float:
    return sum(r.seconds + r.vacuity_seconds for r in results)


def timed(fn, *a, **kw):
    t0 = time.time()
    v = fn(*a, **kw)
    return v, time.time() - t0
