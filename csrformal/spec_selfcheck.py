"""规格自洽：permit()（Python）与 permit_smt()（z3）必须对同一输入空间判决一致。

为什么单独做这一步
------------------
EQ 的待证公式走 permit_smt，反例解释走 permit()。两套实现，改一边漏一边
会让「译.spec」和求解器用的规格对不上。这里不引入第三套无结构 SMT，
复用 permit_terms / permit_as_smt / permit_smt / eq_assumes。

检查顺序
--------
1. 真空：eq_assumes 可满足，且存在一次真实访问（ren ∨ wen）。
2. 主结论：在同一套 eq_assumes 下，permit_as_smt（由 permit() 决策体
   编成）与 permit_smt 的 II/VI 不等价 ⇒ 应 unsat。
3. 补充点测：已知场景 + 从假设集随机具体化，两边逐点比对。
"""
from typing import Dict, List, Tuple

from . import spec_permit
from .spec_permit import Enables, Stateen, permit, permit_as_smt, permit_smt

# 与 CSRPermitModule 精化顶层对齐，只列 eq_assumes / permit_smt 用到的端口。
# 不依赖 RTL：自检必须在没精化时也能跑。
SPEC_PORT_WIDTHS: Dict[str, int] = {
    "io_in_csrAccess_addr": 12,
    "io_in_csrAccess_ren": 1,
    "io_in_csrAccess_wen": 1,
    "io_in_debugMode": 1,
    "io_in_privState_PRVM": 2,
    "io_in_privState_V": 1,
    "io_in_status_mstatusFSOff": 1,
    "io_in_status_mstatusVSOff": 1,
    "io_in_status_tvm": 1,
    "io_in_status_vgein": 6,
    "io_in_status_vsstatusFSOff": 1,
    "io_in_status_vsstatusVSOff": 1,
    "io_in_status_vtvm": 1,
    "io_in_xRet_dret": 1,
    "io_in_xRet_mnret": 1,
    "io_in_xRet_mret": 1,
    "io_in_xRet_sret": 1,
    "io_in_xcounteren_hcounteren": 32,
    "io_in_xcounteren_mcounteren": 32,
    "io_in_xcounteren_scounteren": 32,
    "io_in_xenvcfg_henvcfg": 64,
    "io_in_xenvcfg_menvcfg": 64,
    "io_in_aia_hvictlVTI": 1,
    "io_in_aia_mvienSEIE": 1,
    "io_in_aia_miselect": 64,
    "io_in_aia_siselect": 64,
    "io_in_aia_vsiselect": 64,
    "io_in_xstateen_hstateen0_AIA": 1,
    "io_in_xstateen_hstateen0_C": 1,
    "io_in_xstateen_hstateen0_CONTEXT": 1,
    "io_in_xstateen_hstateen0_CSRIND": 1,
    "io_in_xstateen_hstateen0_ENVCFG": 1,
    "io_in_xstateen_hstateen0_IMSIC": 1,
    "io_in_xstateen_hstateen0_SE0": 1,
    "io_in_xstateen_hstateen1_SE": 1,
    "io_in_xstateen_hstateen2_SE": 1,
    "io_in_xstateen_hstateen3_SE": 1,
    "io_in_xstateen_mstateen0_AIA": 1,
    "io_in_xstateen_mstateen0_C": 1,
    "io_in_xstateen_mstateen0_CONTEXT": 1,
    "io_in_xstateen_mstateen0_CSRIND": 1,
    "io_in_xstateen_mstateen0_ENVCFG": 1,
    "io_in_xstateen_mstateen0_IMSIC": 1,
    "io_in_xstateen_mstateen0_SE0": 1,
    "io_in_xstateen_mstateen1_SE": 1,
    "io_in_xstateen_mstateen2_SE": 1,
    "io_in_xstateen_mstateen3_SE": 1,
    "io_in_xstateen_sstateen0_C": 1,
}


def make_spec_decls(z3) -> Dict:
    decls = {}
    for name, w in SPEC_PORT_WIDTHS.items():
        decls[name] = z3.Bool(name) if w == 1 else z3.BitVec(name, w)
    return decls


def parse_assumes(z3, decls: Dict, texts: List[str]):
    """eq_assumes() 已是 SMT-LIB 字符串，复用同一套 decls 解析，不手写公式。"""
    if not texts:
        return z3.BoolVal(True)
    body = "(assert (and " + " ".join(texts) + "))" if len(texts) > 1 \
        else f"(assert {texts[0]})"
    parsed = z3.parse_smt2_string(body, decls=decls)
    return z3.And(*parsed) if len(parsed) > 1 else parsed[0]


def _smt_verdict(z3, spec_ii, spec_vi) -> str:
    if z3.is_true(spec_ii):
        return "II"
    if z3.is_true(spec_vi):
        return "VI"
    return "NONE"


def _model_int(z3, model, expr, default=0) -> int:
    v = model.eval(expr, model_completion=True)
    if z3.is_true(v):
        return 1
    if z3.is_false(v):
        return 0
    if z3.is_bv_value(v):
        return v.as_long()
    return default


def enables_from_model(z3, model, decls) -> Tuple[int, bool, int, bool, bool, Enables]:
    """把 z3 模型具体化成 permit() 的 Python 输入。"""
    def d(name, default=0):
        return _model_int(z3, model, decls[name], default)

    def st_bit(name):
        return bool(d(f"io_in_xstateen_{name}", 1))

    st = Stateen(
        m_se=tuple(st_bit(p) for p in spec_permit.STATEEN_SE_M),
        h_se=tuple(st_bit(p) for p in spec_permit.STATEEN_SE_H),
        m_envcfg=st_bit("mstateen0_ENVCFG"),
        h_envcfg=st_bit("hstateen0_ENVCFG"),
        m_context=st_bit("mstateen0_CONTEXT"),
        h_context=st_bit("hstateen0_CONTEXT"),
        m_imsic=st_bit("mstateen0_IMSIC"),
        h_imsic=st_bit("hstateen0_IMSIC"),
        m_csrind=st_bit("mstateen0_CSRIND"),
        h_csrind=st_bit("hstateen0_CSRIND"),
    )
    menv = d("io_in_xenvcfg_menvcfg")
    henv = d("io_in_xenvcfg_henvcfg")
    en = Enables(
        mcounteren=d("io_in_xcounteren_mcounteren"),
        hcounteren=d("io_in_xcounteren_hcounteren"),
        scounteren=d("io_in_xcounteren_scounteren"),
        menvcfg_stce=bool((menv >> 63) & 1),
        henvcfg_stce=bool((henv >> 63) & 1),
        tvm=bool(d("io_in_status_tvm")),
        vtvm=bool(d("io_in_status_vtvm")),
        debug_mode=bool(d("io_in_debugMode")),
        stateen=st,
    )
    return (d("io_in_privState_PRVM"), bool(d("io_in_privState_V")),
            d("io_in_csrAccess_addr"), bool(d("io_in_csrAccess_ren")),
            bool(d("io_in_csrAccess_wen")), en)


def _known_points():
    """对照 case 层语义的选点，只作补充，不替代 unsat。"""
    clean = Enables()
    stce0 = Enables(menvcfg_stce=False, henvcfg_stce=False)
    return [
        # S3：HS 访 vstimecmp、STCE=0 → II（恢复后的 stce_op2）
        (1, False, 0x24D, True, False, stce0, "II"),
        (1, False, 0x14D, True, False, stce0, "II"),
        (1, False, 0x24D, True, False, clean, "NONE"),
        (3, False, 0x24D, True, False, stce0, "NONE"),
        (0, True, 0x24D, True, False, stce0, "II"),
        # 无访问
        (1, False, 0x24D, False, False, clean, "NONE"),
        # 只读写
        (3, False, 0xC00, False, True, clean, "II"),
        # TVM
        (1, False, 0x180, True, False, Enables(tvm=True), "II"),
    ]


def run_selfcheck(n_random: int = 64) -> int:
    import z3
    decls = make_spec_decls(z3)
    assumes = parse_assumes(z3, decls, spec_permit.eq_assumes())
    access = z3.Or(decls["io_in_csrAccess_ren"], decls["io_in_csrAccess_wen"])
    bad = 0

    vac = z3.Solver()
    vac.add(assumes)
    if vac.check() != z3.sat:
        print("FAIL 真空：eq_assumes 不可满足")
        return 1
    print("ok   真空：eq_assumes 可满足")

    vac2 = z3.Solver()
    vac2.add(assumes, access)
    if vac2.check() != z3.sat:
        print("FAIL 真空：eq_assumes ∧ (ren∨wen) 不可满足")
        return 1
    print("ok   真空：存在一次真实访问")

    spec_ii, spec_vi = permit_smt(z3, decls)
    py_ii, py_vi = permit_as_smt(z3, decls)

    diverge = z3.Solver()
    diverge.add(assumes)
    diverge.add(z3.Or(spec_ii != py_ii, spec_vi != py_vi))
    r = diverge.check()
    if r == z3.sat:
        m = diverge.model()
        prvm, v, addr, ren, wen, en = enables_from_model(z3, m, decls)
        py = permit(prvm, v, addr, ren, wen, en)
        print("FAIL 存在分歧（permit_smt 与 permit() 公式在 eq_assumes 下不等）")
        print(f"     priv={spec_permit.mode_name(prvm, v)} addr=0x{addr:03x} "
              f"ren={int(ren)} wen={int(wen)} permit()={py}")
        print(f"     permit_smt II={m.eval(spec_ii)} VI={m.eval(spec_vi)}")
        print(f"     permit()   II={m.eval(py_ii)} VI={m.eval(py_vi)}")
        bad += 1
    elif r != z3.unsat:
        print(f"FAIL 等价性检查返回 {r}，不是 unsat")
        bad += 1
    else:
        print("ok   等价：permit_smt ≡ permit() 公式（eq_assumes 下 unsat）")

    for prvm, v, addr, ren, wen, en, expect in _known_points():
        got = permit(prvm, v, addr, ren, wen, en)
        if got != expect:
            print(f"FAIL 点测 permit() 0x{addr:03x} {spec_permit.mode_name(prvm, v)}"
                  f" 得到 {got}，期望 {expect}")
            bad += 1
            continue
        s = z3.Solver()
        s.add(assumes)
        s.add(decls["io_in_privState_PRVM"] == prvm)
        s.add(decls["io_in_privState_V"] == v)
        s.add(decls["io_in_csrAccess_addr"] == addr)
        s.add(decls["io_in_csrAccess_ren"] == ren)
        s.add(decls["io_in_csrAccess_wen"] == wen)
        s.add(decls["io_in_xenvcfg_menvcfg"] ==
              (0x7FFFFFFFFFFFFFFF if not en.menvcfg_stce else 0xFFFFFFFFFFFFFFFF))
        s.add(decls["io_in_xenvcfg_henvcfg"] ==
              (0x7FFFFFFFFFFFFFFF if not en.henvcfg_stce else 0xFFFFFFFFFFFFFFFF))
        s.add(decls["io_in_status_tvm"] == en.tvm)
        if s.check() != z3.sat:
            # 已知点若被 eq_assumes 关掉（例如间接窗口），跳过 SMT 侧。
            print(f"skip 点测 0x{addr:03x} 与 eq_assumes 冲突，只核了对 permit()")
            continue
        m = s.model()
        smt_v = _smt_verdict(z3, m.eval(spec_ii), m.eval(spec_vi))
        if smt_v != got:
            print(f"FAIL 点测分歧 0x{addr:03x} {spec_permit.mode_name(prvm, v)} "
                  f"permit()={got} permit_smt={smt_v}")
            bad += 1
    if bad == 0:
        print(f"ok   点测：{len(_known_points())} 个已知场景一致")

    s = z3.Solver()
    s.add(assumes, access)
    compared = 0
    for _ in range(n_random):
        if s.check() != z3.sat:
            break
        m = s.model()
        prvm, v, addr, ren, wen, en = enables_from_model(z3, m, decls)
        py = permit(prvm, v, addr, ren, wen, en)
        smt_v = _smt_verdict(z3, m.eval(spec_ii), m.eval(spec_vi))
        if py != smt_v:
            print(f"FAIL 随机点 0x{addr:03x} {spec_permit.mode_name(prvm, v)} "
                  f"permit()={py} permit_smt={smt_v}")
            bad += 1
            break
        compared += 1
        # 换一个模型：挡住本轮的地址/特权/STCE，让求解器换点。
        block = [d != m.eval(d, model_completion=True) for d in (
            decls["io_in_csrAccess_addr"],
            decls["io_in_privState_PRVM"],
            decls["io_in_privState_V"],
            decls["io_in_xenvcfg_menvcfg"],
        )]
        s.add(z3.Or(*block))
    print(f"{'ok' if bad == 0 else 'FAIL'}   随机点：比对 {compared} 个具体化模型")

    print(f"\n规格自洽：{'通过' if bad == 0 else f'失败 {bad} 处'}")
    return 1 if bad else 0
