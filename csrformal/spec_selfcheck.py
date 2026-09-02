"""规格自洽：Python 规格函数与 SMT 公式必须对同一输入空间判决一致。

为什么单独做这一步
------------------
EQ 的待证公式走 *_smt，反例解释走 Python 函数。两套实现，改一边漏一边
会让「译.spec」和求解器用的规格对不上。这里不引入第三套无结构 SMT。

CSRPermit：复用 permit_terms / permit_as_smt / permit_smt / eq_assumes。
TrapEntry：复用 trap_entry_{m,hs} / trap_entry_{m,hs}_smt / tval_smt / eq_assumes_*。
VS / epc 本轮不做。

检查顺序
--------
1. 真空：eq_assumes 可满足（permit 还要求存在一次真实访问）。
2. 主结论：同一套 eq_assumes 下两边不等价 ⇒ 应 unsat（permit）；
   TrapEntry 用点测 + 随机具体化对照 Python 与 SMT。
3. 补充点测：已知场景 + 从假设集随机具体化。
"""
from typing import Dict, List, Tuple

from . import spec_permit, spec_trap_entry
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

    bad += _trap_entry_selfcheck(z3, n_random)

    print(f"\n规格自洽：{'通过' if bad == 0 else f'失败 {bad} 处'}")
    return 1 if bad else 0


# TrapEntry 自检用的端口，不依赖 RTL。1-bit 用 Bool，与 EQ 假设字符串一致。
TRAP_PORT_WIDTHS: Dict[str, int] = {
    "valid": 1,
    "in_hasDTExcp": 1,
    "in_privState_PRVM": 2,
    "in_privState_V": 1,
    "in_mstatus_MIE": 1,
    "in_mstatus_SIE": 1,
    "in_hstatus_SPVP": 1,
    "in_causeNO_Interrupt": 1,
    "in_causeNO_ExceptionCode": 63,
    "in_trapPc": 50,
    "in_trapPcGPA": 56,
    "in_memExceptionVAddr": 64,
    "in_memExceptionGPAddr": 64,
    "in_trapInst_bits": 32,
    "in_trapInst_valid": 1,
    "in_isCrossPageIPF": 1,
    "in_iMode_V": 1,
    "in_dMode_V": 1,
    "in_isHls": 1,
}
for _name, _w in spec_trap_entry.SSTATUS_AS_MSTATUS:
    TRAP_PORT_WIDTHS[f"in_mstatus_{_name}"] = _w
    TRAP_PORT_WIDTHS[f"in_sstatus_{_name}"] = _w


def make_trap_decls(z3) -> Dict:
    decls = {}
    for name, w in TRAP_PORT_WIDTHS.items():
        decls[name] = z3.Bool(name) if w == 1 else z3.BitVec(name, w)
    return decls


def _trap_int(z3, model, expr, default=0) -> int:
    v = model.eval(expr, model_completion=True)
    if z3.is_true(v):
        return 1
    if z3.is_false(v):
        return 0
    if z3.is_bv_value(v):
        return v.as_long()
    return default


def _trap_entry_selfcheck(z3, n_random: int) -> int:
    """trap_entry_*() 与 trap_entry_*_smt 在同一套 eq_assumes 下必须一致。"""
    bad = 0
    decls = make_trap_decls(z3)

    print("\n---- TrapEntry 规格 ----")
    for label, assume_fn in (
        ("M", spec_trap_entry.eq_assumes_m),
        ("HS", spec_trap_entry.eq_assumes_hs),
    ):
        assumes = parse_assumes(z3, decls, assume_fn())
        vac = z3.Solver()
        vac.add(assumes)
        if vac.check() != z3.sat:
            print(f"FAIL 真空：TrapEntry{label} eq_assumes 不可满足")
            return 1
        print(f"ok   真空：TrapEntry{label} eq_assumes 可满足")

    assumes_m = parse_assumes(z3, decls, spec_trap_entry.eq_assumes_m())
    spec_m = spec_trap_entry.trap_entry_m_smt(z3, decls)
    spec_tv = spec_trap_entry.tval_smt(z3, decls)
    s = z3.Solver()
    s.add(assumes_m)
    s.add(decls["in_privState_PRVM"] == 1)
    s.add(z3.Not(decls["in_privState_V"]))
    s.add(decls["in_mstatus_MIE"])
    s.add(z3.Not(decls["in_causeNO_Interrupt"]))
    s.add(decls["in_causeNO_ExceptionCode"] == 2)
    if s.check() != z3.sat:
        print("FAIL 点测：TrapEntryM 已知场景与 eq_assumes 冲突")
        bad += 1
    else:
        m = s.model()
        py = spec_trap_entry.trap_entry_m(1, False, True, False, 2)
        if (bool(m.eval(spec_m["mpie"])) != py.mpie or
                bool(m.eval(spec_m["mie"])) != py.mie or
                m.eval(spec_m["mpp"]).as_long() != py.mpp or
                bool(m.eval(spec_m["mpv"])) != py.mpv or
                m.eval(spec_m["prvm"]).as_long() != py.prvm):
            print("FAIL 点测：TrapEntryM Python 与 SMT 不一致")
            bad += 1
        else:
            print("ok   点测：TrapEntryM HS+MIE=1 → MPIE=1,MIE=0,MPP=1,特权=M")

    s = z3.Solver()
    s.add(assumes_m)
    s.add(z3.Not(decls["in_causeNO_Interrupt"]))
    s.add(decls["in_causeNO_ExceptionCode"] == 21)
    s.add(decls["in_memExceptionGPAddr"] == 0x40)
    s.add(decls["in_memExceptionVAddr"] == 0x1234)
    if s.check() != z3.sat:
        print("FAIL 点测：LS-GPF tval2 与 eq_assumes 冲突")
        bad += 1
    else:
        m = s.model()
        py2 = spec_trap_entry.spec_tval2(False, 21, 0, False, 0x40)
        pyt = spec_trap_entry.spec_tval(False, 21, 0, False, 0x1234, 0, False)
        if m.eval(spec_tv["tval2"]).as_long() != py2:
            print("FAIL 点测：LS-GPF tval2 Python 与 SMT 不一致")
            bad += 1
        elif m.eval(spec_tv["tval"]).as_long() != pyt:
            print("FAIL 点测：LS-GPF tval Python 与 SMT 不一致")
            bad += 1
        else:
            print("ok   点测：LS-GPF tval = memVA，tval2 = memGPA>>2")

    s = z3.Solver()
    s.add(assumes_m)
    s.add(z3.Not(decls["in_causeNO_Interrupt"]))
    s.add(decls["in_causeNO_ExceptionCode"] == 13)
    s.add(decls["in_memExceptionVAddr"] == 0x2000)
    if s.check() != z3.sat:
        print("FAIL 点测：LPF tval 与 eq_assumes 冲突")
        bad += 1
    else:
        m = s.model()
        pyt = spec_trap_entry.spec_tval(False, 13, 0, False, 0x2000, 0, False)
        if m.eval(spec_tv["tval"]).as_long() != pyt:
            print("FAIL 点测：LPF tval Python 与 SMT 不一致")
            bad += 1
        else:
            print("ok   点测：LPF tval = memVA")

    s = z3.Solver()
    s.add(assumes_m)
    s.add(z3.Not(decls["in_causeNO_Interrupt"]))
    s.add(decls["in_causeNO_ExceptionCode"] == 2)
    s.add(decls["in_trapInst_valid"])
    s.add(decls["in_trapInst_bits"] == 0x13)
    if s.check() != z3.sat:
        print("FAIL 点测：II tval 与 eq_assumes 冲突")
        bad += 1
    else:
        m = s.model()
        pyt = spec_trap_entry.spec_tval(False, 2, 0, False, 0, 0x13, True)
        if m.eval(spec_tv["tval"]).as_long() != pyt:
            print("FAIL 点测：II tval Python 与 SMT 不一致")
            bad += 1
        else:
            print("ok   点测：II tval = 指令位")

    s = z3.Solver()
    s.add(assumes_m)
    s.add(z3.Not(decls["in_causeNO_Interrupt"]))
    s.add(decls["in_causeNO_ExceptionCode"] == 12)
    s.add(decls["in_isCrossPageIPF"])
    s.add(decls["in_trapPc"] == 0x100)
    if s.check() != z3.sat:
        print("FAIL 点测：跨页 IPF tval 与 eq_assumes 冲突")
        bad += 1
    else:
        m = s.model()
        pyt = spec_trap_entry.spec_tval(False, 12, 0x100, True, 0, 0, False)
        if m.eval(spec_tv["tval"]).as_long() != pyt:
            print("FAIL 点测：跨页 IPF tval Python 与 SMT 不一致")
            bad += 1
        else:
            print("ok   点测：跨页 IPF tval = PC+2")

    assumes_hs = parse_assumes(z3, decls, spec_trap_entry.eq_assumes_hs())
    spec_hs = spec_trap_entry.trap_entry_hs_smt(z3, decls)
    s = z3.Solver()
    s.add(assumes_hs)
    s.add(decls["in_privState_PRVM"] == 0)
    s.add(z3.Not(decls["in_privState_V"]))
    s.add(decls["in_mstatus_SIE"])
    if s.check() != z3.sat:
        print("FAIL 点测：TrapEntryHS 已知场景与 eq_assumes 冲突")
        bad += 1
    else:
        m = s.model()
        py = spec_trap_entry.trap_entry_hs(0, False, True, False, False, 0)
        if (bool(m.eval(spec_hs["spie"])) != py.spie or
                bool(m.eval(spec_hs["sie"])) != py.sie or
                bool(m.eval(spec_hs["spp"])) != py.spp):
            print("FAIL 点测：TrapEntryHS Python 与 SMT 不一致")
            bad += 1
        else:
            print("ok   点测：TrapEntryHS HU+SIE=1 → SPIE=1,SIE=0,SPP=0")

    s = z3.Solver()
    s.add(assumes_m)
    compared = 0
    for _ in range(n_random):
        if s.check() != z3.sat:
            break
        m = s.model()
        prvm = _trap_int(z3, m, decls["in_privState_PRVM"])
        v = bool(_trap_int(z3, m, decls["in_privState_V"]))
        mie = bool(_trap_int(z3, m, decls["in_mstatus_MIE"]))
        interrupt = bool(_trap_int(z3, m, decls["in_causeNO_Interrupt"]))
        code = _trap_int(z3, m, decls["in_causeNO_ExceptionCode"])
        py = spec_trap_entry.trap_entry_m(prvm, v, mie, interrupt, code)
        cross = bool(_trap_int(z3, m, decls["in_isCrossPageIPF"]))
        mem_gpa = _trap_int(z3, m, decls["in_memExceptionGPAddr"])
        pc_gpa = _trap_int(z3, m, decls["in_trapPcGPA"])
        py2 = spec_trap_entry.spec_tval2(interrupt, code, pc_gpa, cross, mem_gpa)
        pyt = spec_trap_entry.spec_tval(
            interrupt, code,
            _trap_int(z3, m, decls["in_trapPc"]),
            cross,
            _trap_int(z3, m, decls["in_memExceptionVAddr"]),
            _trap_int(z3, m, decls["in_trapInst_bits"]),
            bool(_trap_int(z3, m, decls["in_trapInst_valid"])),
        )
        smt_tv = m.eval(spec_tv["tval"]).as_long()
        # exclude 类 Python 为 None，SMT 仍给出 0；两边都不进主定理。
        tval_ok = pyt is None or smt_tv == pyt
        if (bool(m.eval(spec_m["mpie"])) != py.mpie or
                m.eval(spec_m["mpp"]).as_long() != py.mpp or
                bool(m.eval(spec_m["interrupt"])) != py.interrupt or
                m.eval(spec_tv["tval2"]).as_long() != py2 or
                not tval_ok):
            print(f"FAIL 随机点 TrapEntryM priv={spec_trap_entry.mode_name(prvm, v)}")
            bad += 1
            break
        compared += 1
        s.add(z3.Or(
            decls["in_privState_PRVM"] != m.eval(decls["in_privState_PRVM"]),
            decls["in_mstatus_MIE"] != m.eval(decls["in_mstatus_MIE"]),
            decls["in_causeNO_ExceptionCode"] != m.eval(decls["in_causeNO_ExceptionCode"]),
            decls["in_causeNO_Interrupt"] != m.eval(decls["in_causeNO_Interrupt"]),
        ))
    print(f"{'ok' if bad == 0 else 'FAIL'}   随机点：TrapEntryM 比对 {compared} 个具体化模型")
    return bad
