"""TrapEntry 陷入次态的独立规格，禁止从 Chisel 比较器翻译。

next(priv, status, cause) → 陷入后被规范点名的 CSR 字段。

权威只来自特权手册 / SpecRef。RTL 只用来对齐端口名和位宽。
本文件同时提供：
  * 可执行的 Python 次态函数（反例翻译、人工抽查）
  * 绑到同一套 Circuit.decls 上的 z3 公式（EQ 主定理）

覆盖范围（本轮）
--------------
陷入 M / HS 时手册写成赋值句的字段：

* M：MIE←0、MPIE←MIE、MPP←当前特权、MPV←当前 V、新特权=M、
  mcause←输入 cause（norm:mstatus_xpie_xie_xpp_trap_op /
  norm:mstatus_mpv_op / norm:H_trap_m_csrwrites / norm:mcause_op）
* HS：SIE←0、SPIE←SIE、SPP←(来自 U 则 0 否则 1)、SPV←当前 V、
  SPVP（V=1 时 ←SPP，否则保持）、新特权=HS、scause←输入 cause
  （norm:sstatus_spie / norm:sstatus_spp / norm:H_trap_hs_csrwrites /
  norm:hstatus_spvp_op）

别名表（必须先建，漏一条就会假红）
--------------------------------
体系结构上 sstatus 是 mstatus 的视图（同一批位）。这些模块把
mstatus / sstatus / vsstatus 当成三组独立输入端口。RTL 读
`current.sstatus.SIE` 写 SPIE 时，规格若拿 `in_mstatus_SIE` 比，
SMT 会把两个自由变量判成不等。

* sstatus 重叠字段必须 (= in_sstatus_X in_mstatus_X)。
* vsstatus 是另一份 CSR，不是 mstatus 的别名。禁止把
  vsstatus.SIE 钉成 mstatus.SIE——那会把 VS 陷入的真分歧盖掉。

显式不覆盖（假设关掉，或根本不比）
--------------------------------
- NMI / TrapEntryMN（本轮不做 MN 次态）
- debug / TrapEntryD（精化后 registers≠0，跳过，禁止假装时序完整）
- 自定义 tval：mtval / mtval2 / mtinst / stval / htval / htinst、GVA
- mepc / sepc 的 VA 合法化与 fetchMalAddr
- Smdbltrp 非预期陷入（hasDTExcp）：假设关掉，否则 mcause 被改写成 DT
- Ssdbltrp 的 SDT / MDT 次态：本轮不进主定理

未覆盖字段不要用 RTL 行为填进 spec 来「凑绿」。
"""
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .props import SpecRef

# ---------------------------------------------------------------- 条款出处
# 错误的 id 比没有更糟。没有锚点就 SpecRef(None, note=)。

R = {
    "xpie":   SpecRef("norm:mstatus_xpie_xie_xpp_trap_op", "priv/machine.adoc"),
    "mpv":    SpecRef("norm:mstatus_mpv_op", "priv/hypervisor.adoc"),
    "m_wr":   SpecRef("norm:H_trap_m_csrwrites", "priv/hypervisor.adoc"),
    "mcause": SpecRef("norm:mcause_op", "priv/machine.adoc"),
    "mc_int": SpecRef("norm:mcause_intr_op", "priv/machine.adoc"),
    "spie":   SpecRef("norm:sstatus_spie", "priv/supervisor.adoc"),
    "spp":    SpecRef("norm:sstatus_spp", "priv/supervisor.adoc"),
    "hs_wr":  SpecRef("norm:H_trap_hs_csrwrites", "priv/hypervisor.adoc"),
    "spvp":   SpecRef("norm:hstatus_spvp_op", "priv/hypervisor.adoc"),
    # 正文有「sstatus 是 mstatus 的子集」，但没有独立 norm: 锚点。
    "alias":  SpecRef(None, "priv/supervisor.adoc（sstatus 是 mstatus 视图）",
                      "查过 isa-manual：supervisor.adoc 在 sstatus_spie 段落后写"
                      "「The sstatus register is a subset of the mstatus register」，"
                      "没有单独的 norm: 锚点。别名表按这句建，不硬凑 id。"),
}

CLAUSE_REFS_M: List[SpecRef] = [
    R["xpie"], R["mpv"], R["m_wr"], R["mcause"], R["mc_int"], R["alias"],
]
CLAUSE_REFS_HS: List[SpecRef] = [
    R["xpie"], R["spie"], R["spp"], R["hs_wr"], R["spvp"], R["alias"],
]


# sstatus 与 mstatus 重叠的字段。位宽按手册 / XiangShan Bundle 对齐，
# 不是从比较器抄来的。VS/FS/XS 是 2-bit ContextStatus；UXL 是 2-bit XLEN。
# SD 是只读汇总位，也是同一批物理位，漏了同样会假红。
SSTATUS_AS_MSTATUS: Tuple[Tuple[str, int], ...] = (
    ("SIE", 1), ("SPIE", 1), ("UBE", 1), ("SPP", 1),
    ("VS", 2), ("FS", 2), ("XS", 2),
    ("SUM", 1), ("MXR", 1), ("SDT", 1),
    ("UXL", 2), ("SD", 1),
)


@dataclass(frozen=True)
class TrapMNext:
    """陷入 M 后，本轮规格覆盖的次态。"""
    mie: bool
    mpie: bool
    mpp: int
    mpv: bool
    prvm: int
    v: bool
    interrupt: bool
    exception_code: int


@dataclass(frozen=True)
class TrapHSNext:
    """陷入 HS 后，本轮规格覆盖的次态。"""
    sie: bool
    spie: bool
    spp: bool
    spv: bool
    spvp: bool
    prvm: int
    v: bool
    interrupt: bool
    exception_code: int


def trap_entry_m(prvm: int, v: bool, mie: bool,
                 interrupt: bool, exception_code: int) -> TrapMNext:
    """陷入 M：xPIE←xIE、xIE←0、xPP←y、MPV←V、特权←M、mcause←cause。"""
    return TrapMNext(
        mie=False,
        mpie=bool(mie),
        mpp=int(prvm),
        mpv=bool(v),
        prvm=3,
        v=False,
        interrupt=bool(interrupt),
        exception_code=int(exception_code),
    )


def trap_entry_hs(prvm: int, v: bool, sie: bool, old_spvp: bool,
                  interrupt: bool, exception_code: int) -> TrapHSNext:
    """陷入 HS：SPIE←SIE、SIE←0、SPP←(y≠U)、SPV←V、SPVP、特权←HS、scause。"""
    from_user = int(prvm) == 0
    spp = not from_user
    return TrapHSNext(
        sie=False,
        spie=bool(sie),
        spp=bool(spp),
        spv=bool(v),
        spvp=bool(spp) if v else bool(old_spvp),
        prvm=1,
        v=False,
        interrupt=bool(interrupt),
        exception_code=int(exception_code),
    )


def alias_assumes() -> List[str]:
    """sstatus 是 mstatus 视图。vsstatus 不在这里钉。"""
    return [
        f"(= in_sstatus_{name} in_mstatus_{name})"
        for name, _w in SSTATUS_AS_MSTATUS
    ]


def legal_priv_assumes(prvm: str = "in_privState_PRVM",
                       v: str = "in_privState_V") -> List[str]:
    """PRVM∈{U,S,M}，M 不能带 V=1。PRVM=2 是编码空洞。"""
    return [
        f"(or (= {prvm} (_ bv0 2))"
        f" (= {prvm} (_ bv1 2))"
        f" (= {prvm} (_ bv3 2)))",
        f"(=> (= {prvm} (_ bv3 2)) (not {v}))",
    ]


def eq_assumes_m() -> List[str]:
    """TrapEntryM 的声明假设。集合必须可满足。"""
    return [
        # 事件发生。数据位虽是组合常算，定理说的是「陷入时」的次态。
        "(= valid true)",
        # 非预期双陷入改写 mcause，本轮不建模。
        "(= in_hasDTExcp false)",
        *legal_priv_assumes(),
        *alias_assumes(),
    ]


def eq_assumes_hs() -> List[str]:
    """TrapEntryHS 的声明假设。别名表在这里是负载，不是摆设。"""
    return [
        "(= valid true)",
        *legal_priv_assumes(),
        *alias_assumes(),
    ]


def _d(decls: Dict, name: str):
    if name not in decls:
        raise KeyError(f"规格公式找不到端口 {name}；先核对精化顶层的端口名")
    return decls[name]


def trap_entry_m_smt(z3, decls: Dict) -> Dict[str, object]:
    """返回各次态字段的规格表达式，已绑到 Circuit 端口。"""
    prvm = _d(decls, "in_privState_PRVM")
    v = _d(decls, "in_privState_V")
    mie = _d(decls, "in_mstatus_MIE")
    interrupt = _d(decls, "in_causeNO_Interrupt")
    code = _d(decls, "in_causeNO_ExceptionCode")
    return {
        "mie": z3.BoolVal(False),
        "mpie": mie,
        "mpp": prvm,
        "mpv": v,
        "prvm": z3.BitVecVal(3, 2),
        "v": z3.BoolVal(False),
        "interrupt": interrupt,
        "exception_code": code,
    }


def trap_entry_hs_smt(z3, decls: Dict) -> Dict[str, object]:
    """HS 次态。SPIE 读 mstatus.SIE：与 sstatus.SIE 靠别名假设对齐。"""
    prvm = _d(decls, "in_privState_PRVM")
    v = _d(decls, "in_privState_V")
    # 规格读架构视图（mstatus.SIE）。RTL 读 in_sstatus_SIE。
    # 没有 alias_assumes 这条就会假红，普查 HS2 已经栽过。
    sie = _d(decls, "in_mstatus_SIE")
    old_spvp = _d(decls, "in_hstatus_SPVP")
    interrupt = _d(decls, "in_causeNO_Interrupt")
    code = _d(decls, "in_causeNO_ExceptionCode")
    from_user = prvm == 0
    spp = z3.Not(from_user)
    return {
        "sie": z3.BoolVal(False),
        "spie": sie,
        "spp": spp,
        "spv": v,
        "spvp": z3.If(v, spp, old_spvp),
        "prvm": z3.BitVecVal(1, 2),
        "v": z3.BoolVal(False),
        "interrupt": interrupt,
        "exception_code": code,
    }


def eq_prove_m(circuit) -> object:
    z3 = circuit.z3
    spec = trap_entry_m_smt(z3, circuit.decls)
    d = circuit.decls
    return z3.And(
        d["out_mstatus_bits_MIE"] == spec["mie"],
        d["out_mstatus_bits_MPIE"] == spec["mpie"],
        d["out_mstatus_bits_MPP"] == spec["mpp"],
        d["out_mstatus_bits_MPV"] == spec["mpv"],
        d["out_privState_bits_PRVM"] == spec["prvm"],
        d["out_privState_bits_V"] == spec["v"],
        d["out_mcause_bits_Interrupt"] == spec["interrupt"],
        d["out_mcause_bits_ExceptionCode"] == spec["exception_code"],
    )


def eq_prove_hs(circuit) -> object:
    z3 = circuit.z3
    spec = trap_entry_hs_smt(z3, circuit.decls)
    d = circuit.decls
    return z3.And(
        d["out_mstatus_bits_SIE"] == spec["sie"],
        d["out_mstatus_bits_SPIE"] == spec["spie"],
        d["out_mstatus_bits_SPP"] == spec["spp"],
        d["out_hstatus_bits_SPV"] == spec["spv"],
        d["out_hstatus_bits_SPVP"] == spec["spvp"],
        d["out_privState_bits_PRVM"] == spec["prvm"],
        d["out_privState_bits_V"] == spec["v"],
        d["out_scause_bits_Interrupt"] == spec["interrupt"],
        d["out_scause_bits_ExceptionCode"] == spec["exception_code"],
    )


def _model_int(model: Dict, name: str, default: int = 0) -> int:
    v = model.get(name)
    if v is None:
        return default
    try:
        import z3
        if z3.is_true(v):
            return 1
        if z3.is_false(v):
            return 0
        if z3.is_bv_value(v):
            return v.as_long()
    except Exception:  # noqa: BLE001
        pass
    return default


def mode_name(prvm: int, v: bool) -> str:
    if prvm == 3 and not v:
        return "M"
    if prvm == 1 and not v:
        return "HS"
    if prvm == 0 and not v:
        return "HU"
    if prvm == 1 and v:
        return "VS"
    if prvm == 0 and v:
        return "VU"
    return f"PRVM={prvm},V={int(bool(v))}"


def explain_eq_model_m(model: Dict, _circuit=None) -> Dict[str, str]:
    prvm = _model_int(model, "in_privState_PRVM")
    v = bool(_model_int(model, "in_privState_V"))
    mie = bool(_model_int(model, "in_mstatus_MIE"))
    sie_m = bool(_model_int(model, "in_mstatus_SIE"))
    sie_s = bool(_model_int(model, "in_sstatus_SIE"))
    interrupt = bool(_model_int(model, "in_causeNO_Interrupt"))
    code = _model_int(model, "in_causeNO_ExceptionCode")
    spec = trap_entry_m(prvm, v, mie, interrupt, code)
    return {
        "译.priv": mode_name(prvm, v),
        "译.MIE": str(int(mie)),
        "译.别名SIE": f"mstatus.SIE={int(sie_m)} sstatus.SIE={int(sie_s)}",
        "译.cause": f"{'int' if interrupt else 'ex'} {code}",
        "译.spec": (f"MIE={int(spec.mie)} MPIE={int(spec.mpie)} "
                    f"MPP={spec.mpp} MPV={int(spec.mpv)} "
                    f"priv={mode_name(spec.prvm, spec.v)}"),
        "译.rtl": (f"MIE={_model_int(model, 'out_mstatus_bits_MIE')} "
                   f"MPIE={_model_int(model, 'out_mstatus_bits_MPIE')} "
                   f"MPP={_model_int(model, 'out_mstatus_bits_MPP')} "
                   f"MPV={_model_int(model, 'out_mstatus_bits_MPV')} "
                   f"priv={mode_name(_model_int(model, 'out_privState_bits_PRVM'), bool(_model_int(model, 'out_privState_bits_V')))}"),
    }


def explain_eq_model_hs(model: Dict, _circuit=None) -> Dict[str, str]:
    prvm = _model_int(model, "in_privState_PRVM")
    v = bool(_model_int(model, "in_privState_V"))
    sie_m = bool(_model_int(model, "in_mstatus_SIE"))
    sie_s = bool(_model_int(model, "in_sstatus_SIE"))
    old_spvp = bool(_model_int(model, "in_hstatus_SPVP"))
    interrupt = bool(_model_int(model, "in_causeNO_Interrupt"))
    code = _model_int(model, "in_causeNO_ExceptionCode")
    spec = trap_entry_hs(prvm, v, sie_m, old_spvp, interrupt, code)
    return {
        "译.priv": mode_name(prvm, v),
        "译.别名SIE": f"mstatus.SIE={int(sie_m)} sstatus.SIE={int(sie_s)}",
        "译.cause": f"{'int' if interrupt else 'ex'} {code}",
        "译.spec": (f"SIE={int(spec.sie)} SPIE={int(spec.spie)} "
                    f"SPP={int(spec.spp)} SPV={int(spec.spv)} "
                    f"SPVP={int(spec.spvp)} priv={mode_name(spec.prvm, spec.v)}"),
        "译.rtl": (f"SIE={_model_int(model, 'out_mstatus_bits_SIE')} "
                   f"SPIE={_model_int(model, 'out_mstatus_bits_SPIE')} "
                   f"SPP={_model_int(model, 'out_mstatus_bits_SPP')} "
                   f"SPV={_model_int(model, 'out_hstatus_bits_SPV')} "
                   f"priv={mode_name(_model_int(model, 'out_privState_bits_PRVM'), bool(_model_int(model, 'out_privState_bits_V')))}"),
    }
