"""TrapEntry 陷入次态的独立规格，禁止从 Chisel 比较器翻译。

next(priv, status, cause) → 陷入后被规范点名的 CSR 字段。

权威只来自特权手册 / SpecRef。RTL 只用来对齐端口名和位宽。
本文件同时提供：
  * 可执行的 Python 次态函数（反例翻译、人工抽查）
  * 绑到同一套 Circuit.decls 上的 z3 公式（EQ 主定理）

本轮交付（审查收窄后）
--------------------
1. EQ-next：手册赋值句（SIE/PP/cause/特权）。不含 tval、不含 epc。
2. EQ-tval：按异常**类**写 xtval / xtval2 / GVA，不抄 Mux1H，
   不把 genTrapVA / fetchMalAddr 写进规格，不把 tval 和 epc 绑成一条合取。

异常类（编码来自特权手册 cause 表 / norm:H_cause，不是 Chisel 名）
--------------------------------------------------------------
* fetch：IAM=0, IAF=1, IPF=12, IGPF=20
    tval = 故障指令 VA。变长指令取「出故障的那一段」
    （norm:mtval_vaddr_wr1 / norm:mtval_varlen_wr）：
    跨页第二段用 PC+2，否则 PC。PC 取输入 trapPc 零扩展，**不**做
    satp 符号/零扩展（那是 WARL，和 epc 后置同一条债）。
* mem：LAM=4, LAF=5, SAM=6, SAF=7, LPF=13, SPF=15, LGPF=21, SGPF=23
    tval = 故障访存 VA（norm:mtval_vaddr_wr1 / norm:stval_op_load_store_fault）
* inst：II=2, VI=22（VI 与 II 相同，norm:H_virtinst_xtval）
    tval = 提供的指令位，右对齐；未提供则 0
    （norm:mtval_instr_bits_list / norm:stval_op_illegal_instr）
* zero：中断、ecall(8–11)、保留、double-trap(16)
    tval = 0（norm:mtval_other_traps_zero / norm:stval_op_other_traps）
* exclude：BP=3（EBREAK 允许 0 或 PC，norm:stval_op_breakpoint，
    不把 RTL 选边写成条文）、SWC=18（软件检查原因码，不是这五类）、
    HWE=19（手册把 fetch/load/store 的 HWE 都写成「0 或 VA」，
    单靠 cause=19 分不出类，不猜）

tval2 / htval（norm:mtval2_trapval / norm:htval_trapval）
* GPF：0 或 GPA>>2。本规格取「写 GPA」这一侧的信息值：
    IGPF → (trapPcGPA 或 +2)>>2；LS-GPF → memGPA>>2。
    允许写 0 是平台句；香山不是 tval2 恒 0 的平台。不把 fetchMalTval
    写进规格。
* 其它陷阱：必须 0。Ssdbltrp 改写 mtval2 靠 hasDTExcp=0 关掉。

GVA（norm:mstatus_gva_op / norm:hstatus_gva_op）
* 列入 {misaligned, AF, PF, GPF} 且写入的是客户机 VA → 1
    （GPF 必是；fetch 看 iMode.V；mem 看 dMode.V 或 HLS）
* 未列入或中断 → 0。BP 与 tval 一同排除。HWE 未列入 → 0。

显式不做（本轮未验收，不要当成交付）
--------------------------------
- TrapEntryVS / MN / D（D 有寄存器；VS 审查要求后置）
- epc 合法化（与 genTrapVA 同一条 WARL，后置，不和 tval 绑合取）
- tinst（同步异常取值不唯一）
- MDT / SDT、NMI、debug
- 用假设钉死 isFetchMalAddr / isFetchGuestExcp / isCrossPageIPF 再报绿

别名表：sstatus 是 mstatus 视图。vsstatus 不是，禁止钉成 mstatus。
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .props import SpecRef

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
    "mtval0": SpecRef("norm:mtval_other_traps_zero", "priv/machine.adoc"),
    "stval0": SpecRef("norm:stval_op_other_traps", "priv/supervisor.adoc"),
    "mtvalv": SpecRef("norm:mtval_vaddr_wr1", "priv/machine.adoc"),
    "mtvalp": SpecRef("norm:mtval_varlen_wr", "priv/machine.adoc"),
    "mtvali": SpecRef("norm:mtval_ill_instr_exc_in_low_bits", "priv/machine.adoc"),
    "stvalv": SpecRef("norm:stval_op_faulting_addr", "priv/supervisor.adoc"),
    "stvall": SpecRef("norm:stval_op_load_store_fault", "priv/supervisor.adoc"),
    "stvali": SpecRef("norm:stval_op_illegal_instr", "priv/supervisor.adoc"),
    "stvalb": SpecRef("norm:stval_op_breakpoint", "priv/supervisor.adoc"),
    "vi_tv":  SpecRef("norm:H_virtinst_xtval", "priv/hypervisor.adoc"),
    "tval2":  SpecRef("norm:mtval2_trapval", "priv/hypervisor.adoc"),
    "htval":  SpecRef("norm:htval_trapval", "priv/hypervisor.adoc"),
    "gva_m":  SpecRef("norm:mstatus_gva_op", "priv/hypervisor.adoc"),
    "gva_h":  SpecRef("norm:hstatus_gva_op", "priv/hypervisor.adoc"),
    "h_cause": SpecRef("norm:H_cause", "priv/hypervisor.adoc"),
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
CLAUSE_REFS_TVAL_M: List[SpecRef] = [
    R["mtval0"], R["mtvalv"], R["mtvalp"], R["mtvali"], R["vi_tv"],
    R["stvalb"], R["tval2"], R["gva_m"], R["h_cause"],
]
CLAUSE_REFS_TVAL_HS: List[SpecRef] = [
    R["stval0"], R["stvalv"], R["stvall"], R["stvali"], R["stvalb"],
    R["vi_tv"], R["htval"], R["gva_h"], R["h_cause"],
]


SSTATUS_AS_MSTATUS: Tuple[Tuple[str, int], ...] = (
    ("SIE", 1), ("SPIE", 1), ("UBE", 1), ("SPP", 1),
    ("VS", 2), ("FS", 2), ("XS", 2),
    ("SUM", 1), ("MXR", 1), ("SDT", 1),
    ("UXL", 2), ("SD", 1),
)

# 手册 cause 编码。
EX_IAM, EX_IAF, EX_II, EX_BP = 0, 1, 2, 3
EX_LAM, EX_LAF, EX_SAM, EX_SAF = 4, 5, 6, 7
EX_ECALL = frozenset({8, 9, 10, 11})
EX_IPF, EX_LPF, EX_SPF = 12, 13, 15
EX_DT, EX_SWC, EX_HWE = 16, 18, 19
EX_IGPF, EX_LGPF, EX_VI, EX_SGPF = 20, 21, 22, 23

FETCH = frozenset({EX_IAM, EX_IAF, EX_IPF, EX_IGPF})
MEM = frozenset({EX_LAM, EX_LAF, EX_SAM, EX_SAF, EX_LPF, EX_SPF, EX_LGPF, EX_SGPF})
INST = frozenset({EX_II, EX_VI})
GPF = frozenset({EX_IGPF, EX_LGPF, EX_SGPF})
LS_GPF = frozenset({EX_LGPF, EX_SGPF})
# GVA 条文点名。不含 HWE、不含 II/VI。BP 与 tval 一同排除。
GVA_LIST = frozenset({
    EX_IAM, EX_IAF, EX_LAM, EX_LAF, EX_SAM, EX_SAF,
    EX_IPF, EX_LPF, EX_SPF, EX_IGPF, EX_LGPF, EX_SGPF,
})
TVAL_EXCLUDE = frozenset({EX_BP, EX_SWC, EX_HWE})

CAUSE_W = 63
TVAL_W = 64
TRAP_PC_W = 50
TRAP_PC_GPA_W = 56
TRAP_INST_W = 32

CLS_ZERO, CLS_FETCH, CLS_MEM, CLS_INST, CLS_EXCLUDE = (
    "zero", "fetch", "mem", "inst", "exclude",
)


def tval_class(interrupt: bool, exception_code: int) -> str:
    """把 cause 分到手册异常类。不看 RTL 开关名。"""
    if interrupt:
        return CLS_ZERO
    c = int(exception_code)
    if c in TVAL_EXCLUDE:
        return CLS_EXCLUDE
    if c in FETCH:
        return CLS_FETCH
    if c in MEM:
        return CLS_MEM
    if c in INST:
        return CLS_INST
    return CLS_ZERO


def spec_tval(interrupt: bool, exception_code: int, trap_pc: int,
              cross_page: bool, mem_va: int,
              inst_bits: int, inst_valid: bool) -> Optional[int]:
    """该类的 xtval。exclude 返回 None，主定理不比。不调用 genTrapVA。"""
    cls = tval_class(interrupt, exception_code)
    if cls == CLS_EXCLUDE:
        return None
    if cls == CLS_ZERO:
        return 0
    if cls == CLS_FETCH:
        pc = int(trap_pc) & ((1 << TRAP_PC_W) - 1)
        return (pc + (2 if cross_page else 0)) & ((1 << TVAL_W) - 1)
    if cls == CLS_MEM:
        return int(mem_va) & ((1 << TVAL_W) - 1)
    if inst_valid:
        return int(inst_bits) & ((1 << TRAP_INST_W) - 1)
    return 0


def spec_tval2(interrupt: bool, exception_code: int, trap_pc_gpa: int,
               cross_page: bool, mem_gpa: int) -> Optional[int]:
    """xtval2/htval。非 GPF 必须 0；GPF 取 GPA>>2。不含 fetchMalTval。"""
    if interrupt or int(exception_code) not in GPF:
        return 0
    if int(exception_code) == EX_IGPF:
        gpa = int(trap_pc_gpa) & ((1 << TRAP_PC_GPA_W) - 1)
        gpa = (gpa + (2 if cross_page else 0)) & ((1 << TVAL_W) - 1)
        return gpa >> 2
    return (int(mem_gpa) & ((1 << TVAL_W) - 1)) >> 2


def spec_gva(interrupt: bool, exception_code: int,
             imode_v: bool, dmode_v: bool, is_hls: bool) -> Optional[bool]:
    """GVA。BP 排除；未列入的（含 HWE）为 0。"""
    if interrupt:
        return False
    c = int(exception_code)
    if c == EX_BP:
        return None
    if c not in GVA_LIST:
        return False
    if c in GPF:
        return True
    if c in FETCH:
        return bool(imode_v)
    if c in MEM:
        return bool(dmode_v) or bool(is_hls)
    return False


@dataclass(frozen=True)
class TrapMNext:
    """陷入 M 后，EQ-next 覆盖的次态（不含 tval/epc）。"""
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
    """陷入 HS 后，EQ-next 覆盖的次态（不含 tval/epc）。"""
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
        mie=False, mpie=bool(mie), mpp=int(prvm), mpv=bool(v),
        prvm=3, v=False,
        interrupt=bool(interrupt), exception_code=int(exception_code),
    )


def trap_entry_hs(prvm: int, v: bool, sie: bool, old_spvp: bool,
                  interrupt: bool, exception_code: int) -> TrapHSNext:
    """陷入 HS：SPIE←SIE、SIE←0、SPP←(y≠U)、SPV←V、SPVP、特权←HS、scause。"""
    from_user = int(prvm) == 0
    spp = not from_user
    return TrapHSNext(
        sie=False, spie=bool(sie), spp=bool(spp), spv=bool(v),
        spvp=bool(spp) if v else bool(old_spvp),
        prvm=1, v=False,
        interrupt=bool(interrupt), exception_code=int(exception_code),
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
    """TrapEntryM 的声明假设。不钉 isFetchMalAddr / isCrossPageIPF。"""
    return [
        "(= valid true)",
        # Ssdbltrp 改写 mcause/mtval2，本轮不建模。
        "(= in_hasDTExcp false)",
        *legal_priv_assumes(),
        *alias_assumes(),
    ]


def eq_assumes_hs() -> List[str]:
    """TrapEntryHS 的声明假设。别名表是负载。"""
    return [
        "(= valid true)",
        *legal_priv_assumes(),
        *alias_assumes(),
    ]


def _d(decls: Dict, name: str):
    if name not in decls:
        raise KeyError(f"规格公式找不到端口 {name}；先核对精化顶层的端口名")
    return decls[name]


def _code_in(z3, code, nums) -> object:
    return z3.Or(*[code == z3.BitVecVal(n, CAUSE_W) for n in nums])


def trap_entry_m_smt(z3, decls: Dict) -> Dict[str, object]:
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
    prvm = _d(decls, "in_privState_PRVM")
    v = _d(decls, "in_privState_V")
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


def _zext(z3, expr, width: int):
    n = expr.size()
    if n == width:
        return expr
    if n > width:
        return z3.Extract(width - 1, 0, expr)
    return z3.ZeroExt(width - n, expr)


def tval_smt(z3, decls: Dict) -> Dict[str, object]:
    """EQ-tval 的规格表达式。fetch 用 trapPc 零扩展，不调用 genTrapVA。"""
    interrupt = _d(decls, "in_causeNO_Interrupt")
    code = _d(decls, "in_causeNO_ExceptionCode")
    trap_pc = _zext(z3, _d(decls, "in_trapPc"), TVAL_W)
    trap_gpa = _zext(z3, _d(decls, "in_trapPcGPA"), TVAL_W)
    mem_va = _d(decls, "in_memExceptionVAddr")
    mem_gpa = _d(decls, "in_memExceptionGPAddr")
    inst = _zext(z3, _d(decls, "in_trapInst_bits"), TVAL_W)
    inst_v = _d(decls, "in_trapInst_valid")
    cross = _d(decls, "in_isCrossPageIPF")
    imode_v = _d(decls, "in_iMode_V")
    dmode_v = _d(decls, "in_dMode_V")
    is_hls = _d(decls, "in_isHls")
    two = z3.BitVecVal(2, TVAL_W)

    is_fetch = z3.And(z3.Not(interrupt), _code_in(z3, code, FETCH))
    is_mem = z3.And(z3.Not(interrupt), _code_in(z3, code, MEM))
    is_inst = z3.And(z3.Not(interrupt), _code_in(z3, code, INST))
    is_excl = z3.And(z3.Not(interrupt), _code_in(z3, code, TVAL_EXCLUDE))
    is_zero = z3.And(z3.Not(is_excl), z3.Not(is_fetch), z3.Not(is_mem),
                     z3.Not(is_inst))
    is_gpf = z3.And(z3.Not(interrupt), _code_in(z3, code, GPF))
    is_igpf = z3.And(z3.Not(interrupt), code == z3.BitVecVal(EX_IGPF, CAUSE_W))
    is_lsgpf = z3.And(z3.Not(interrupt), _code_in(z3, code, LS_GPF))
    in_gva_list = z3.And(z3.Not(interrupt), _code_in(z3, code, GVA_LIST))
    is_bp = z3.And(z3.Not(interrupt), code == z3.BitVecVal(EX_BP, CAUSE_W))

    fetch_va = z3.If(cross, trap_pc + two, trap_pc)
    fetch_gpa = z3.If(cross, trap_gpa + two, trap_gpa)
    tval = z3.If(is_fetch, fetch_va,
                 z3.If(is_mem, mem_va,
                       z3.If(is_inst, z3.If(inst_v, inst, z3.BitVecVal(0, TVAL_W)),
                             z3.BitVecVal(0, TVAL_W))))
    # IGPF 的 tval2 用 trapPcGPA，不是 trapPc。不写 fetchMalTval。
    tval2 = z3.If(is_igpf, z3.LShR(fetch_gpa, 2),
                  z3.If(is_lsgpf, z3.LShR(mem_gpa, 2),
                        z3.BitVecVal(0, TVAL_W)))

    gva_listed = z3.If(is_gpf, z3.BoolVal(True),
                       z3.If(is_fetch, imode_v,
                             z3.If(is_mem, z3.Or(dmode_v, is_hls),
                                   z3.BoolVal(False))))
    return {
        "tval": tval,
        "tval2": tval2,
        "gva": z3.And(in_gva_list, gva_listed),
        "tval_constrained": z3.Not(is_excl),
        "tval2_constrained": z3.BoolVal(True),
        "gva_constrained": z3.Not(is_bp),
        "is_zero": is_zero,
        "is_fetch": is_fetch,
        "is_mem": is_mem,
        "is_inst": is_inst,
        "is_gpf": is_gpf,
        "is_igpf": is_igpf,
        "is_lsgpf": is_lsgpf,
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


def _tval2_gva_prove(z3, decls, tval2_port: str, gva_port: str) -> object:
    """只把不依赖 genTrapVA / fetchMalAddr 的条款放进待证公式。

    精确 tval（PC/PC+2/memVA/inst）已在 spec_tval() 里按类写好，
    但不进 prove：RTL 用 fetchMalAddr 覆盖任意异常的 xtval，再用
    genTrapVA 改 fetch VA。两边都不抄进规格，也不钉输入再报绿。
    IGPF 的 tval2 同样会被 fetchMalTval 盖掉，不比。
    HWE 的 GVA 条文没点名，不把 RTL 当 mem 故障写成 GVA=1，也不在
    本轮 prove 里用 GVA=0 打红（未过五关，不混进交付）。
    """
    spec = tval_smt(z3, decls)
    interrupt = _d(decls, "in_causeNO_Interrupt")
    code = _d(decls, "in_causeNO_ExceptionCode")
    is_ecall = z3.And(z3.Not(interrupt), _code_in(z3, code, EX_ECALL))
    return z3.And(
        z3.Implies(spec["is_lsgpf"], decls[tval2_port] == spec["tval2"]),
        z3.Implies(z3.Not(spec["is_gpf"]), decls[tval2_port] == spec["tval2"]),
        z3.Implies(spec["is_gpf"], decls[gva_port] == z3.BoolVal(True)),
        z3.Implies(z3.Or(interrupt, is_ecall),
                   decls[gva_port] == z3.BoolVal(False)),
    )


def eq_prove_m_tval(circuit) -> object:
    return _tval2_gva_prove(
        circuit.z3, circuit.decls,
        "out_mtval2_bits_ALL", "out_mstatus_bits_GVA")


def eq_prove_hs_tval(circuit) -> object:
    return _tval2_gva_prove(
        circuit.z3, circuit.decls,
        "out_htval_bits_ALL", "out_hstatus_bits_GVA")


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


def explain_tval_model(model: Dict, _circuit=None) -> Dict[str, str]:
    interrupt = bool(_model_int(model, "in_causeNO_Interrupt"))
    code = _model_int(model, "in_causeNO_ExceptionCode")
    cls = tval_class(interrupt, code)
    tv = spec_tval(
        interrupt, code,
        _model_int(model, "in_trapPc"),
        bool(_model_int(model, "in_isCrossPageIPF")),
        _model_int(model, "in_memExceptionVAddr"),
        _model_int(model, "in_trapInst_bits"),
        bool(_model_int(model, "in_trapInst_valid")),
    )
    tv2 = spec_tval2(
        interrupt, code,
        _model_int(model, "in_trapPcGPA"),
        bool(_model_int(model, "in_isCrossPageIPF")),
        _model_int(model, "in_memExceptionGPAddr"),
    )
    gva = spec_gva(
        interrupt, code,
        bool(_model_int(model, "in_iMode_V")),
        bool(_model_int(model, "in_dMode_V")),
        bool(_model_int(model, "in_isHls")),
    )
    rtl_tv = model.get("out_mtval_bits_ALL", model.get("out_stval_bits_ALL"))
    rtl_tv2 = model.get("out_mtval2_bits_ALL", model.get("out_htval_bits_ALL"))
    rtl_gva = model.get("out_mstatus_bits_GVA", model.get("out_hstatus_bits_GVA"))
    return {
        "译.cause": f"{'int' if interrupt else 'ex'} {code} class={cls}",
        "译.cross": str(_model_int(model, "in_isCrossPageIPF")),
        "译.mal": str(_model_int(model, "in_isFetchMalAddr")),
        "译.spec": f"tval={tv} tval2={tv2} GVA={gva}",
        "译.rtl": f"tval={rtl_tv} tval2={rtl_tv2} GVA={rtl_gva}",
    }
