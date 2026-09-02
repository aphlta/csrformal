"""CSRPermit 的独立规格函数，禁止从 Chisel 比较器翻译。

permit(priv, addr[12], ren, wen, enables) → {II, VI, NONE}

权威只来自特权规范 / AIA 手册 / SpecRef。RTL 只用来对齐端口名和位宽。
本文件同时提供：
  * 可执行的 Python 决策函数（反例翻译、人工抽查）
  * 绑到同一套 Circuit.decls 上的 z3 公式（EQ 主定理）

覆盖范围（本轮）
--------------
1. PrivilegePermit：addr[9:8] × (PRVM, V) × debug CSR 0x7B*（∀ 12-bit 地址）
2. 只读 CSR 写：addr[11:10]=11 ∧ wen → II
3. Sstc：mcounteren.TM / menvcfg.STCE / hcounteren.TM / henvcfg.STCE
   × {stimecmp, vstimecmp} × 全部非 M 特权（含写路径）
4. counteren：cycle/time/instret/hpm × HS/HU/VS/VU，∀ 32 bit（addr[4:0]）
5. TVM / VTVM / hgatp
6. Smstateen（手册点名的 CSR，不是从 RTL 比较器抄地址）：
   * bit 63 / SE0：mstateen{i} 门控匹配的 hstateen{i}/sstateen{i}（非 M → II）；
     hstateen{i} 门控匹配的 sstateen{i}（V=1 → VI）
   * ENVCFG：henvcfg / senvcfg（RV32 的 henvcfgh 不写，本栈 RV64）
   * CONTEXT：scontext / hcontext
   * IMSIC：stopei / vstopei（h 侧原文是 stopei，really vstopei，即 0x15C）
   * CSRIND：siselect/sireg* / vsiselect/vsireg*（条款写入 permit；
     EQ 仍排除这段地址，因为 Smcdeleg 内容规则未建模）

Sstc 必须按恢复后的 norm:menvcfg_stce_op2 写：非 M 访问 stimecmp **或**
vstimecmp 且 menvcfg.STCE=0 → II。不要抄当前 RTL「STCE 只管 stimecmp」——
那是 b90dbba 上 EQ 应被打红的前提。

mstateen 作用于 M 以下全体，HS 同样会被挡住，所以不是 HS-qualified，
VS/VU 也走 II。hstateen 只挡 VS/VU，HS 不受影响，故 V=1 走 VI。
依据 norm:stateen_illegal_state_access + norm:hstateen_encoding，
不是从 PrivilegePermit 的 decoder 反推。

显式假设（本轮不做，必须关掉以免被无关条款打红；集合可满足）
----------------------------------------------------------
- XRet（mnret/mret/sret/dret；TSR/VTSR 随之失去入口）
- FS/VS off（fp / vec CSR）
- AIA 其余：hvictl.VTI 对 sip/sie、mvien.SEIE、vgein 越界；
  VS 写 stimecmp × hvictl.VTI 在 isa-manual 里没有独立锚点，不猜，关掉 VTI
- Smcdeleg 间接窗口（排除 sireg*/vsireg*/mireg* 地址段）
- scountinhibit / scountovf

TODO：未写进规格的 stateen，EQ 必须继续钉 1（不要用 RTL 行为填）
----------------------------------------------------------
- mstateen0.AIA / hstateen0.AIA：norm:mstateen0_aia_op 是内涵定义
  （「Ssaia 引入且不受 CSRIND/IMSIC 控制的全部状态」），smstateen
  没有闭合地址表。不猜测，位置 1。
- mstateen0.C / hstateen0.C / sstateen0.C：custom 地址，不把 RTL
  自定义译进规格。C=1。
- FCSR / JVT / CTR / P1P13 / SRMCFG：本轮不建模（精化顶层也没有
  对应的 permit 输入端口可放开）。
- RV32 高半 CSR（henvcfgh、hstateen*h）：本栈 RV64，不写。

debugMode：规范只说 0x7B0–0x7BF 仅 debug 可见，没说 debug 能绕过其余
特权检查。为避免把「debug 旁路」从 RTL 抄进来，假设
`¬debugMode ∨ addr[11:4]=0x7B`。

未覆盖条款不要用 RTL 行为填进 spec 来「凑绿」。
"""
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .props import SpecRef

# ---------------------------------------------------------------- 条款出处
# 错误的 id 比没有更糟：spec-drift 会去盯错段落。没有锚点就 SpecRef(None, note=)。

R = {
    "zicsr_acc":    SpecRef("norm:Zicsr_access", "priv/csrs.adoc"),
    "zicsr_higher": SpecRef("norm:Zicsr_higher_priv", "priv/csrs.adoc"),
    "zicsr_mode":   SpecRef("norm:Zicsr_illegal_mode", "priv/csrs.adoc"),
    "zicsr_rw":     SpecRef("norm:Zicsr_rw", "priv/csrs.adoc"),
    "zicsr_ro":     SpecRef("norm:Zicsr_illegal_acc", "priv/csrs.adoc"),
    "zicsr_dbg":    SpecRef("norm:Zicsr_debug_illegal", "priv/csrs.adoc"),
    "hs_qual":      SpecRef("norm:H_cause_virtual_instruction", "priv/hypervisor.adoc"),
    "vi_h_vs":      SpecRef("norm:H_virtinst_vu_vs_nonhigh_allowedhs_tvm0",
                            "priv/hypervisor.adoc"),
    "vi_s_vu":      SpecRef("norm:H_virtinst_vu_nonhigh_supervisor_allowedhs_tvm0",
                            "priv/hypervisor.adoc"),
    "mcnt_tm_clr":  SpecRef("norm:mcounteren_tm_clr", "priv/machine.adoc"),
    "mcnt_tm_set":  SpecRef("norm:mcounteren_tm_set", "priv/machine.adoc"),
    "stce2":        SpecRef("norm:menvcfg_stce_op2", "priv/machine.adoc"),
    "henv_stce":    SpecRef("norm:henvcfg_stce", "priv/hypervisor.adoc"),
    "hcnt_acc":     SpecRef("norm:hcounteren_acc", "priv/hypervisor.adoc"),
    "mcnt_clr":     SpecRef("norm:mcounteren_clr_ill_inst_exc", "priv/machine.adoc"),
    "scnt_op":      SpecRef("norm:scounteren_op", "priv/supervisor.adoc"),
    "hcnt_op":      SpecRef("norm:hcounteren_op", "priv/hypervisor.adoc"),
    "tvm":          SpecRef("norm:mstatus_tvm_warl_op", "priv/machine.adoc"),
    "hgatp_tvm":    SpecRef("norm:hgatp_tvm_illegal", "priv/hypervisor.adoc"),
    "vtvm":         SpecRef("norm:hstatus_vtvm_op", "priv/hypervisor.adoc"),
    # isa-manual 没有 hvictl.VTI × stimecmp 的独立锚点；AIA 6.3 现有 case
    # 只覆盖 sip/sie。本轮不把「VS 写 stimecmp ∧ VTI → VI」写进规格。
    "vti_stc":      SpecRef(None, "riscv-aia（无 isa-manual 锚点）",
                            "查过 isa-manual：没有 hvictl.VTI 门控 stimecmp 写路径"
                            "的独立 norm: 锚点。现有 AIA 6.3 引用只覆盖 sip/sie。"
                            "不猜测，本轮用假设关掉 VTI。"),
    # Smstateen。错误的 id 比没有更糟；AIA 位没有闭合地址表，不硬凑。
    "st_op":        SpecRef("norm:stateen_op", "priv/smstateen.adoc"),
    "st_ill":       SpecRef("norm:stateen_illegal_state_access", "priv/smstateen.adoc"),
    "h_enc":        SpecRef("norm:hstateen_encoding", "priv/smstateen.adoc"),
    "mst63":        SpecRef("norm:mstateen_bit_63_op", "priv/smstateen.adoc"),
    "hst63":        SpecRef("norm:hstateen_bit_63_op", "priv/smstateen.adoc"),
    "mse0":         SpecRef("norm:mstateen0_se0_op", "priv/smstateen.adoc"),
    "hse0":         SpecRef("norm:hstateen0_SE0_op", "priv/smstateen.adoc"),
    "m_env":        SpecRef("norm:mstateen0_envcfg_op", "priv/smstateen.adoc"),
    "h_env":        SpecRef("norm:hstateen0_envcfg_op", "priv/smstateen.adoc"),
    "m_ctx":        SpecRef("norm:mstateen0_context_op", "priv/smstateen.adoc"),
    "h_ctx":        SpecRef("norm:hstateen0_context_op", "priv/smstateen.adoc"),
    "m_imsic":      SpecRef("norm:mstateen0_imsic_op", "priv/smstateen.adoc"),
    "h_imsic":      SpecRef("norm:hstateen0_imsic_op", "priv/smstateen.adoc"),
    "m_csrind":     SpecRef("norm:mstateen0_csrind_op", "priv/smstateen.adoc"),
    "h_csrind":     SpecRef("norm:hstateen0_csrind_op", "priv/smstateen.adoc"),
    "aia_open":     SpecRef(None, "priv/smstateen.adoc（AIA 位无闭合 CSR 列表）",
                            "norm:mstateen0_aia_op / hstateen0_aia_op 写的是"
                            "「Ssaia 引入且不受 CSRIND/IMSIC 控制的全部状态」，"
                            "smstateen 没有给出闭合地址表。不猜测，本轮用假设把 AIA 位置 1。"),
}

# lint / spec-drift 收录这些条款。vti_stc / aia_open 无 rule_id，靠 note 过 lint。
CLAUSE_REFS: List[SpecRef] = [
    R["zicsr_acc"], R["zicsr_higher"], R["zicsr_mode"], R["zicsr_rw"],
    R["zicsr_ro"], R["zicsr_dbg"], R["hs_qual"], R["vi_h_vs"], R["vi_s_vu"],
    R["mcnt_tm_clr"], R["mcnt_tm_set"], R["stce2"], R["henv_stce"], R["hcnt_acc"],
    R["mcnt_clr"], R["scnt_op"], R["hcnt_op"], R["tvm"], R["hgatp_tvm"], R["vtvm"],
    R["vti_stc"],
    R["st_op"], R["st_ill"], R["h_enc"], R["mst63"], R["hst63"],
    R["mse0"], R["hse0"], R["m_env"], R["h_env"], R["m_ctx"], R["h_ctx"],
    R["m_imsic"], R["h_imsic"], R["m_csrind"], R["h_csrind"], R["aia_open"],
]

# 标准 CSR 地址（特权手册的编号，不是从 RTL 枚举抄的）
ADDR_STIMECMP = 0x14D
ADDR_VSTIMECMP = 0x24D
ADDR_SATP = 0x180
ADDR_HGATP = 0x680
ADDR_CYCLE = 0xC00
ADDR_HPM31 = 0xC1F
ADDR_SCOUNTINHIBIT = 0x120
ADDR_SCOUNTOVF = 0xDA0
# 以下编号来自 priv/csrs.adoc 的标准分配，不是从 RTL 枚举抄的。
ADDR_SENVCFG = 0x10A
ADDR_HENVCFG = 0x60A
ADDR_SCONTEXT = 0x5A8
ADDR_HCONTEXT = 0x6A8
ADDR_STOPEI = 0x15C
ADDR_VSTOPEI = 0x25C
# sstateen0..3 / hstateen0..3
ADDR_SSTATEEN = (0x10C, 0x10D, 0x10E, 0x10F)
ADDR_HSTATEEN = (0x60C, 0x60D, 0x60E, 0x60F)
# siselect + sireg*：手册表跳过 0x154（siph，RV32）。vs 侧同构。
ADDR_SIREG = (0x150, 0x151, 0x152, 0x153, 0x155, 0x156, 0x157)
ADDR_VSIREG = (0x250, 0x251, 0x252, 0x253, 0x255, 0x256, 0x257)

# Smcdeleg / Smcsrind 间接窗口：本轮不建模内容规则，假设里排除这些地址。
# 范围按手册分配（S/VS/M 间接 CSR 落在 0x15x / 0x25x / 0x35x）。
# CSRIND 门控条款已写入 permit，但这段地址仍排除，避免 Smcdeleg 把 EQ 打红。
IND_S = (0x150, 0x157)
IND_VS = (0x250, 0x257)
IND_M = (0x350, 0x357)

# 精化顶层把 stateen 拆成 1-bit Bool 端口（前缀 io_in_xstateen_）。
# 已建模的位在 EQ 里自由；未建模的必须钉 1，见文件头 TODO。
STATEEN_SE_M = ("mstateen0_SE0", "mstateen1_SE", "mstateen2_SE", "mstateen3_SE")
STATEEN_SE_H = ("hstateen0_SE0", "hstateen1_SE", "hstateen2_SE", "hstateen3_SE")
STATEEN_MODELED = STATEEN_SE_M + STATEEN_SE_H + (
    "mstateen0_ENVCFG", "hstateen0_ENVCFG",
    "mstateen0_CONTEXT", "hstateen0_CONTEXT",
    "mstateen0_IMSIC", "hstateen0_IMSIC",
    "mstateen0_CSRIND", "hstateen0_CSRIND",
)
STATEEN_UNMODELED = (
    "mstateen0_AIA", "hstateen0_AIA",
    "mstateen0_C", "hstateen0_C", "sstateen0_C",
)
# case 层 clean() 仍用完整端口表。
STATEEN_PORTS = list(STATEEN_MODELED) + list(STATEEN_UNMODELED)

CSR_NAMES = {
    ADDR_STIMECMP: "stimecmp",
    ADDR_VSTIMECMP: "vstimecmp",
    ADDR_SATP: "satp",
    ADDR_HGATP: "hgatp",
    ADDR_SENVCFG: "senvcfg",
    ADDR_HENVCFG: "henvcfg",
    ADDR_SCONTEXT: "scontext",
    ADDR_HCONTEXT: "hcontext",
    ADDR_STOPEI: "stopei",
    ADDR_VSTOPEI: "vstopei",
    0xC00: "cycle", 0xC01: "time", 0xC02: "instret",
}
CSR_NAMES.update({a: f"sstateen{i}" for i, a in enumerate(ADDR_SSTATEEN)})
CSR_NAMES.update({a: f"hstateen{i}" for i, a in enumerate(ADDR_HSTATEEN)})
CSR_NAMES.update({0x150: "siselect", 0x151: "sireg", 0x250: "vsiselect", 0x251: "vsireg"})


@dataclass(frozen=True)
class Stateen:
    """手册点名的 stateen 门。默认全开，与 case 层 clean() 一致。

    精化顶层把这些拆成 1-bit Bool 端口，不是 64 位整字。
    AIA / C 未建模，不放这里。
    """
    m_se: Tuple[bool, bool, bool, bool] = (True, True, True, True)
    h_se: Tuple[bool, bool, bool, bool] = (True, True, True, True)
    m_envcfg: bool = True
    h_envcfg: bool = True
    m_context: bool = True
    h_context: bool = True
    m_imsic: bool = True
    h_imsic: bool = True
    m_csrind: bool = True
    h_csrind: bool = True


@dataclass(frozen=True)
class Enables:
    mcounteren: int = 0xFFFFFFFF
    hcounteren: int = 0xFFFFFFFF
    scounteren: int = 0xFFFFFFFF
    menvcfg_stce: bool = True
    henvcfg_stce: bool = True
    tvm: bool = False
    vtvm: bool = False
    debug_mode: bool = False
    stateen: Stateen = Stateen()


# ---------------------------------------------------------------- 可执行决策


def _mode(prvm: int, v: bool):
    is_m = prvm == 3 and not v
    is_hs = prvm == 1 and not v
    is_hu = prvm == 0 and not v
    is_vs = prvm == 1 and v
    is_vu = prvm == 0 and v
    return is_m, is_hs, is_hu, is_vs, is_vu


def _priv_ok(prvm: int, v: bool, addr: int, debug_mode: bool) -> bool:
    """csr[9:8] 最低特权 × 当前 (PRVM, V)；0x7B* 仅 debug。

    真值表来自 Zicsr 地址约定，不是 PrivilegePermitModule 的 decoder。
    00=U 全体可访问；01=S 要 PRVM≥S（M/HS/VS）；10=HS 只要 M/HS；
    11=M 只要 M。更高特权可访问更低 CSR（norm:Zicsr_higher_priv）。
    """
    if ((addr >> 4) & 0xFF) == 0x7B:
        return bool(debug_mode)
    level = (addr >> 8) & 3
    is_m, is_hs, _is_hu, is_vs, _is_vu = _mode(prvm, v)
    if level == 0:
        return True
    if level == 1:
        return is_m or is_hs or is_vs
    if level == 2:
        return is_m or is_hs
    return is_m


def _hs_would_allow(addr: int, wen: bool) -> bool:
    """HS-qualified：同一访问在 HS、TVM=0 时是否合法。

    用来在 V=1 时决定 II 还是 VI（norm:H_cause_virtual_instruction）。
    写只读、访 M 级、访 debug-only，在 HS 都不合法，所以不是 HS-qualified，
    应抛 II 而不是 VI。这里不读 RTL 的 `csrIsM` 分支，只复述这条定义。
    """
    if ((addr >> 4) & 0xFF) == 0x7B:
        return False
    level = (addr >> 8) & 3
    if level == 3:
        return False
    if ((addr >> 10) & 3) == 3 and wen:
        return False
    return True


def permit(prvm: int, v: bool, addr: int, ren: bool, wen: bool,
           en: Enables) -> str:
    """返回 'II' / 'VI' / 'NONE'。无访问则 NONE。II 优先于 VI。"""
    access = bool(ren or wen)
    if not access:
        return "NONE"

    is_m, is_hs, is_hu, is_vs, is_vu = _mode(prvm, v)
    any_ii = False
    any_vi = False

    # --- Privilege（rule: zicsr_* + hs_qual / vi_h_vs / vi_s_vu）---
    if not _priv_ok(prvm, v, addr, en.debug_mode):
        if v and _hs_would_allow(addr, wen):
            any_vi = True
        else:
            any_ii = True

    # --- 只读写（rule: zicsr_rw / zicsr_ro）---
    # 写只读在 HS 也不合法，故即令 V=1 也是 II（已被 hs_would_allow 排除 VI）。
    if ((addr >> 10) & 3) == 3 and wen:
        any_ii = True

    # --- Sstc（rule: stce2 用恢复后的原文：stimecmp 或 vstimecmp）---
    is_stc = addr in (ADDR_STIMECMP, ADDR_VSTIMECMP)
    is_stimecmp = addr == ADDR_STIMECMP
    if is_stc and not is_m and not en.menvcfg_stce:
        any_ii = True
    # mcounteren.TM=0：非 M 访 stimecmp 或 vstimecmp → II
    if is_stc and not is_m and not ((en.mcounteren >> 1) & 1):
        any_ii = True
    # henvcfg.STCE=0：V=1 访 stimecmp（其实是 vstimecmp）→ VI
    # 原文写的是 V=1，不是「仅 VS」。VU 会被特权先打成 II/VI，合取后 II 优先。
    if is_stimecmp and v and not en.henvcfg_stce:
        any_vi = True
    # hcounteren.TM=0：VS 访 stimecmp（其实 vstimecmp），且 mcounteren.TM=1 → VI
    if is_stimecmp and is_vs and not ((en.hcounteren >> 1) & 1) and ((en.mcounteren >> 1) & 1):
        any_vi = True

    # --- counteren，∀ bit（rule: mcnt_clr / scnt_op / hcnt_op）---
    # 手册写的是「读」cycle/time/instret/hpm。写走只读条款。
    # 地址 0xC00–0xC1F 的低 5 位就是 CY/TM/IR/HPMn 的位号，这是手册编码，
    # 不是从 RTL 的 `counterAddr = addr(4,0)` 反推。
    if ADDR_CYCLE <= addr <= ADDR_HPM31 and ren:
        bit = addr & 0x1F
        mbit = bool((en.mcounteren >> bit) & 1)
        hbit = bool((en.hcounteren >> bit) & 1)
        sbit = bool((en.scounteren >> bit) & 1)
        if not is_m and not mbit:
            any_ii = True
        if is_hu and not sbit:
            any_ii = True
        if v and mbit and not hbit:
            any_vi = True
        if is_vu and mbit and hbit and not sbit:
            any_vi = True

    # --- TVM / VTVM / hgatp ---
    if is_hs and en.tvm and addr in (ADDR_SATP, ADDR_HGATP):
        any_ii = True
    if is_vs and en.vtvm and addr == ADDR_SATP:
        any_vi = True

    # --- Smstateen（rule: st_ill + 各 bit 的 *_op；II/VI 分界见文件头）---
    st = en.stateen
    for i in range(4):
        if addr in (ADDR_SSTATEEN[i], ADDR_HSTATEEN[i]) and not is_m and not st.m_se[i]:
            any_ii = True
        if addr == ADDR_SSTATEEN[i] and v and not st.h_se[i]:
            any_vi = True
    if addr in (ADDR_SENVCFG, ADDR_HENVCFG) and not is_m and not st.m_envcfg:
        any_ii = True
    if addr == ADDR_SENVCFG and v and not st.h_envcfg:
        any_vi = True
    if addr in (ADDR_SCONTEXT, ADDR_HCONTEXT) and not is_m and not st.m_context:
        any_ii = True
    if addr == ADDR_SCONTEXT and v and not st.h_context:
        any_vi = True
    if addr in (ADDR_STOPEI, ADDR_VSTOPEI) and not is_m and not st.m_imsic:
        any_ii = True
    if addr == ADDR_STOPEI and v and not st.h_imsic:
        any_vi = True
    if addr in ADDR_SIREG + ADDR_VSIREG and not is_m and not st.m_csrind:
        any_ii = True
    if addr in ADDR_SIREG and v and not st.h_csrind:
        any_vi = True

    if any_ii:
        return "II"
    if any_vi:
        return "VI"
    return "NONE"


# ---------------------------------------------------------------- SMT 公式（与 permit() 同一套条款）


def _bv_bit(z3, reg, idx: int):
    return z3.Extract(idx, idx, reg) == 1


def _bv_dyn_bit(z3, reg, idx5):
    """reg[idx5]，idx5 是 5 位自由量。∀ hpm 位必须走这条，不能只抽 5 个常数。"""
    return z3.Extract(0, 0, z3.LShR(reg, z3.ZeroExt(27, idx5))) == 1


def permit_smt(z3, decls: Dict) -> Tuple[object, object]:
    """返回 (spec_ii, spec_vi)，已绑到 Circuit 端口常量上。"""
    def d(name: str):
        if name not in decls:
            raise KeyError(f"规格公式找不到端口 {name}；先核对精化顶层的端口名")
        return decls[name]

    addr = d("io_in_csrAccess_addr")
    prvm = d("io_in_privState_PRVM")
    v = d("io_in_privState_V")
    ren = d("io_in_csrAccess_ren")
    wen = d("io_in_csrAccess_wen")
    debug = d("io_in_debugMode")
    mcnt = d("io_in_xcounteren_mcounteren")
    hcnt = d("io_in_xcounteren_hcounteren")
    scnt = d("io_in_xcounteren_scounteren")
    menv = d("io_in_xenvcfg_menvcfg")
    henv = d("io_in_xenvcfg_henvcfg")
    tvm = d("io_in_status_tvm")
    vtvm = d("io_in_status_vtvm")

    access = z3.Or(ren, wen)
    is_m = z3.And(prvm == 3, z3.Not(v))
    is_hs = z3.And(prvm == 1, z3.Not(v))
    is_hu = z3.And(prvm == 0, z3.Not(v))
    is_vs = z3.And(prvm == 1, v)
    is_vu = z3.And(prvm == 0, v)

    level = z3.Extract(9, 8, addr)
    is_dbg_csr = z3.Extract(11, 4, addr) == 0x7B
    ro = z3.Extract(11, 10, addr) == 3

    # Privilege：与 _priv_ok 同一张表
    priv_ok = z3.If(
        is_dbg_csr, debug,
        z3.If(level == 0, True,
              z3.If(level == 1, z3.Or(is_m, is_hs, is_vs),
                    z3.If(level == 2, z3.Or(is_m, is_hs), is_m))))
    hs_would = z3.And(z3.Not(is_dbg_csr), level != 3, z3.Not(z3.And(ro, wen)))
    priv_ii = z3.And(access, z3.Not(priv_ok), z3.Or(z3.Not(v), z3.Not(hs_would)))
    priv_vi = z3.And(access, z3.Not(priv_ok), v, hs_would)

    ro_ii = z3.And(access, ro, wen)

    is_stimecmp = addr == ADDR_STIMECMP
    is_vstimecmp = addr == ADDR_VSTIMECMP
    is_stc = z3.Or(is_stimecmp, is_vstimecmp)
    menv_stce = _bv_bit(z3, menv, 63)
    henv_stce = _bv_bit(z3, henv, 63)
    mcnt_tm = _bv_bit(z3, mcnt, 1)
    hcnt_tm = _bv_bit(z3, hcnt, 1)

    # 恢复后的 stce_op2：stimecmp **或** vstimecmp。抄「只管 stimecmp」会让 EQ 假绿。
    stce_m_ii = z3.And(access, is_stc, z3.Not(is_m), z3.Not(menv_stce))
    tm_m_ii = z3.And(access, is_stc, z3.Not(is_m), z3.Not(mcnt_tm))
    stce_h_vi = z3.And(access, is_stimecmp, v, z3.Not(henv_stce))
    tm_h_vi = z3.And(access, is_stimecmp, is_vs, z3.Not(hcnt_tm), mcnt_tm)

    is_hpm = z3.And(z3.UGE(addr, ADDR_CYCLE), z3.ULE(addr, ADDR_HPM31))
    bit = z3.Extract(4, 0, addr)
    mbit = _bv_dyn_bit(z3, mcnt, bit)
    hbit = _bv_dyn_bit(z3, hcnt, bit)
    sbit = _bv_dyn_bit(z3, scnt, bit)
    mcnt_ii = z3.And(is_hpm, ren, z3.Not(is_m), z3.Not(mbit))
    scnt_ii = z3.And(is_hpm, ren, is_hu, z3.Not(sbit))
    hcnt_vi = z3.And(is_hpm, ren, v, mbit, z3.Not(hbit))
    scnt_vi = z3.And(is_hpm, ren, is_vu, mbit, hbit, z3.Not(sbit))

    tvm_ii = z3.And(access, is_hs, tvm, z3.Or(addr == ADDR_SATP, addr == ADDR_HGATP))
    vtvm_vi = z3.And(access, is_vs, vtvm, addr == ADDR_SATP)

    # Smstateen：与 permit() 同一套地址 / II-VI 分界。端口是 1-bit Bool。
    def _addr_in(addrs):
        return z3.Or(*[addr == a for a in addrs])

    se_m_ii, se_h_vi = [], []
    for i, (mp, hp) in enumerate(zip(STATEEN_SE_M, STATEEN_SE_H)):
        m_se = d(f"io_in_xstateen_{mp}")
        h_se = d(f"io_in_xstateen_{hp}")
        se_m_ii.append(z3.And(access, _addr_in((ADDR_SSTATEEN[i], ADDR_HSTATEEN[i])),
                              z3.Not(is_m), z3.Not(m_se)))
        se_h_vi.append(z3.And(access, addr == ADDR_SSTATEEN[i], v, z3.Not(h_se)))

    m_env = d("io_in_xstateen_mstateen0_ENVCFG")
    h_env = d("io_in_xstateen_hstateen0_ENVCFG")
    env_m_ii = z3.And(access, _addr_in((ADDR_SENVCFG, ADDR_HENVCFG)),
                      z3.Not(is_m), z3.Not(m_env))
    env_h_vi = z3.And(access, addr == ADDR_SENVCFG, v, z3.Not(h_env))

    m_ctx = d("io_in_xstateen_mstateen0_CONTEXT")
    h_ctx = d("io_in_xstateen_hstateen0_CONTEXT")
    ctx_m_ii = z3.And(access, _addr_in((ADDR_SCONTEXT, ADDR_HCONTEXT)),
                      z3.Not(is_m), z3.Not(m_ctx))
    ctx_h_vi = z3.And(access, addr == ADDR_SCONTEXT, v, z3.Not(h_ctx))

    m_im = d("io_in_xstateen_mstateen0_IMSIC")
    h_im = d("io_in_xstateen_hstateen0_IMSIC")
    imsic_m_ii = z3.And(access, _addr_in((ADDR_STOPEI, ADDR_VSTOPEI)),
                        z3.Not(is_m), z3.Not(m_im))
    imsic_h_vi = z3.And(access, addr == ADDR_STOPEI, v, z3.Not(h_im))

    m_ind = d("io_in_xstateen_mstateen0_CSRIND")
    h_ind = d("io_in_xstateen_hstateen0_CSRIND")
    csrind_m_ii = z3.And(access, _addr_in(ADDR_SIREG + ADDR_VSIREG),
                         z3.Not(is_m), z3.Not(m_ind))
    csrind_h_vi = z3.And(access, _addr_in(ADDR_SIREG), v, z3.Not(h_ind))

    any_ii = z3.Or(priv_ii, ro_ii, stce_m_ii, tm_m_ii, mcnt_ii, scnt_ii, tvm_ii,
                   *se_m_ii, env_m_ii, ctx_m_ii, imsic_m_ii, csrind_m_ii)
    any_vi = z3.Or(priv_vi, stce_h_vi, tm_h_vi, hcnt_vi, scnt_vi, vtvm_vi,
                   *se_h_vi, env_h_vi, ctx_h_vi, imsic_h_vi, csrind_h_vi)
    spec_ii = any_ii
    spec_vi = z3.And(any_vi, z3.Not(any_ii))
    return spec_ii, spec_vi


def eq_assumes() -> List[str]:
    """关掉未覆盖路径。集合必须可满足，真空门禁会查。"""
    a = [
        # 合法特权态：PRVM∈{U,S,M} 且 M 不能带 V=1。PRVM=2 是编码空洞。
        "(or (= io_in_privState_PRVM (_ bv0 2))"
        " (= io_in_privState_PRVM (_ bv1 2))"
        " (= io_in_privState_PRVM (_ bv3 2)))",
        "(=> (= io_in_privState_PRVM (_ bv3 2)) (not io_in_privState_V))",
        # debug 旁路未写入规格，只保留 0x7B* 这条有锚点的路径。
        "(or (not io_in_debugMode)"
        " (= ((_ extract 11 4) io_in_csrAccess_addr) #x7b))",
        "(and (not io_in_xRet_mnret) (not io_in_xRet_mret)"
        " (not io_in_xRet_sret) (not io_in_xRet_dret))",
        "(and (not io_in_status_mstatusFSOff) (not io_in_status_vsstatusFSOff)"
        " (not io_in_status_mstatusVSOff) (not io_in_status_vsstatusVSOff))",
        "(not io_in_aia_hvictlVTI)",
        "(not io_in_aia_mvienSEIE)",
        # geilen=7（MinimalConfig）。合法 vgein 关掉 vstopei 越界条款。
        "(and (bvuge io_in_status_vgein (_ bv1 6))"
        " (bvule io_in_status_vgein (_ bv7 6)))",
        "(= io_in_aia_miselect (_ bv112 64))",
        "(= io_in_aia_siselect (_ bv112 64))",
        "(= io_in_aia_vsiselect (_ bv112 64))",
        # 间接窗口 + scountinhibit/scountovf：地址排除，使能位仍可自由。
        "(and (not (and (bvuge io_in_csrAccess_addr "
        f"#x{IND_S[0]:03x}) (bvule io_in_csrAccess_addr #x{IND_S[1]:03x})))"
        " (not (and (bvuge io_in_csrAccess_addr "
        f"#x{IND_VS[0]:03x}) (bvule io_in_csrAccess_addr #x{IND_VS[1]:03x})))"
        " (not (and (bvuge io_in_csrAccess_addr "
        f"#x{IND_M[0]:03x}) (bvule io_in_csrAccess_addr #x{IND_M[1]:03x})))"
        f" (distinct io_in_csrAccess_addr #x{ADDR_SCOUNTINHIBIT:03x})"
        f" (distinct io_in_csrAccess_addr #x{ADDR_SCOUNTOVF:03x}))",
    ]
    # 已建模的 stateen 位自由；未建模的必须钉 1，见文件头 TODO。
    a += [f"(= io_in_xstateen_{s} true)" for s in STATEEN_UNMODELED]
    return a


def eq_prove(circuit) -> object:
    spec_ii, spec_vi = permit_smt(circuit.z3, circuit.decls)
    rtl_ii = circuit.decls["io_out_EX_II"]
    rtl_vi = circuit.decls["io_out_EX_VI"]
    return circuit.z3.And(rtl_ii == spec_ii, rtl_vi == spec_vi)


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


def csr_name(addr: int) -> str:
    if addr in CSR_NAMES:
        return CSR_NAMES[addr]
    if ADDR_CYCLE <= addr <= ADDR_HPM31:
        return f"hpmcounter{addr - ADDR_CYCLE}"
    return "—"


def explain_eq_model(model: Dict, _circuit=None) -> Dict[str, str]:
    """把反例译成 0x24d / HS / STCE=0 这种字段。STCE=0 是默认值，不能靠滤 0。"""
    addr = _model_int(model, "io_in_csrAccess_addr")
    prvm = _model_int(model, "io_in_privState_PRVM")
    v = bool(_model_int(model, "io_in_privState_V"))
    ren = bool(_model_int(model, "io_in_csrAccess_ren"))
    wen = bool(_model_int(model, "io_in_csrAccess_wen"))
    menv = _model_int(model, "io_in_xenvcfg_menvcfg")
    henv = _model_int(model, "io_in_xenvcfg_henvcfg")
    mcnt = _model_int(model, "io_in_xcounteren_mcounteren")
    hcnt = _model_int(model, "io_in_xcounteren_hcounteren")
    scnt = _model_int(model, "io_in_xcounteren_scounteren")
    def _st_bit(name: str, default: int = 1) -> int:
        # stateen 端口默认 True；反例里 0 才是相关位，不能靠滤默认值。
        return _model_int(model, f"io_in_xstateen_{name}", default)

    st = Stateen(
        m_se=tuple(bool(_st_bit(p)) for p in STATEEN_SE_M),
        h_se=tuple(bool(_st_bit(p)) for p in STATEEN_SE_H),
        m_envcfg=bool(_st_bit("mstateen0_ENVCFG")),
        h_envcfg=bool(_st_bit("hstateen0_ENVCFG")),
        m_context=bool(_st_bit("mstateen0_CONTEXT")),
        h_context=bool(_st_bit("hstateen0_CONTEXT")),
        m_imsic=bool(_st_bit("mstateen0_IMSIC")),
        h_imsic=bool(_st_bit("hstateen0_IMSIC")),
        m_csrind=bool(_st_bit("mstateen0_CSRIND")),
        h_csrind=bool(_st_bit("hstateen0_CSRIND")),
    )
    en = Enables(
        mcounteren=mcnt, hcounteren=hcnt, scounteren=scnt,
        menvcfg_stce=bool((menv >> 63) & 1),
        henvcfg_stce=bool((henv >> 63) & 1),
        tvm=bool(_model_int(model, "io_in_status_tvm")),
        vtvm=bool(_model_int(model, "io_in_status_vtvm")),
        debug_mode=bool(_model_int(model, "io_in_debugMode")),
        stateen=st,
    )
    spec = permit(prvm, v, addr, ren, wen, en)
    rtl_ii = bool(_model_int(model, "io_out_EX_II"))
    rtl_vi = bool(_model_int(model, "io_out_EX_VI"))
    rtl = "II" if rtl_ii else ("VI" if rtl_vi else "NONE")
    acc = "w" if wen and not ren else ("rw" if wen and ren else ("r" if ren else "—"))
    # 只列出关掉的门，避免反例被「全 1」淹没。
    off = []
    for i, on in enumerate(st.m_se):
        if not on:
            off.append(f"mstateen{i}.SE=0")
    for i, on in enumerate(st.h_se):
        if not on:
            off.append(f"hstateen{i}.SE=0")
    for lab, on in (
        ("m.ENVCFG", st.m_envcfg), ("h.ENVCFG", st.h_envcfg),
        ("m.CONTEXT", st.m_context), ("h.CONTEXT", st.h_context),
        ("m.IMSIC", st.m_imsic), ("h.IMSIC", st.h_imsic),
        ("m.CSRIND", st.m_csrind), ("h.CSRIND", st.h_csrind),
    ):
        if not on:
            off.append(f"{lab}=0")
    return {
        "译.addr": f"0x{addr:03x} ({csr_name(addr)})",
        "译.priv": mode_name(prvm, v),
        "译.acc": acc,
        "译.STCE": f"menvcfg.STCE={int(en.menvcfg_stce)} henvcfg.STCE={int(en.henvcfg_stce)}",
        "译.TM": f"mcounteren.TM={int(bool((mcnt >> 1) & 1))} hcounteren.TM={int(bool((hcnt >> 1) & 1))}",
        "译.stateen": ",".join(off) if off else "（已建模位全开）",
        "译.spec": spec,
        "译.rtl": rtl,
    }
