"""TrapHandleModule 的规范符合性性质集。

被测模块：`XiangShan/src/main/scala/xiangshan/backend/fu/NewCSR/TrapHandleModule.scala`
关注输出：`entryPrivState`（陷入到哪个特权态）、`causeNO`、`pcFromXtvec`、
`hasDTExcp` / `dbltrpToMN`（Sm/Ssdbltrp 双重陷入）。

覆盖：medeleg/hedeleg 异常委托链、irToHS/irToVS 中断委托、cause 编码、
xtvec 选择与 Direct/Vectored 入口 PC、双重陷入。
"""
from ..props import Property, SpecRef

MODULE = "TrapHandleModule"

R = {
    "medeleg":  SpecRef("norm:medeleg_mideleg_op2", "priv/machine.adoc"),
    "hedeleg":  SpecRef("norm:hedeleg_op", "priv/hypervisor.adoc"),
    "hideleg":  SpecRef("norm:hideleg_op", "priv/hypervisor.adoc"),
    "hid_tr":   SpecRef("norm:hideleg_trans", "priv/hypervisor.adoc"),
    "mtvec_v":  SpecRef("norm:mtvec_mode_vectored_op", "priv/machine.adoc"),
    # supervisor.adoc 只说 stvec「formatted analogously to mtvec」，
    # Vectored 的取址语义没有自己的 norm: 锚点，不硬凑一个。
    "stvec_v":  SpecRef(None, "priv/supervisor.adoc（stvec 类比 mtvec）",
                        "stvec 的 Vectored 取址语义在 supervisor.adoc 中以 “formatted "
                        "analogously to mtvec” 转述，没有独立 norm: 锚点；"
                        "实际约束文本见 norm:mtvec_mode_vectored_op。"),
    "sdt_trap": SpecRef("norm:sstatus_sdt_trap", "priv/supervisor.adoc"),
    "vs_sdt":   SpecRef("norm:vsstatus_sdt_op", "priv/hypervisor.adoc"),
    "rnmi_y":   SpecRef("norm:trap_unexp_hndl_rnmi", "priv/machine.adoc"),
    "rnmi_n":   SpecRef("norm:trap_unexp_hndl_no_rnmi", "priv/machine.adoc"),
    "self":     SpecRef(None, "自洽性检查（非规范条文）",
                        "无陷入时不应产生双重陷入信号。这是实现自洽性，不对应规范条文，"
                        "但能抓住把 valid 漏掉的逻辑错误。"),
}

# 异常号 → medeleg/hedeleg 端口后缀
EXC = {
    0: "EX_IAM", 1: "EX_IAF", 2: "EX_II", 3: "EX_BP", 4: "EX_LAM", 5: "EX_LAF",
    6: "EX_SAM", 7: "EX_SAF", 8: "EX_UCALL", 9: "EX_HSCALL", 10: "EX_VSCALL",
    11: "EX_MCALL", 12: "EX_IPF", 13: "EX_LPF", 15: "EX_SPF", 16: "EX_DBLTRP",
    18: "EX_SWC", 19: "EX_HWE", 20: "EX_IGPF", 21: "EX_LGPF", 22: "EX_VI",
    23: "EX_SGPF",
}

MODE = {
    "M":  ['(= io_in_privState_PRVM (_ bv3 2))', '(= io_in_privState_V false)'],
    "HS": ['(= io_in_privState_PRVM (_ bv1 2))', '(= io_in_privState_V false)'],
    "HU": ['(= io_in_privState_PRVM (_ bv0 2))', '(= io_in_privState_V false)'],
    "VS": ['(= io_in_privState_PRVM (_ bv1 2))', '(= io_in_privState_V true)'],
    "VU": ['(= io_in_privState_PRVM (_ bv0 2))', '(= io_in_privState_V true)'],
}
PS = {
    "M":  '(and (= io_out_entryPrivState_PRVM (_ bv3 2)) (not io_out_entryPrivState_V))',
    "HS": '(and (= io_out_entryPrivState_PRVM (_ bv1 2)) (not io_out_entryPrivState_V))',
    "VS": '(and (= io_out_entryPrivState_PRVM (_ bv1 2)) io_out_entryPrivState_V)',
}

# 双重陷入相关位默认清零，避免与被测条款纠缠（DT* 用例自己覆盖）
DT_CLEAN = ['(= io_in_mstatus_MDT false)', '(= io_in_mstatus_SDT false)',
            '(= io_in_vsstatus_SDT false)', 'io_in_mnstatus_NMIE']


def deleg(reg, on):
    return [f'(= io_in_{reg}_{nm} {"true" if n in on else "false"})'
            for n, nm in EXC.items()]


def exc(e):
    return ['io_in_trapInfo_valid', '(= io_in_trapInfo_bits_isInterrupt false)',
            f'(= io_in_trapInfo_bits_trapVec (_ bv{1 << e} 64))',
            '(= io_in_trapInfo_bits_singleStep false)',
            '(= io_in_trapInfo_bits_irToHS false)',
            '(= io_in_trapInfo_bits_irToVS false)']


def intr(n, to_hs, to_vs):
    return ['io_in_trapInfo_valid', 'io_in_trapInfo_bits_isInterrupt',
            f'(= io_in_trapInfo_bits_intrVec (_ bv{n} 8))',
            '(= io_in_trapInfo_bits_singleStep false)',
            f'(= io_in_trapInfo_bits_irToHS {"true" if to_hs else "false"})',
            f'(= io_in_trapInfo_bits_irToVS {"true" if to_vs else "false"})']


def tvec(mode_m=0, mode_s=0, mode_vs=0):
    return [f'(= io_in_mtvec_mode (_ bv{mode_m} 2))',
            f'(= io_in_stvec_mode (_ bv{mode_s} 2))',
            f'(= io_in_vstvec_mode (_ bv{mode_vs} 2))']


def pc(reg, off=0):
    return (f'(= io_out_pcFromXtvec (concat (bvadd io_in_{reg}_addr'
            f' (_ bv{off} 62)) (_ bv0 2)))')


def cause(n, is_int):
    return (f'(and (= io_out_causeNO_ExceptionCode (_ bv{n} 63))'
            f' (= io_out_causeNO_Interrupt {"true" if is_int else "false"}))')


PROPS = []


def case(pid, title, ref, asm, prove):
    PROPS.append(Property(pid=f"TrapHandle/{pid}", title=title, module=MODULE,
                          assumes=asm, prove=prove, ref=ref,
                          tags=[pid.split("[")[0]]))


# ---------------------------------------------------- 异常委托链
for e in [2, 3, 5, 8, 12, 13, 15, 18, 19]:
    for m in ["HS", "HU"]:
        case(f"D1[e={e},{m}]", f"medeleg[{e}]=1 → 陷入 HS，cause={e}，pc=stvec", R["medeleg"],
             MODE[m] + exc(e) + deleg("medeleg", {e}) + deleg("hedeleg", set())
             + DT_CLEAN + tvec(),
             f'(and {PS["HS"]} {cause(e, False)} {pc("stvec")})')
        case(f"D2[e={e},{m}]", f"medeleg[{e}]=0 → 陷入 M，pc=mtvec", R["medeleg"],
             MODE[m] + exc(e) + deleg("medeleg", set()) + deleg("hedeleg", {e})
             + DT_CLEAN + tvec(),
             f'(and {PS["M"]} {cause(e, False)} {pc("mtvec")})')
    for m in ["VS", "VU"]:
        case(f"D3[e={e},{m}]", f"medeleg&hedeleg 都置位 → 陷入 VS，pc=vstvec", R["hedeleg"],
             MODE[m] + exc(e) + deleg("medeleg", {e}) + deleg("hedeleg", {e})
             + DT_CLEAN + tvec(),
             f'(and {PS["VS"]} {cause(e, False)} {pc("vstvec")})')
        case(f"D4[e={e},{m}]", f"medeleg=1,hedeleg=0 → 陷入 HS，pc=stvec", R["hedeleg"],
             MODE[m] + exc(e) + deleg("medeleg", {e}) + deleg("hedeleg", set())
             + DT_CLEAN + tvec(),
             f'(and {PS["HS"]} {cause(e, False)} {pc("stvec")})')
        case(f"D5[e={e},{m}]", f"medeleg=0 → 陷入 M（hedeleg 无关）", R["hedeleg"],
             MODE[m] + exc(e) + deleg("medeleg", set()) + deleg("hedeleg", {e})
             + DT_CLEAN + tvec(),
             f'(and {PS["M"]} {pc("mtvec")})')
    case(f"D6[e={e}]", "M 态发生异常 → 恒陷入 M（medeleg 只对低于 M 的态生效）", R["medeleg"],
         MODE["M"] + exc(e) + deleg("medeleg", {e}) + deleg("hedeleg", {e})
         + DT_CLEAN + tvec(),
         f'(and {PS["M"]} {pc("mtvec")})')

# ---------------------------------------------------- 中断委托
for n in [1, 5, 9, 13]:          # SSI/STI/SEI/LCOFI
    case(f"I1[n={n}]", "irToHS 且非 M 态 → 陷入 HS", R["medeleg"],
         MODE["HS"] + intr(n, True, False) + deleg("medeleg", set())
         + deleg("hedeleg", set()) + DT_CLEAN + tvec(),
         f'(and {PS["HS"]} {cause(n, True)} {pc("stvec")})')
    case(f"I2[n={n}]", "未委托 → 陷入 M", R["medeleg"],
         MODE["HS"] + intr(n, False, False) + deleg("medeleg", set())
         + deleg("hedeleg", set()) + DT_CLEAN + tvec(),
         f'(and {PS["M"]} {cause(n, True)} {pc("mtvec")})')
    case(f"I3[n={n}]", "M 态且 irToHS → 仍陷入 M", R["medeleg"],
         MODE["M"] + intr(n, True, True) + deleg("medeleg", set())
         + deleg("hedeleg", set()) + DT_CLEAN + tvec(),
         f'(and {PS["M"]} {pc("mtvec")})')
for n in [2, 6, 10]:             # VSSI/VSTI/VSEI
    case(f"I4[n={n}]", "irToVS 且 V=1 → 陷入 VS", R["hideleg"],
         MODE["VS"] + intr(n, True, True) + deleg("medeleg", set())
         + deleg("hedeleg", set()) + DT_CLEAN + tvec(),
         f'(and {PS["VS"]} {cause(n, True)} {pc("vstvec")})')
    case(f"I5[n={n}]", "irToVS 但 V=0 → 不进 VS", R["hideleg"],
         MODE["HS"] + intr(n, True, True) + deleg("medeleg", set())
         + deleg("hedeleg", set()) + DT_CLEAN + tvec(),
         '(not io_out_entryPrivState_V)')

# ---------------------------------------------------- 向量化入口 PC
for n in [1, 5, 9, 13, 63]:
    case(f"V1[n={n}]", "mtvec=Vectored + 中断到 M → pc=BASE+4*cause", R["mtvec_v"],
         MODE["HS"] + intr(n, False, False) + deleg("medeleg", set())
         + deleg("hedeleg", set()) + DT_CLEAN + tvec(mode_m=1),
         pc("mtvec", n))
    case(f"V2[n={n}]", "stvec=Vectored + 中断到 HS → pc=BASE+4*cause", R["stvec_v"],
         MODE["HS"] + intr(n, True, False) + deleg("medeleg", set())
         + deleg("hedeleg", set()) + DT_CLEAN + tvec(mode_s=1),
         pc("stvec", n))
for n, off in [(2, 1), (6, 5), (10, 9)]:
    case(f"V3[n={n}]", "vstvec=Vectored + VS 级中断 → pc=BASE+4*(cause-1)", R["hid_tr"],
         MODE["VS"] + intr(n, True, True) + deleg("medeleg", set())
         + deleg("hedeleg", set()) + DT_CLEAN + tvec(mode_vs=1),
         pc("vstvec", off))
for e in [2, 12, 13]:
    case(f"V4[e={e}]", "Vectored 下同步异常 → pc=BASE（无偏移）", R["mtvec_v"],
         MODE["HS"] + exc(e) + deleg("medeleg", set()) + deleg("hedeleg", set())
         + DT_CLEAN + tvec(mode_m=1, mode_s=1, mode_vs=1),
         pc("mtvec"))

# ---------------------------------------------------- 双重陷入 Sm/Ssdbltrp
case("DT1", "委托到 HS 且 mstatus.SDT=1 → 转为 M 态双重陷入", R["sdt_trap"],
     MODE["HS"] + exc(2) + deleg("medeleg", {2}) + deleg("hedeleg", set())
     + ['(= io_in_mstatus_MDT false)', 'io_in_mstatus_SDT',
        '(= io_in_vsstatus_SDT false)', 'io_in_mnstatus_NMIE'] + tvec(),
     f'(and {PS["M"]} io_out_hasDTExcp {pc("mtvec")})')
case("DT2", "委托到 VS 且 vsstatus.SDT=1 → 转为 M 态双重陷入", R["vs_sdt"],
     MODE["VS"] + exc(2) + deleg("medeleg", {2}) + deleg("hedeleg", {2})
     + ['(= io_in_mstatus_MDT false)', '(= io_in_mstatus_SDT false)',
        'io_in_vsstatus_SDT', 'io_in_mnstatus_NMIE'] + tvec(),
     f'(and {PS["M"]} io_out_hasDTExcp {pc("mtvec")})')
case("DT3", "M 态陷入且 mstatus.MDT=1、NMIE=1 → dbltrpToMN", R["rnmi_y"],
     MODE["M"] + exc(2) + deleg("medeleg", set()) + deleg("hedeleg", set())
     + ['io_in_mstatus_MDT', '(= io_in_mstatus_SDT false)',
        '(= io_in_vsstatus_SDT false)', 'io_in_mnstatus_NMIE'] + tvec(),
     '(and io_out_hasDTExcp io_out_dbltrpToMN)')
case("DT4", "M 态陷入且 MDT=1、NMIE=0 → 不再进 RNMI", R["rnmi_n"],
     MODE["M"] + exc(2) + deleg("medeleg", set()) + deleg("hedeleg", set())
     + ['io_in_mstatus_MDT', '(= io_in_mstatus_SDT false)',
        '(= io_in_vsstatus_SDT false)', '(= io_in_mnstatus_NMIE false)'] + tvec(),
     '(and io_out_hasDTExcp (not io_out_dbltrpToMN))')
case("DT5", "SDT=1 但陷入本就进 M（medeleg=0）→ 不算双重陷入", R["sdt_trap"],
     MODE["HS"] + exc(2) + deleg("medeleg", set()) + deleg("hedeleg", set())
     + ['(= io_in_mstatus_MDT false)', 'io_in_mstatus_SDT',
        '(= io_in_vsstatus_SDT false)', 'io_in_mnstatus_NMIE'] + tvec(),
     f'(and {PS["M"]} (not io_out_hasDTExcp))')
case("DT6", "vsstatus.SDT=1 但陷入只到 HS（hedeleg=0）→ 不算双重陷入", R["vs_sdt"],
     MODE["VS"] + exc(2) + deleg("medeleg", {2}) + deleg("hedeleg", set())
     + ['(= io_in_mstatus_MDT false)', '(= io_in_mstatus_SDT false)',
        'io_in_vsstatus_SDT', 'io_in_mnstatus_NMIE'] + tvec(),
     f'(and {PS["HS"]} (not io_out_hasDTExcp) {pc("stvec")})')

# ---------------------------------------------------- 无陷入
case("N1", "trapInfo.valid=0 → 不产生双重陷入信号", R["self"],
     MODE["HS"] + ['(= io_in_trapInfo_valid false)'] + deleg("medeleg", set())
     + deleg("hedeleg", set())
     + ['io_in_mstatus_MDT', 'io_in_mstatus_SDT', 'io_in_vsstatus_SDT',
        'io_in_mnstatus_NMIE'] + tvec(),
     '(and (not io_out_hasDTExcp) (not io_out_dbltrpToMN))')
