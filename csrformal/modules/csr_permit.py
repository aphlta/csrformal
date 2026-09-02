"""CSRPermitModule 的规范符合性性质集。

被测模块：`XiangShan/src/main/scala/xiangshan/backend/fu/NewCSR/CSRPermitModule.scala`
输出：`io.out.EX_II`（illegal instruction）/ `io.out.EX_VI`（virtual instruction）。

写法约定
--------
每条性质用 `CLEAN`（见 `clean()`）把**所有其它陷入源**关掉，只翻转被测的那一位。
这样一来「抛了 II」就只可能来自被测条款，而不是别的条款顺带抛的。

⚠️ CLEAN 的整字默认值必须是「除被测位外全 1」，不能写死 0xffffffff：
被测条款往往要求某位为 0，写死全 1 会让假设集自相矛盾，性质变成真空成立。
这正是上一轮 30+ 条假通过的根因，所以 `clean()` 接受掩码参数，
并由 runner 的真空性门禁兜底。
"""
from ..props import Property, SpecRef

MODULE = "CSRPermitModule"

ONES32 = 0xFFFFFFFF
ONES64 = 0xFFFFFFFFFFFFFFFF

# ---------------------------------------------------------------- 规范引用表
# 集中放在这里，方便 `csrformal rules` 一次性列出、也方便 spec-drift 汇总。
R = {
    "mcnt_tm_clr":  SpecRef("norm:mcounteren_tm_clr", "priv/machine.adoc"),
    "mcnt_tm_set":  SpecRef("norm:mcounteren_tm_set", "priv/machine.adoc"),
    "mcnt_clr":     SpecRef("norm:mcounteren_clr_ill_inst_exc", "priv/machine.adoc"),
    "mcnt_set":     SpecRef("norm:mcounteren_set_nxt_priv", "priv/machine.adoc"),
    "scnt_op":      SpecRef("norm:scounteren_op", "priv/supervisor.adoc"),
    "hcnt_op":      SpecRef("norm:hcounteren_op", "priv/hypervisor.adoc"),
    "hcnt_acc":     SpecRef("norm:hcounteren_acc", "priv/hypervisor.adoc"),
    "stce2":        SpecRef("norm:menvcfg_stce_op2", "priv/machine.adoc"),
    "henvcfg_stce": SpecRef("norm:henvcfg_stce", "priv/hypervisor.adoc"),
    "zicsr_acc":    SpecRef("norm:Zicsr_access", "priv/csrs.adoc"),
    "st_ill":       SpecRef("norm:stateen_illegal_state_access", "priv/smstateen.adoc"),
    "mst63":        SpecRef("norm:mstateen_bit_63_op", "priv/smstateen.adoc"),
    "hst63":        SpecRef("norm:hstateen_bit_63_op", "priv/smstateen.adoc"),
    "sst_vs_roz":   SpecRef("norm:sstateen_vsmode_access_roz", "priv/smstateen.adoc"),
    "tvm":          SpecRef("norm:mstatus_tvm_warl_op", "priv/machine.adoc"),
    "hgatp_tvm":    SpecRef("norm:hgatp_tvm_illegal", "priv/hypervisor.adoc"),
    "vtvm":         SpecRef("norm:hstatus_vtvm_op", "priv/hypervisor.adoc"),
    "vgein":        SpecRef("norm:hstatus_vgein_op", "priv/hypervisor.adoc"),
    # AIA 的 hvictl / mvien 语义在独立的 riscv-aia 文档里，isa-manual 没有
    # 对应的 norm: 锚点。如实标注为无规则 id，不硬凑。
    "aia_vti":      SpecRef(None, "riscv-aia 6.3 hvictl.VTI",
                            "AIA 规范是独立仓库 riscv/riscv-aia，未纳入 riscv-isa-manual 的 "
                            "norm: 锚点体系；本条依据 AIA 手册 6.3 节 hvictl.VTI，无法机械追溯。"),
    "aia_mvien":    SpecRef(None, "riscv-aia 5.3 mvien.SEIE",
                            "同上，AIA 独立文档 5.3 节 mvien.SEIE，无 norm: 锚点。"),
    # 关系型性质不对应任何单条规范文本，它是从「所有 CSR 访问限制都是特权越低
    # 限制越多」这一结构性事实推出的元性质。
    "mono":         SpecRef(None, "结构性元性质（特权单调性）",
                            "非规范单条条文；由 Zicsr addr[9:8] 编码 + counteren/stateen 逐级"
                            "收紧的整体结构推出。只在 V 相同的特权链上成立（跨 V 有 satp/vsatp "
                            "等 CSR 别名，见 REPORT.md 的 X1/X2）。"),
    "cde0":         SpecRef("norm:ssccfg_illegal_sireg_cde0", "priv/smcdeleg.adoc"),
    "cde_en":       SpecRef("norm:smcdeleg_cde_en", "priv/smcdeleg.adoc"),
    "not_deleg":    SpecRef("norm:ssccfg_illegal_sireg_not_delegated", "priv/smcdeleg.adoc"),
    "sireg36":      SpecRef("norm:ssccfg_illegal_sireg3_6", "priv/smcdeleg.adoc"),
    "sireg45":      SpecRef("norm:ssccfg_illegal_sireg4_5_xlen64", "priv/smcdeleg.adoc"),
    "vs_cond":      SpecRef("norm:ssccfg_hyp_vs_access_sireg_conditional", "priv/smcdeleg.adoc"),
    "ms_vsireg":    SpecRef("norm:ssccfg_hyp_m_s_vsireg_illegal", "priv/smcdeleg.adoc"),
    "mireg_rsv":    SpecRef(None, "priv/smcdeleg.adoc（0x40-0x5F 范围归属）",
                            "smcdeleg 只为 siselect/vsiselect 定义 0x40-0x5F；miselect 的该范围"
                            "未被任何 norm: 规则覆盖，属规范留白，本条按 “未定义即非法” 检查。"),
    "csrind_gate":  SpecRef("norm:mstateen0_csrind_op", "priv/smstateen.adoc"),
    "hcsrind_gate": SpecRef("norm:hstateen0_csrind_op", "priv/smstateen.adoc"),
}
MST_BIT = {b: SpecRef(f"norm:mstateen0_{b.lower()}_op", "priv/smstateen.adoc")
           for b in ("ENVCFG", "CONTEXT", "AIA", "IMSIC", "CSRIND")}
HST_BIT = {b: SpecRef(f"norm:hstateen0_{b.lower()}_op", "priv/smstateen.adoc")
           for b in ("ENVCFG", "CONTEXT", "AIA", "IMSIC", "CSRIND")}

# ---------------------------------------------------------------- 场景构造

STATEEN_PORTS = [
    'mstateen0_SE0', 'mstateen0_ENVCFG', 'mstateen0_CSRIND', 'mstateen0_AIA',
    'mstateen0_IMSIC', 'mstateen0_CONTEXT', 'mstateen0_C',
    'mstateen1_SE', 'mstateen2_SE', 'mstateen3_SE',
    'hstateen0_SE0', 'hstateen0_ENVCFG', 'hstateen0_CSRIND', 'hstateen0_AIA',
    'hstateen0_IMSIC', 'hstateen0_CONTEXT', 'hstateen0_C',
    'hstateen1_SE', 'hstateen2_SE', 'hstateen3_SE', 'sstateen0_C',
]


def clean(mcnt=ONES32, hcnt=ONES32, scnt=ONES32, menv=ONES64, henv=ONES64,
          st_off=(), tvm=False, vtvm=False, vgein=1, hvictl=False, mvien=False,
          iselect=0x70):
    """干净环境：除显式指定的位以外，所有陷入源都关掉。"""
    a = [
        '(= io_in_debugMode false)',
        '(and (= io_in_xRet_mnret false) (= io_in_xRet_mret false)'
        ' (= io_in_xRet_sret false) (= io_in_xRet_dret false))',
        f'(= io_in_xcounteren_mcounteren #x{mcnt:08x})',
        f'(= io_in_xcounteren_hcounteren #x{hcnt:08x})',
        f'(= io_in_xcounteren_scounteren #x{scnt:08x})',
        f'(= io_in_xenvcfg_menvcfg #x{menv:016x})',
        f'(= io_in_xenvcfg_henvcfg #x{henv:016x})',
        f'(= io_in_status_tvm {"true" if tvm else "false"})',
        f'(= io_in_status_vtvm {"true" if vtvm else "false"})',
        f'(= io_in_status_vgein (_ bv{vgein} 6))',
        f'(= io_in_aia_hvictlVTI {"true" if hvictl else "false"})',
        f'(= io_in_aia_mvienSEIE {"true" if mvien else "false"})',
        '(= io_in_status_mstatusFSOff false)', '(= io_in_status_vsstatusFSOff false)',
        '(= io_in_status_mstatusVSOff false)', '(= io_in_status_vsstatusVSOff false)',
        f'(= io_in_aia_miselect (_ bv{iselect} 64))',
        f'(= io_in_aia_siselect (_ bv{iselect} 64))',
        f'(= io_in_aia_vsiselect (_ bv{iselect} 64))',
    ]
    a += [f'(= io_in_xstateen_{s} {"false" if s in st_off else "true"})'
          for s in STATEEN_PORTS]
    return a


MODE = {
    "M":  ['(= io_in_privState_PRVM (_ bv3 2))', '(= io_in_privState_V false)'],
    "HS": ['(= io_in_privState_PRVM (_ bv1 2))', '(= io_in_privState_V false)'],
    "HU": ['(= io_in_privState_PRVM (_ bv0 2))', '(= io_in_privState_V false)'],
    "VS": ['(= io_in_privState_PRVM (_ bv1 2))', '(= io_in_privState_V true)'],
    "VU": ['(= io_in_privState_PRVM (_ bv0 2))', '(= io_in_privState_V true)'],
}
RD = ['io_in_csrAccess_ren', '(= io_in_csrAccess_wen false)']
WR = ['io_in_csrAccess_wen', '(= io_in_csrAccess_ren false)']

II = 'io_out_EX_II'
VI = '(and io_out_EX_VI (not io_out_EX_II))'
TRAP = '(or io_out_EX_II io_out_EX_VI)'
NONE = '(and (not io_out_EX_II) (not io_out_EX_VI))'

PROPS = []


def case(pid, title, ref, mode, acc, addr, prove, **kw):
    PROPS.append(Property(
        pid=f"CSRPermit/{pid}", title=title, module=MODULE,
        assumes=MODE[mode] + acc + [f'(= io_in_csrAccess_addr (_ bv{addr} 12))'] + clean(**kw),
        prove=prove, ref=ref, tags=[pid.split("[")[0].rstrip("0123456789abcus")]))


def clr(v, i):
    return v & ~(1 << i)


# ---------------------------------------------------- Sstc / 计时器
case("S1a", "mcounteren.TM=0 → HS 访问 stimecmp 抛 II", R["mcnt_tm_clr"],
     "HS", RD, 0x14D, II, mcnt=clr(ONES32, 1))
case("S1b", "mcounteren.TM=0 → HS 访问 vstimecmp 抛 II", R["mcnt_tm_clr"],
     "HS", RD, 0x24D, II, mcnt=clr(ONES32, 1))
case("S1c", "mcounteren.TM=0 → VS 访问 stimecmp 抛 II", R["mcnt_tm_clr"],
     "VS", RD, 0x14D, II, mcnt=clr(ONES32, 1))
case("S2", "menvcfg.STCE=0 → HS 访问 stimecmp 抛 II", R["stce2"],
     "HS", RD, 0x14D, II, menv=clr(ONES64, 63), henv=clr(ONES64, 63))
case("S3", "menvcfg.STCE=0 → HS 访问 vstimecmp 抛 II", R["stce2"],
     "HS", RD, 0x24D, II, menv=clr(ONES64, 63), henv=clr(ONES64, 63))
case("S3b", "menvcfg.STCE=0 → VS 访问 stimecmp 抛 II", R["stce2"],
     "VS", RD, 0x14D, II, menv=clr(ONES64, 63), henv=clr(ONES64, 63))
case("S4", "hcounteren.TM=0（mcnt.TM=1）→ VS 访问 stimecmp 抛 VI", R["hcnt_acc"],
     "VS", RD, 0x14D, VI, hcnt=clr(ONES32, 1))
case("S5", "henvcfg.STCE=0（menvcfg.STCE=1）→ VS 访问 stimecmp 抛 VI",
     R["henvcfg_stce"], "VS", RD, 0x14D, VI, henv=clr(ONES64, 63))
case("S6", "全开 → HS 访问 stimecmp 不抛", R["mcnt_tm_set"], "HS", RD, 0x14D, NONE)
case("S7", "全开 → HS 访问 vstimecmp 不抛", R["mcnt_tm_set"], "HS", RD, 0x24D, NONE)
case("S8", "全开 → VS 访问 stimecmp 不抛", R["hcnt_acc"], "VS", RD, 0x14D, NONE)

# ---------------------------------------------------- counteren
for i, addr, nm in [(0, 0xC00, "cycle"), (1, 0xC01, "time"), (2, 0xC02, "instret"),
                    (5, 0xC05, "hpm5"), (31, 0xC1F, "hpm31")]:
    case(f"C1[{nm}]", f"mcounteren[{i}]=0 → HS 读 {nm} 抛 II", R["mcnt_clr"],
         "HS", RD, addr, II, mcnt=clr(ONES32, i))
    case(f"C1u[{nm}]", f"mcounteren[{i}]=0 → HU 读 {nm} 抛 II", R["mcnt_clr"],
         "HU", RD, addr, II, mcnt=clr(ONES32, i))
    case(f"C2[{nm}]", f"scounteren[{i}]=0 → HU 读 {nm} 抛 II", R["scnt_op"],
         "HU", RD, addr, II, scnt=clr(ONES32, i))
    case(f"C3[{nm}]", f"hcounteren[{i}]=0 → VS 读 {nm} 抛 VI", R["hcnt_op"],
         "VS", RD, addr, VI, hcnt=clr(ONES32, i))
    case(f"C4[{nm}]", f"hcounteren[{i}]=0 → VU 读 {nm} 抛 VI", R["hcnt_op"],
         "VU", RD, addr, VI, hcnt=clr(ONES32, i))
    case(f"C4s[{nm}]", f"scounteren[{i}]=0（m,h=1）→ VU 读 {nm} 抛异常", R["hcnt_op"],
         "VU", RD, addr, TRAP, scnt=clr(ONES32, i))
    case(f"C5[{nm}]", f"全开 → HS 读 {nm} 不抛", R["mcnt_set"], "HS", RD, addr, NONE)
    case(f"C6[{nm}]", f"全开 → VU 读 {nm} 不抛", R["hcnt_op"], "VU", RD, addr, NONE)
    case(f"C7[{nm}]", f"全开 → HU 读 {nm} 不抛", R["scnt_op"], "HU", RD, addr, NONE)

# ---------------------------------------------------- 只读 CSR 写
for addr, nm in [(0xC00, "cycle"), (0xF11, "mvendorid"), (0xC80, "cycleh"),
                 (0xDB0, "stopi")]:
    case(f"R1[{nm}]", f"addr[11:10]=11（只读）且 wen → 写 {nm} 抛 II", R["zicsr_acc"],
         "M", WR, addr, II)

# ---------------------------------------------------- Smstateen
for i in range(4):
    sfx = "SE0" if i == 0 else "SE"
    case(f"E1[{i}]", f"mstateen{i}.{sfx}=0 → HS 访问 hstateen{i} 抛 II", R["mst63"],
         "HS", RD, 0x60C + i, II, st_off=(f'mstateen{i}_{sfx}',))
    case(f"E2[{i}]", f"mstateen{i}.{sfx}=0 → HS 访问 sstateen{i} 抛 II", R["mst63"],
         "HS", RD, 0x10C + i, II, st_off=(f'mstateen{i}_{sfx}',))
    case(f"E3[{i}]", f"hstateen{i}.{sfx}=0 → VS 访问 sstateen{i} 抛 VI", R["hst63"],
         "VS", RD, 0x10C + i, VI, st_off=(f'hstateen{i}_{sfx}',))
    case(f"E3u[{i}]", f"hstateen{i}.{sfx}=0 → VU 访问 sstateen{i} 抛异常",
         R["sst_vs_roz"], "VU", RD, 0x10C + i, TRAP, st_off=(f'hstateen{i}_{sfx}',))

for bit, addrs in [
    ("ENVCFG", [("senvcfg", 0x10A), ("henvcfg", 0x60A)]),
    ("CONTEXT", [("scontext", 0x5A8), ("hcontext", 0x6A8)]),
    ("AIA", [("stopi", 0xDB0), ("hvictl", 0x609), ("hviprio1", 0x646),
             ("hviprio2", 0x647), ("hvien", 0x608), ("vstopi", 0xEB0)]),
    ("IMSIC", [("stopei", 0x15C), ("vstopei", 0x25C)]),
    ("CSRIND", [("siselect", 0x150), ("sireg", 0x151),
                ("vsiselect", 0x250), ("vsireg", 0x251)]),
]:
    for nm, addr in addrs:
        case(f"EM.{bit}[{nm}]", f"mstateen0.{bit}=0 → HS 访问 {nm} 抛 II",
             MST_BIT[bit], "HS", RD, addr, II, st_off=(f'mstateen0_{bit}',))

for bit, addrs in [("ENVCFG", [("senvcfg", 0x10A)]), ("CONTEXT", [("scontext", 0x5A8)]),
                   ("AIA", [("stopi", 0xDB0)]), ("IMSIC", [("stopei", 0x15C)]),
                   ("CSRIND", [("siselect", 0x150), ("sireg", 0x151)])]:
    for nm, addr in addrs:
        case(f"EH.{bit}[{nm}]", f"hstateen0.{bit}=0 → VS 访问 {nm} 抛 VI",
             HST_BIT[bit], "VS", RD, addr, VI, st_off=(f'hstateen0_{bit}',))

# ---------------------------------------------------- TVM / VTVM
case("T1", "mstatus.TVM=1 → HS 访问 satp 抛 II", R["tvm"], "HS", RD, 0x180, II, tvm=True)
case("T2", "mstatus.TVM=1 → HS 访问 hgatp 抛 II", R["hgatp_tvm"], "HS", RD, 0x680, II, tvm=True)
case("T3", "hstatus.VTVM=1 → VS 访问 satp 抛 VI", R["vtvm"], "VS", RD, 0x180, VI, vtvm=True)
case("T4", "mstatus.TVM=1 时 M 态访问 satp 不抛", R["tvm"], "M", RD, 0x180, NONE, tvm=True)
case("T5", "TVM=0 → HS 访问 satp 不抛", R["tvm"], "HS", RD, 0x180, NONE)
case("T6", "VTVM=0 → VS 访问 satp 不抛", R["vtvm"], "VS", RD, 0x180, NONE)

# ---------------------------------------------------- AIA
case("A1", "vgein=0 → M 访问 vstopei 抛 II", R["vgein"], "M", RD, 0x25C, II, vgein=0)
case("A2", "vgein=0 → HS 访问 vstopei 抛 II", R["vgein"], "HS", RD, 0x25C, II, vgein=0)
case("A3", "vgein>geilen(=7) → HS 访问 vstopei 抛 II", R["vgein"], "HS", RD, 0x25C, II, vgein=8)
case("A4", "vgein=0 → VS 访问 stopei 抛 VI", R["vgein"], "VS", RD, 0x15C, VI, vgein=0)
case("A5", "vgein 合法 → HS 访问 vstopei 不抛", R["vgein"], "HS", RD, 0x25C, NONE, vgein=7)
case("A6", "hvictl.VTI=1 → VS 访问 sip 抛 VI", R["aia_vti"], "VS", RD, 0x144, VI, hvictl=True)
case("A7", "hvictl.VTI=1 → VS 访问 sie 抛 VI", R["aia_vti"], "VS", RD, 0x104, VI, hvictl=True)
case("A8", "mvien.SEIE=1 → HS 访问 stopei 抛 II", R["aia_mvien"], "HS", RD, 0x15C, II, mvien=True)

# ---------------------------------------------------- Smcsrind/Smcdeleg 间接窗口
SIREG = {1: 0x151, 2: 0x152, 3: 0x153, 4: 0x155, 5: 0x156, 6: 0x157}
VSIREG = {1: 0x251, 2: 0x252, 3: 0x253, 4: 0x255, 6: 0x257}
MIREG = {1: 0x351, 2: 0x352, 4: 0x355, 6: 0x357}
MENV_CDE0 = ONES64 & ~(1 << 60)

for k in (1, 2):
    case(f"ID-A1[sireg{k}]", f"menvcfg.CDE=0 → HS 访问 sireg{k} 抛 II", R["cde0"],
         "HS", RD, SIREG[k], II, iselect=0x43, menv=MENV_CDE0)
    case(f"ID-A2[sireg{k}]", f"CDE=1 且计数器已委托 → HS 访问 sireg{k} 不抛", R["cde_en"],
         "HS", RD, SIREG[k], NONE, iselect=0x43)
    case(f"ID-A4a[sireg{k}]", f"siselect=0x41(time) → HS 访问 sireg{k} 抛 II",
         R["not_deleg"], "HS", RD, SIREG[k], II, iselect=0x41)
    case(f"ID-A4b[sireg{k}]", f"mcounteren[3]=0（未委托）→ HS 访问 sireg{k} 抛 II",
         R["not_deleg"], "HS", RD, SIREG[k], II, iselect=0x43, mcnt=clr(ONES32, 3))
for k in (3, 4, 5, 6):
    case(f"ID-A2b[sireg{k}]", f"XLEN=64 → HS 访问 sireg{k} 恒抛 II",
         R["sireg36"] if k in (3, 6) else R["sireg45"],
         "HS", RD, SIREG[k], II, iselect=0x43)
    case(f"ID-A2c[sireg{k}]", f"menvcfg.CDE=0 → HS 访问 sireg{k} 抛 II", R["cde0"],
         "HS", RD, SIREG[k], II, iselect=0x43, menv=MENV_CDE0)
for k in (1, 2, 3, 6):
    case(f"ID-B2a[sireg{k}]", f"VS + CDE=0 → 访问 sireg{k} 抛 II（不是 VI）", R["vs_cond"],
         "VS", RD, SIREG[k], II, iselect=0x43, menv=MENV_CDE0)
    case(f"ID-B2b[sireg{k}]", f"VS + CDE=1 → 访问 sireg{k} 抛 VI（不是 II）", R["vs_cond"],
         "VS", RD, SIREG[k], VI, iselect=0x43)
for k, addr in VSIREG.items():
    case(f"ID-B1[vsireg{k}]", f"M 态访问 vsireg{k} 抛 II", R["ms_vsireg"],
         "M", RD, addr, II, iselect=0x43)
    case(f"ID-B1s[vsireg{k}]", f"HS 态访问 vsireg{k} 抛 II", R["ms_vsireg"],
         "HS", RD, addr, II, iselect=0x43)
for k, addr in MIREG.items():
    case(f"ID-C[mireg{k}]", f"miselect∈0x40-0x5F 保留 → M 访问 mireg{k} 抛 II",
         R["mireg_rsv"], "M", RD, addr, II, iselect=0x43)
case("ID-D1", "mstateen0.CSRIND=0 → HS 访问 sireg 抛 II（先于 Smcdeleg 规则）",
     R["csrind_gate"], "HS", RD, 0x151, II, iselect=0x43, st_off=('mstateen0_CSRIND',))
case("ID-D2", "hstateen0.CSRIND=0 → VS 访问 sireg 抛 VI", R["hcsrind_gate"],
     "VS", RD, 0x151, VI, iselect=0x43, st_off=('hstateen0_CSRIND',))

# ---------------------------------------------------- 关系型：特权单调性
# 同一 CSR 状态、同一次访问，高特权态若陷入则低特权态必然也陷入。
# 只在 V 相同的链上成立：跨 V 边界有 satp/vsatp、sireg/vsireg 等 CSR 别名，
# 「同一地址」在两边根本不是同一个寄存器（见 REPORT.md X1/X2）。
_MONO_COMMON = [
    '(= A_io_in_debugMode false)',
    '(or A_io_in_csrAccess_ren A_io_in_csrAccess_wen)',
    '(and (= A_io_in_xRet_mnret false) (= A_io_in_xRet_mret false)'
    ' (= A_io_in_xRet_sret false) (= A_io_in_xRet_dret false))',
]
for pid, (ap, av), (bp, bv), desc in [
    ("MONO-M2HS", (3, "false"), (1, "false"), "M→HS"),
    ("MONO-HS2HU", (1, "false"), (0, "false"), "HS→HU"),
    ("MONO-VS2VU", (1, "true"), (0, "true"), "VS→VU"),
]:
    PROPS.append(Property(
        pid=f"CSRPermit/{pid}",
        title=f"特权单调性 {desc}：高特权陷入 ⇒ 低特权也陷入（全 12bit 地址 × 全 CSR 状态）",
        module=MODULE, kind="relational",
        free=['io_in_privState_PRVM', 'io_in_privState_V'],
        assumes=_MONO_COMMON + [
            f'(= A_io_in_privState_PRVM (_ bv{ap} 2))', f'(= A_io_in_privState_V {av})',
            f'(= B_io_in_privState_PRVM (_ bv{bp} 2))', f'(= B_io_in_privState_V {bv})',
        ],
        prove='(=> (or A_io_out_EX_II A_io_out_EX_VI) (or B_io_out_EX_II B_io_out_EX_VI))',
        ref=R["mono"], tags=["MONO"]))
