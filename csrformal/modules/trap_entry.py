"""TrapEntry*Event 的规范符合性性质集。

被测模块：`XiangShan/.../NewCSR/CSREvents/TrapEntry{M,HS}Event.scala`
接口是「陷入后各 CSR 的次态」。EQ 对照独立规格 `spec_trap_entry.py`，
禁止把本文件或 Chisel 条件翻译进规格。

EQ-next、EQ-tval（tval2/GVA）、EQ-tval-data（精确 xtval）分开：
tval 不和 epc 绑成一条合取。epc / VS / MN / D 本轮不做。

别名表在 `spec_trap_entry.alias_assumes`：sstatus 是 mstatus 视图。
"""
from .. import spec_trap_entry
from ..props import Property, SpecRef

PROPS_M = [
    Property(
        pid="TrapEntryM/EQ-next",
        title="陷入 M 后 RTL ≡ spec（MIE/MPIE/MPP/MPV/特权/mcause）",
        module="TrapEntryMEventModule",
        assumes=spec_trap_entry.eq_assumes_m(),
        prove="(and (= out.mstatus.MIE spec.MIE) (= out.mstatus.MPIE spec.MPIE) "
              "(= out.mstatus.MPP spec.MPP) (= out.mstatus.MPV spec.MPV) "
              "(= out.privState spec.ModeM) (= out.mcause spec.cause))",
        prove_fn=spec_trap_entry.eq_prove_m,
        explain_fn=spec_trap_entry.explain_eq_model_m,
        extra_refs=spec_trap_entry.CLAUSE_REFS_M,
        ref=SpecRef(None, "TrapEntryM 等价性主定理（SIE 族合取）",
                    "主定理是陷入 M 时 xPIE←xIE、xIE←0、xPP←y、MPV←V、"
                    "新特权=M、mcause←cause 的合取。tval/epc 不在这条里。"
                    "不要给合取硬凑一个 id。"),
        tags=["EQ"]),
    Property(
        pid="TrapEntryM/EQ-tval",
        title="陷入 M 后 tval2/GVA ≡ 异常类（LS-GPF=GPA>>2，非 GPF=0，GPF 的 GVA=1）",
        module="TrapEntryMEventModule",
        assumes=spec_trap_entry.eq_assumes_m(),
        prove="(and (=> spec.lsgpf (= out.mtval2 spec.memGPA>>2)) "
              "(=> (not spec.gpf) (= out.mtval2 0)) "
              "(=> spec.gpf out.mstatus.GVA) "
              "(=> spec.int_or_ecall (not out.mstatus.GVA)))",
        prove_fn=spec_trap_entry.eq_prove_m_tval,
        explain_fn=spec_trap_entry.explain_tval_model,
        extra_refs=spec_trap_entry.CLAUSE_REFS_TVAL_M,
        ref=SpecRef(None, "TrapEntryM tval2/GVA 异常类合取",
                    "本条只比 tval2 与 GVA。精确 xtval 在 EQ-tval-data，"
                    "不和本条绑合取。BP/HWE 排除。不要硬凑 id。"),
        tags=["EQ"]),
    Property(
        pid="TrapEntryM/EQ-tval-data",
        title="陷入 M 后 mtval ≡ 异常类（mem=memVA，inst=指令位，zero=0）",
        module="TrapEntryMEventModule",
        assumes=spec_trap_entry.eq_assumes_m(),
        prove="(and (=> spec.mem (= out.mtval spec.memVA)) "
              "(=> spec.inst (= out.mtval spec.inst_or_0)) "
              "(=> spec.zero (= out.mtval 0)))",
        prove_fn=spec_trap_entry.eq_prove_m_tval_data,
        explain_fn=spec_trap_entry.explain_tval_model,
        extra_refs=spec_trap_entry.CLAUSE_REFS_TVAL_DATA_M,
        ref=SpecRef(None, "TrapEntryM 精确 xtval 异常类合取",
                    "mem/inst/zero 按手册取值。fetch 的 PC/PC+2 不进 prove"
                    "（genTrapVA WARL）。不钉 isFetchMalAddr / isCrossPageIPF。"
                    "BP/SWC/HWE 排除。不要硬凑 id。"),
        tags=["EQ"]),
]

PROPS_HS = [
    Property(
        pid="TrapEntryHS/EQ-next",
        title="陷入 HS 后 RTL ≡ spec（SIE/SPIE/SPP/SPV/SPVP/特权/scause）",
        module="TrapEntryHSEventModule",
        assumes=spec_trap_entry.eq_assumes_hs(),
        prove="(and (= out.mstatus.SIE spec.SIE) (= out.mstatus.SPIE spec.SPIE) "
              "(= out.mstatus.SPP spec.SPP) (= out.hstatus.SPV spec.SPV) "
              "(= out.privState spec.ModeHS) (= out.scause spec.cause))",
        prove_fn=spec_trap_entry.eq_prove_hs,
        explain_fn=spec_trap_entry.explain_eq_model_hs,
        extra_refs=spec_trap_entry.CLAUSE_REFS_HS,
        ref=SpecRef(None, "TrapEntryHS 等价性主定理（SIE 族合取）",
                    "主定理是陷入 HS 时 xPIE←xIE、xIE←0、SPP/SPV/SPVP、"
                    "新特权=HS、scause←cause。SPIE 读 mstatus.SIE，"
                    "靠别名与 RTL 的 sstatus.SIE 对齐。tval/epc 不在这条里。"),
        tags=["EQ"]),
    Property(
        pid="TrapEntryHS/EQ-tval",
        title="陷入 HS 后 htval/GVA ≡ 异常类（LS-GPF=GPA>>2，非 GPF=0，GPF 的 GVA=1）",
        module="TrapEntryHSEventModule",
        assumes=spec_trap_entry.eq_assumes_hs(),
        prove="(and (=> spec.lsgpf (= out.htval spec.memGPA>>2)) "
              "(=> (not spec.gpf) (= out.htval 0)) "
              "(=> spec.gpf out.hstatus.GVA) "
              "(=> spec.int_or_ecall (not out.hstatus.GVA)))",
        prove_fn=spec_trap_entry.eq_prove_hs_tval,
        explain_fn=spec_trap_entry.explain_tval_model,
        extra_refs=spec_trap_entry.CLAUSE_REFS_TVAL_HS,
        ref=SpecRef(None, "TrapEntryHS tval2/GVA 异常类合取",
                    "与 TrapEntryM/EQ-tval 同一套 tval2/GVA 条款，端口换成 "
                    "htval/hstatus.GVA。精确 stval 在 EQ-tval-data。"),
        tags=["EQ"]),
    Property(
        pid="TrapEntryHS/EQ-tval-data",
        title="陷入 HS 后 stval ≡ 异常类（mem=memVA，inst=指令位，zero=0）",
        module="TrapEntryHSEventModule",
        assumes=spec_trap_entry.eq_assumes_hs(),
        prove="(and (=> spec.mem (= out.stval spec.memVA)) "
              "(=> spec.inst (= out.stval spec.inst_or_0)) "
              "(=> spec.zero (= out.stval 0)))",
        prove_fn=spec_trap_entry.eq_prove_hs_tval_data,
        explain_fn=spec_trap_entry.explain_tval_model,
        extra_refs=spec_trap_entry.CLAUSE_REFS_TVAL_DATA_HS,
        ref=SpecRef(None, "TrapEntryHS 精确 xtval 异常类合取",
                    "与 TrapEntryM/EQ-tval-data 同一套 mem/inst/zero 条款，"
                    "端口换成 stval。fetch 不进 prove。不抄 genTrapVA，不钉 mal/cross。"),
        tags=["EQ"]),
]
