"""TrapEntry*Event 的规范符合性性质集。

被测模块：`XiangShan/.../NewCSR/CSREvents/TrapEntry{M,HS}Event.scala`
接口是「陷入后各 CSR 的次态」。EQ 对照独立规格 `spec_trap_entry.py`，
禁止把本文件或 Chisel 条件翻译进规格。

本轮只注册 registers=0 的模块。TrapEntryDEvent 精化后有寄存器，
跳过，不假装时序完整。TrapEntryVS / MN 的 EQ 还没写。

别名表在 `spec_trap_entry.alias_assumes`：sstatus 是 mstatus 视图。
漏一条就会被假反例淹没（普查 HS2）。
"""
from .. import spec_trap_entry
from ..props import Property, SpecRef

PROPS_M = [
    Property(
        pid="TrapEntryM/EQ-next",
        title="陷入 M 后 RTL 次态字段 ≡ spec（MIE/MPIE/MPP/MPV/特权/mcause）",
        module="TrapEntryMEventModule",
        assumes=spec_trap_entry.eq_assumes_m(),
        prove="(and (= out.mstatus.MIE spec.MIE) (= out.mstatus.MPIE spec.MPIE) "
              "(= out.mstatus.MPP spec.MPP) (= out.mstatus.MPV spec.MPV) "
              "(= out.privState spec.ModeM) (= out.mcause spec.cause))",
        prove_fn=spec_trap_entry.eq_prove_m,
        explain_fn=spec_trap_entry.explain_eq_model_m,
        extra_refs=spec_trap_entry.CLAUSE_REFS_M,
        ref=SpecRef(None, "TrapEntryM 等价性主定理（多条款合取）",
                    "主定理是陷入 M 时 xPIE←xIE、xIE←0、xPP←y、MPV←V、"
                    "新特权=M、mcause←cause 的合取，不是单条 norm: 条文。"
                    "各条款 rule_id 见 extra_refs。tval/mepc/NMI/debug/DT/MDT "
                    "未进规格，见 spec_trap_entry 文件头。不要给合取硬凑一个 id。"),
        tags=["EQ"]),
]

PROPS_HS = [
    Property(
        pid="TrapEntryHS/EQ-next",
        title="陷入 HS 后 RTL 次态字段 ≡ spec（SIE/SPIE/SPP/SPV/SPVP/特权/scause）",
        module="TrapEntryHSEventModule",
        assumes=spec_trap_entry.eq_assumes_hs(),
        prove="(and (= out.mstatus.SIE spec.SIE) (= out.mstatus.SPIE spec.SPIE) "
              "(= out.mstatus.SPP spec.SPP) (= out.hstatus.SPV spec.SPV) "
              "(= out.privState spec.ModeHS) (= out.scause spec.cause))",
        prove_fn=spec_trap_entry.eq_prove_hs,
        explain_fn=spec_trap_entry.explain_eq_model_hs,
        extra_refs=spec_trap_entry.CLAUSE_REFS_HS,
        ref=SpecRef(None, "TrapEntryHS 等价性主定理（多条款合取）",
                    "主定理是陷入 HS 时 xPIE←xIE、xIE←0、SPP/SPV/SPVP、"
                    "新特权=HS、scause←cause 的合取。SPIE 规格读 mstatus.SIE，"
                    "靠别名假设与 RTL 的 sstatus.SIE 对齐。tval/sepc/GVA/SDT "
                    "未进规格。不要给合取硬凑一个 id。"),
        tags=["EQ"]),
]
