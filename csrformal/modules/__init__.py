"""模块注册表：把「一个可被检查的 RTL 模块」需要的一切集中登记。

加一个新模块只要做三件事（README 有完整步骤）：
  1. 确认 `src/eqcheck/Elab2.scala` 的 `build()` 里能构造它；
  2. 新建 `csrformal/modules/<name>.py`，导出 `MODULE` 和 `PROPS`；
  3. 在下面的 `MODULES` 里登记一行。

`sources` 指向 XiangShan 工作树里该模块的 .scala，只在变异测试时用到
（覆盖编译需要知道改哪个文件）。
"""
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, List

from .. import config
from ..props import Property

NEWCSR = os.path.join(config.XS_TREE,
                      "src/main/scala/xiangshan/backend/fu/NewCSR")


@dataclass
class Mutant:
    """一个被替换进 RTL 的源码变体，用来做对照实验。

    两种用法：

    * `kind="defect"`（阳性对照）—— 注入一个已知缺陷，要求 `expect_kill`
      里列出的性质**报出反例**。不仅要求「有性质挂了」，还要求挂的是
      **意图对应的那一条**：否则可能是别的性质因无关原因误报，对照就失效了。

    * `kind="fix"`（修复对照）—— 打入一个候选修复，要求 `expect_fix`
      里列出的、当前在报反例的性质**转为通过**。这一类的价值是把
      「我建议的改法确实能修好这个 bug」也变成可自动回归的断言，
      而不是停留在报告里的一句话。
    """
    mid: str
    module: str
    desc: str
    patch: str                       # 替换用的 .scala 绝对路径
    expect_kill: List[str] = field(default_factory=list)   # pid 后缀精确匹配；族用 key[
    kind: str = "defect"
    expect_fix: List[str] = field(default_factory=list)


@dataclass
class ModuleSpec:
    name: str
    props: List[Property]
    sources: Dict[str, str] = field(default_factory=dict)   # 逻辑名 → 绝对路径
    mutants: List[Mutant] = field(default_factory=list)
    doc: str = ""


def _mut(path: str) -> str:
    return os.path.join(config.MUTANT_SRC_DIR, path)


def _build() -> Dict[str, ModuleSpec]:
    from . import csr_permit, trap_handle, trap_entry
    specs = {}

    specs["CSRPermitModule"] = ModuleSpec(
        name="CSRPermitModule",
        props=csr_permit.PROPS,
        sources={"CSRPermitModule": os.path.join(NEWCSR, "CSRPermitModule.scala")},
        doc="CSR 访问权限判定（II / VI 的唯一来源；case 层 + 等价性层）",
        mutants=[
            # pc1 = 回滚 XiangShan 94a4b91a（PR #6129），即恢复 menvcfg.STCE
            # 对 vstimecmp 的门控。上一轮把它当「历史 bug 重放」做阳性对照，
            # 依据是当时被误删了 “or vstimecmp” 的规范文本。规范在 2026-08-24
            # 由 PR #3344 恢复原文后，这个「历史 bug」反而成了正确实现 ——
            # 所以这里如实改判为 fix 对照：它应当让 CSRPermit/S3 由反例转为通过。
            Mutant("pc1", "CSRPermitModule",
                   "回滚 94a4b91a（= F1 的建议改法）：恢复 menvcfg.STCE 对 vstimecmp 的门控",
                   _mut("pc1_CSRPermitModule.scala"),
                   kind="fix", expect_fix=["S3", "EQ-permit"]),
            Mutant("m1", "CSRPermitModule",
                   "mcounteren.TM 不再门控 vstimecmp",
                   _mut("m1_CSRPermitModule.scala"), ["S1b", "EQ-permit"]),
            Mutant("m2", "CSRPermitModule",
                   "去掉 HU 态的 scounteren 检查",
                   _mut("m2_CSRPermitModule.scala"), ["C2"]),
            Mutant("m3", "CSRPermitModule",
                   "去掉 hstateen 对 sstateen 的门控",
                   _mut("m3_CSRPermitModule.scala"), ["E3", "EQ-permit"]),
            Mutant("m4", "CSRPermitModule",
                   "VS 计数器门控误用 scounteren 而非 hcounteren",
                   _mut("m4_CSRPermitModule.scala"), ["C3"]),
        ])

    specs["TrapHandleModule"] = ModuleSpec(
        name="TrapHandleModule",
        props=trap_handle.PROPS,
        sources={"TrapHandleModule": os.path.join(NEWCSR, "TrapHandleModule.scala")},
        doc="陷入目标特权态 / cause / 入口 PC / 双重陷入判定",
        mutants=[
            Mutant("t1", "TrapHandleModule", "hsEXVec 忽略 medeleg",
                   _mut("t1_TrapHandleModule.scala"), ["D2", "D5"]),
            Mutant("t2", "TrapHandleModule", "vsEXVec 忽略 hedeleg",
                   _mut("t2_TrapHandleModule.scala"), ["D4"]),
            Mutant("t3", "TrapHandleModule", "handleTrapUnderHS 去掉 !isModeM",
                   _mut("t3_TrapHandleModule.scala"), ["D6"]),
            Mutant("t5", "TrapHandleModule", "trapToHS 去掉 !vs_EX_DT",
                   _mut("t5_TrapHandleModule.scala"), ["DT2"]),
            Mutant("pc3", "TrapHandleModule",
                   "回滚 74fd4f59：VS 向量化入口 PC 用未映射的中断号",
                   _mut("pc3_TrapHandleModule.scala"), ["V3"]),
        ])

    events = os.path.join(NEWCSR, "CSREvents")
    specs["TrapEntryMEventModule"] = ModuleSpec(
        name="TrapEntryMEventModule",
        props=trap_entry.PROPS_M,
        sources={"TrapEntryMEventModule": os.path.join(events, "TrapEntryMEvent.scala")},
        doc="陷入 M 后各 CSR 次态（EQ-next：SIE 族；EQ-tval：tval2/GVA；EQ-tval-data：精确 xtval）",
        mutants=[
            # EQ-tval 必须精确匹配：startswith("EQ-tval") 会误吃 EQ-tval-data。
            Mutant("te1", "TrapEntryMEventModule",
                   "LS guest-page-fault 的 tval2 误用 trapPcGPA 而非 memGPA",
                   _mut("te1_TrapEntryMEvent.scala"), ["EQ-tval"]),
            Mutant("te2", "TrapEntryMEventModule",
                   "精确 tval 翻了 PC 与 memVA：mem 异常误写 trapPC",
                   _mut("te2_TrapEntryMEvent.scala"), ["EQ-tval-data"]),
        ],
    )
    specs["TrapEntryHSEventModule"] = ModuleSpec(
        name="TrapEntryHSEventModule",
        props=trap_entry.PROPS_HS,
        sources={"TrapEntryHSEventModule": os.path.join(events, "TrapEntryHSEvent.scala")},
        doc="陷入 HS 后各 CSR 次态（EQ-next：SIE 族；EQ-tval：tval2/GVA；EQ-tval-data：精确 stval）",
        mutants=[
            # 只改 HS 路径。没有这条的话，TrapEntryHS 三条 EQ 全绿不可信
            # （README：没有阳性对照则全部通过不可信）。
            Mutant("tehs1", "TrapEntryHSEventModule",
                   "HS：LS guest-page-fault 的 tval2 误用 trapPcGPA 而非 memGPA",
                   _mut("tehs1_TrapEntryHSEvent.scala"), ["EQ-tval"]),
        ],
    )
    return specs


_CACHE: Dict[str, ModuleSpec] = {}


def all_modules() -> Dict[str, ModuleSpec]:
    if not _CACHE:
        _CACHE.update(_build())
    return _CACHE


def get(name: str) -> ModuleSpec:
    m = all_modules()
    if name not in m:
        raise SystemExit(f"未知模块 {name}；已注册：{', '.join(sorted(m))}")
    return m[name]


def all_properties() -> List[Property]:
    out = []
    for spec in all_modules().values():
        out.extend(spec.props)
    return out
