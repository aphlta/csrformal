"""性质（Property）与规范引用（SpecRef）的数据模型。

一条性质 = 一个 SMT 假设集 + 一个待证公式 + 一份规范出处。

设计要点
--------
1. **假设集与结论分离**：假设集描述「场景」（哪个特权态、哪些位被清零、
   其它陷入源全部关掉），结论描述「规范要求的输出」。分离之后才能对
   假设集单独做真空性自检。
2. **每条性质必须有 SpecRef**。允许 rule_id 为 None（例如 AIA 有独立文档、
   或者性质是多条规则的合取），但那时必须写清 `note` 说明出处，
   由 `csrformal lint` 强制检查，不允许留空。
3. **kind**：`single` 用单实例求解（spec.py 路线），
   `relational` 开 A/B 两份实例证跨实例关系（spec2.py 路线）。
4. **prove_fn**（可选）：主定理这类「规格函数 ↔ RTL」不宜再写成一长串
   SMT-LIB 字符串。给出 `prove_fn(circuit) -> z3.BoolRef` 时，runner
   用这份公式代替 `prove` 字符串；现有 case 的求解路径不变。
"""
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass(frozen=True)
class SpecRef:
    """一条性质的规范出处。

    rule_id 为 None 表示「规范原文没有可机械引用的锚点」——
    如实标注比硬凑一个近似的 id 更重要：硬凑会让 spec-drift 去盯错误的段落，
    比没有追溯更糟。
    """
    rule_id: Optional[str]
    doc: str                      # 人可读的文档名，如 machine.adoc / AIA 5.4
    note: str = ""                # rule_id 为 None 时必填：出处说明

    def label(self) -> str:
        return self.rule_id or f"（无规则 id）{self.doc}"


@dataclass
class Property:
    pid: str                      # 全局唯一，形如 CSRPermit/S3
    title: str                    # 一句话说明检查什么
    module: str                   # 被测模块名（= 精化 top）
    assumes: List[str]            # SMT-LIB 布尔表达式，全部合取
    prove: str                    # SMT-LIB 布尔表达式，需在假设下恒真
    ref: SpecRef = field(default_factory=lambda: SpecRef(None, "?", "未标注"))
    kind: str = "single"          # single | relational
    free: List[str] = field(default_factory=list)   # relational: 允许 A/B 不同的输入
    tags: List[str] = field(default_factory=list)
    # 可选：用 z3 AST 当待证公式。现有 case 不设此项，仍走 prove 字符串。
    prove_fn: Optional[Callable] = None
    # 合取型主定理的各条款出处。lint / spec-drift 会把这里的 rule_id
    # 和 ref.rule_id 一起收入 referenced_rules；不要把条款塞进一个假 id。
    extra_refs: List[SpecRef] = field(default_factory=list)
    # 可选：把反例模型译成可读字段（addr、特权态、STCE…）。
    explain_fn: Optional[Callable] = None

    def __post_init__(self):
        if self.ref.rule_id is None and not self.ref.note:
            raise ValueError(f"{self.pid}: 无 rule_id 的性质必须写 note 说明出处")
        if self.prove_fn is None and not self.prove:
            raise ValueError(f"{self.pid}: 必须给 prove 字符串或 prove_fn")
