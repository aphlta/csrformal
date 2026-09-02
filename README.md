# csrformal

用 SMT 求解器在全输入空间上验证香山 CSR 子系统是否符合 RISC-V 特权规范。
每条性质机械追溯到规范原文（规则 id + 原文哈希），规范变化时可定位到需要重新审阅的结论。

已在真实代码上找到 1 个确认级 RTL bug（Sstc：`menvcfg.STCE=0` 时未门控 `vstimecmp` 访问）。

## 适用范围

香山的 CSR 权限判定与陷入路由是纯组合真值表：输入是特权态、CSR 地址和一组 enable 位，
输出是抛不抛异常、抛哪种、陷到哪一级。`CSRPermitModule` 光地址就有 4096 种取值，
再乘 20 多个 enable 位，定向测试覆盖不全，而 SMT 可以穷尽。

三条自检机制：

- 每条性质先做假设集可满足性检查，不可满足判 `VACUOUS`（失败）而非通过，报告首屏给出真空条数。
- 每条性质携带 `rule_id`、规范源文件、commit 与原文哈希，`spec-drift` 据此比对。
- `self-test` 注入 10 个已知缺陷，要求意图对应的性质报出反例。

规则追溯的实际案例见 [规范漂移 demo](#规范漂移-demo)。

## 安装

### 外部工具（不由本仓库安装）

| 工具 | 版本 | 用途 | 默认路径（可用环境变量覆盖） |
|---|---|---|---|
| yosys | 0.68 | SystemVerilog → SMT2 | `CSRFORMAL_YOSYS` |
| firtool | 1.135.0 | CHIRRTL → SystemVerilog | `CSRFORMAL_FIRTOOL` |
| JDK + Scala 2.13 编译器 | 与 XiangShan 一致 | 精化 harness | `CSRFORMAL_JAVA` |
| `gh` | 任意 | 拉取规范仓库（本机 git-over-HTTPS 会超时，走 `gh api` + codeload tarball） | — |

### Python

```bash
pip install -r requirements.txt        # 只有 z3-solver
```

### XiangShan 工作树与 classpath

`cp.txt` 是一份已编译好的 XiangShan classpath（74 条，指向 `XiangShan-b90dbba/out/*`
与 coursier 缓存），有了它不必跑 mill 全量编译，精化只需秒级。
换机器时改 `csrformal/config.py` 里的 `XS_TREE` 与 `cp.txt`，或设 `CSRFORMAL_XS_TREE`。

## 怎么跑

```bash
# 1) 静态自检：性质元数据是否齐全，引用的规则 id 是否存在于规范中
./bin/csrformal lint

# 2) 记录规范基线（快照被引用规则的原文）
./bin/csrformal spec-baseline --ref main

# 3) 跑全部模块的全部性质，出报告
./bin/csrformal check all

# 只跑一个模块 / 只跑一条性质（调试用）
./bin/csrformal check CSRPermitModule
./bin/csrformal check CSRPermitModule --only S3

# 4) 规范漂移检测
./bin/csrformal spec-drift --ref main --json out/reports/spec-drift.json
# 把「需要重新审阅」的性质喂回去重跑
./bin/csrformal check all --review out/reports/spec-drift.json

# 5) 变异回归（阳性对照）
./bin/csrformal self-test --report out/reports/self-test.md

# 辅助
./bin/csrformal list                 # 列出全部性质
./bin/csrformal rules --text         # 列出被引用的规则 id 及原文
./bin/csrformal spike                # 多参照交叉检查的设计说明（未实现）
```

产物：

- `out/reports/compliance.md` —— 人可读的符合性报告（摘要 / 规则追溯表 / 反例详情 / 全量清单）
- `out/reports/compliance.json` —— 结构化结果，逐条给出结论、耗时、规则 id、反例取值
- `out/<tag>/m.sv`、`out/<tag>/c.smt2` —— 中间产物，可直接拿去手工调试

退出码：有反例 / 真空 / 错误时为 1，全通过为 0。

### 端到端实测（2026-09-01，`XiangShan-b90dbba` @ `b90dbba4`）

```
$ ./bin/csrformal check all --rebuild        # 全冷启动：重编 harness + 重新精化两个模块
==== 共 295 条：通过 294，反例 1，真空 0，未知 0，错误 0 ====
求解器累计 3.48s，壁钟 14.3s
```

- `CSRPermitModule` 155 条（152 条单实例 + 3 条特权单调性关系型）
- `TrapHandleModule` 140 条
- 唯一反例是 `CSRPermit/S3`，即已确认的 Sstc bug（F1）
- 真空 0 条
- 精化有缓存，复跑（`./bin/csrformal check all`）7.4 s，单条 `--only` 是秒级

## 规范漂移 demo

```bash
./bin/demo-spec-drift.sh
```

复现的是一起真实的规范编辑事故：

| 时间 | 事件 |
|---|---|
| 2025-12-16 | `riscv-isa-manual` PR #2504（纯文本搬运）误删了 `norm:menvcfg_stce_op2` 里的 “or `vstimecmp`” |
| 2026-06-24 | XiangShan PR #6129 与 NEMU PR #1093（同一作者，相隔 22 分钟）照着被删后的文本改了实现 |
| 2026-08-20 | `riscv-isa-manual` issue #3329 指出这是编辑事故 |
| 2026-08-24 | PR #3344 恢复原文，当前 main 已是恢复后的文本 |

结果是照着规范改的实现被规范勘误反转。demo 把基线固定在 2026-06-14
（`f20aa35`，实现作者当时看到的文本），再与当前 main 比对：

```
[CHANGED] norm:menvcfg_stce_op2
  基线位置 priv/machine.adoc:2222  sha=59c33250aeb8103c
  当前位置 priv/machine.adoc:2223  sha=e56229e7534fd5f1
  --- 词级差异（- 基线 / + 当前）---
    + or `vstimecmp`
  --- 受影响、需要重新审阅的性质（3 条）---
    * CSRPermit/S2
    * CSRPermit/S3
    * CSRPermit/S3b
```

demo 的第三步把这 3 条拿去重跑当前 RTL，`CSRPermit/S3` 给出反例，
即 `CSRPermitModule.scala:228-230` 已不符合恢复后的规范。

同一次比对还检出另外两条规则的文本变化：`norm:hideleg_trans` 删掉了一句关于平台中断的说明，
`norm:trap_unexp_hndl_rnmi` 加了两个词。对应的 4 条性质被标为需重新审阅，重跑后仍然通过。
漂移检测只负责标出需要复核的范围，不给出结论。

## 变异回归（阳性对照）

```bash
./bin/csrformal self-test --report out/reports/self-test.md
```

10 个变体，10/10 行为符合预期，约 77 s（每个变体要单独 scalac 覆盖编译 + 重新精化）：

| 变体 | 类型 | 内容 | 结果 |
|---|---|---|---|
| `pc1` | fix | 回滚 `94a4b91a`：恢复 `menvcfg.STCE` 对 `vstimecmp` 的门控 | FIXED（`CSRPermit/S3`、`S3b` 转为通过） |
| `m1` | defect | `mcounteren.TM` 不再门控 `vstimecmp` | KILLED by `S1b` |
| `m2` | defect | 去掉 HU 态的 `scounteren` 检查 | KILLED by `C2` ×5 |
| `m3` | defect | 去掉 `hstateen` 对 `sstateen` 的门控 | KILLED by `E3` ×4 |
| `m4` | defect | VS 计数器门控误用 `scounteren` 而非 `hcounteren` | KILLED by `C3` ×5 |
| `t1` | defect | `hsEXVec` 忽略 `medeleg` | KILLED by `D2`/`D5` ×36 |
| `t2` | defect | `vsEXVec` 忽略 `hedeleg` | KILLED by `D4` ×18 |
| `t3` | defect | `handleTrapUnderHS` 去掉 `!isModeM` | KILLED by `D6` ×9 |
| `t5` | defect | `trapToHS` 去掉 `!vs_EX_DT` | KILLED by `DT2` |
| `pc3` | defect | 回滚 `74fd4f59`：VS 向量化入口 PC 用未映射的中断号 | KILLED by `V3` ×3 |

`pc1` 上一轮的类型是 defect（历史 bug 重放的阳性对照），依据是当时被误删了 “or vstimecmp”
的规范文本。规范恢复后该实现变成正确实现，因此改判为 fix 对照，职责是断言 F1 的建议改法
确实修好了这个 bug。若不改判，一条过期的阳性对照会持续以 SURVIVED 的形式报出。

## 架构

```
bin/csrformal              入口（bash → csrformal.cli）
bin/demo-spec-drift.sh     规范漂移自证 demo
csrformal/
  config.py                路径与外部工具配置（环境变量可覆盖）
  props.py                 Property / SpecRef 数据模型（含可选 prove_fn）
  spec_permit.py           CSRPermit 独立规格函数（等价性层；禁止抄 Chisel）
  specdb.py                规范规则库：adoc 锚点提取、原文哈希、基线、漂移比对
  elaborate.py             Chisel → CHIRRTL → SystemVerilog（含覆盖编译的硬校验）
  smt.py                   SV → SMT2 → z3（电路只 parse 一次，性质用 push/pop）
  runner.py                真空性门禁 + 求解 + 结构化结果
  report.py                Markdown / JSON 报告
  cli.py                   子命令
  modules/
    __init__.py            模块注册表（性质 + 源文件 + 变异体）
    csr_permit.py          CSRPermitModule 的 155 条 case + 3 条 MONO + 1 条 EQ
    trap_handle.py         TrapHandleModule 的 140 条性质
src/eqcheck/Elab2.scala    最小精化 harness（把单个子模块当 top）
mutants-src/               变异体源码（base_* 与各变异版本）
spec/baseline.json         被引用规则的原文快照（进版本库、可被 review）
spec/cache/<sha>/          规范仓库某个 commit 的 adoc 缓存
docs/spike-crosscheck.md   多参照交叉检查设计说明（未实现）
```

### 已验证的技术路径

1. `firtool --btor2` 不可用，不支持 n 元 `comb.and`。
2. 可工作路径：最小 harness 把目标模块当 top → firtool 出 SystemVerilog
   （必须加 `--default-layer-specialization=disable`）→ `yosys read_verilog -sv`
   → `write_smt2` → z3。
3. 精化成本：`TrapHandleModule` 约 3 s、`CSRPermitModule` 约 4 s
   （`MStatusModule` 约 17 s、`MipModule` 约 54 s）。不需要整核精化。
4. 覆盖编译单个 `.scala` 时必须硬校验 scalac 退出码和产出的 `.class` 数量，
   `elaborate.py` 里两项都查。静默失败会让 classpath 悄悄回退到原始 class，
   注入的缺陷不会进入 RTL，变异测试全部假通过。

### registers=0

`CSRPermitModule` 与 `TrapHandleModule` 精化后 registers=0，为纯组合逻辑，单周期求解即完整。
跨模块契约（`irToVS ⇒ irToHS`、`intrVec ≤ 63`）未验证，作为假设处理，见「已知限制」。

## 怎么加一条新性质

编辑对应的 `csrformal/modules/<模块>.py`，用该文件里的 `case()` 助手加一行。
以 `csr_permit.py` 为例：

```python
case("S9",                                        # pid（模块内唯一）
     "menvcfg.STCE=0 → HU 访问 stimecmp 抛 II",    # 一句话说明
     R["stce2"],                                  # 规范引用（见文件顶部的 R 表）
     "HU", RD, 0x14D, II,                         # 特权态、读/写、地址、期望输出
     menv=clr(ONES64, 63))                        # 相对 CLEAN 的偏离
```

三条硬要求：

1. 必须给 `SpecRef`，优先给 `rule_id`（`norm:` 开头的 asciidoc 锚点）。
   没有对应锚点时（例如 AIA 在独立仓库、或性质是多条规则的组合），
   写 `SpecRef(None, "出处", note="为什么没有 id")`，不要凑 id ——
   错误的 id 会让 `spec-drift` 比对错误的段落。
2. 假设集必须可满足。`clean()` 的整字默认值是「除被测位外全 1」，
   要清某一位就用 `clr()` 传掩码，不要在 `assumes` 里另写一条相反的约束。
   真空性门禁会兜底。
3. 加完跑一遍：

```bash
./bin/csrformal lint                          # 规则 id 是否存在
./bin/csrformal spec-baseline --ref main      # 新引用的规则要进基线
./bin/csrformal check <模块> --only S9
```

关系型性质（跨两份实例，例如特权单调性）直接构造 `Property(kind="relational", free=[...])`，
`free` 里列出允许 A/B 取不同值的输入端口，其余输入由 runner 自动对齐。

等价性层和 case 层不是互相替换。case 钉死特权、地址、r/w，再用 `clean()` 关掉其它陷入源，
SMT 只穷尽剩余自由位，职责是选点回归。等价性层（`CSRPermit/EQ-permit`）用独立规格函数
`spec_permit.permit`，在「已建模使能位自由、未覆盖路径按假设关掉」下证
`(rtl.EX_II ↔ spec.II) ∧ (rtl.EX_VI ↔ spec.VI)`；地址、特权、ren/wen 全部自由，不再钉 0x14D。
规格只来自特权规范 / SpecRef，禁止把 RTL 比较器翻译进去。本轮没写进规格的条款
（XRet、FS/VS off、AIA 其余、Smstateen、Smcdeleg、custom、scountinhibit/scountovf）
必须写成可满足的假设关掉，否则会被无关路径打红。合取型主定理用 `prove_fn` 出 z3 公式，
条款的 `rule_id` 放 `extra_refs`，不要给合取硬凑一个 id。

## 怎么加一个新模块

以 `InterruptFilter` 为例，四步：

1. 确认 harness 能构造它。`src/eqcheck/Elab2.scala` 的 `build()` 里加一行
   `case "InterruptFilter" => new xiangshan.backend.fu.NewCSR.InterruptFilter`
   （这一条已经在了）。若模块构造需要额外参数，在这里补。
   删掉 `out/_harness_classes/.ok` 让它重编。

2. 先看端口。精化一次，用端口名写性质：

```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from csrformal import elaborate, smt
sv = elaborate.elaborate('InterruptFilter','base_InterruptFilter')
c  = smt.Circuit(smt.sv_to_smt2(sv,'InterruptFilter','out/base_InterruptFilter/c.smt2'),'InterruptFilter')
print(sorted(c.ins)); print(sorted(c.outs)); print('regs',len(c.regs))
"
```

   `regs` 不为 0 表示该模块有时序状态，单周期求解只覆盖组合部分，
   必须在性质里说明；改用多周期展开本工具目前不支持。

3. 新建 `csrformal/modules/interrupt_filter.py`，导出 `MODULE` 与 `PROPS`
   （照抄 `trap_handle.py` 的结构：一个 `CLEAN`、一个 `case()` 助手、一张 `R` 规范引用表）。

4. 在 `csrformal/modules/__init__.py` 的 `_build()` 里登记一行 `ModuleSpec(...)`，
   同时登记变异体。没有阳性对照，新模块的「全部通过」不可信。

变异体的做法：把 `XiangShan/.../<Module>.scala` 拷进 `mutants-src/<id>_<Module>.scala`，
改一处逻辑，在 `ModuleSpec.mutants` 里写清 `expect_kill`（应当抓住它的性质 pid 前缀）。

## 已知限制

1. 单周期组合逻辑。目前两个模块 registers=0，单周期即完整；但工具不支持时序展开，
   有状态的模块加进来只能覆盖组合部分。
2. 跨模块契约是假设。`TrapHandleModule` 的输入 `irToHS` / `irToVS` / `intrVec`
   由 `InterruptFilter` 产生，二者之间的约束（如 `irToVS ⇒ irToHS`）未被验证。
3. 43 条规则里有一部分性质没有规则 id：AIA 在独立仓库 `riscv/riscv-aia`，
   没有 `norm:` 锚点体系；特权单调性是结构性元性质，不对应单条条文。
   这些在报告的「规范规则追溯」一节里逐条列出了原因。
4. 未覆盖的模块：`InterruptFilter`（由另一项工作进行中）、`XRetPermitModule`
   （MRET/SRET/DRET/MNRET，与 debug 规范耦合）、`MStatusModule`、`MipModule`。
5. 未覆盖的条款：异常优先级表（规范把若干异常放在同一优先级组、组内无序，
   且把 load/store 地址不对齐相对页错误定为实现自定义，香山的差异落在规范
   未约束的自由度内）、AIA iprio 窗口的奇偶规则、fp/vec 的 `mstatus.FS/VS`、
   custom CSR 地址段。
6. 配置相关：结论基于 `MinimalConfig`（`geilen=7`），`vgein` 相关性质依赖该参数。
7. 多参照交叉检查未实现，只留了接口与设计说明（`docs/spike-crosscheck.md`）。
8. `spec-drift` 只检测被引用规则的文本变化，不检测「规范新增了一条我们没写性质的规则」。
   覆盖率缺口需要人来判断。
9. `CSRPermit/EQ-permit` 只覆盖 Privilege、只读写、Sstc、counteren、TVM。
   未覆盖条款靠假设关掉，不是用 RTL 行为填进规格。假设太松会被无关条款打红，
   应收紧假设或扩规格，不要抄比较器凑绿。

## 参考

- 上一轮的调查报告与证据链：`/ssdhome/maoweiming/csr-hunt/REPORT.md`
- 被测源码：`XiangShan/src/main/scala/xiangshan/backend/fu/NewCSR/`
  （`CSRPermitModule.scala`、`TrapHandleModule.scala`）
- 规范：`riscv/riscv-isa-manual`，`src/priv/*.adoc`
