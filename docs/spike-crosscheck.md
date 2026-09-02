# 多参照交叉检查（Spike）：设计说明与接口（未实现）

## 动机

本工具目前是「RTL vs 形式化性质」两方对拍。两方对拍的死角是：性质写错和 RTL 写错
在报告上都表现为 VIOLATED，只能靠人复核。

引入第三方参照（Spike，`riscv-isa-sim`）后，三方的分歧模式本身可用于分类：

| RTL | Spike | 性质 | 判读 |
|---|---|---|---|
| 错 | 对 | 对 | RTL bug（置信度最高） |
| 对 | 错 | 对 | Spike bug |
| 错 | 错 | 对 | 规范条文歧义或勘误：两个独立实现作同一理解 |
| 对 | 对 | 错 | 性质写错 |

第三行已有实例：`norm:menvcfg_stce_op2` 的 issue
[#3329](https://github.com/riscv/riscv-isa-manual/issues/3329) 中，报告者用 Spike 的
`stimecmp_csr_t::verify_permissions`（`stimecmp` 与 `vstimecmp` 共用，第一项检查就是
`MENVCFG_STCE`）作为规范原文被误删的证据。

## 本地资源

Spike 源码：`/ssdhome/maoweiming/xiangshan-work/issues/1872/riscv-isa-sim`
相关文件：`riscv/csrs.cc`（各 CSR 的 `verify_permissions`）、`riscv/csrs.h`。

## 拟定接口

在 `csrformal/oracle.py` 里定义一个协议，让参照实现可插拔：

```python
class Oracle(Protocol):
    name: str
    def csr_permit(self, st: CsrState, addr: int, write: bool) -> Verdict:
        """给定 CSR 架构状态与一次访问，返回 NONE / ILLEGAL / VIRTUAL。"""
```

- `CsrState` 是 `CSRPermitModule` 输入端口集合的语义化版本
  （privState、mcounteren/hcounteren/scounteren、menvcfg/henvcfg、
  mstateen*/hstateen*、mstatus.TVM、hstatus.VTVM/VGEIN、miselect/siselect/vsiselect）。
- `SmtOracle` 复用 `smt.Circuit`，把反例模型翻译成 `CsrState`。
- `SpikeOracle` 有两条可选实现路径：
  1. 进程内：把 `riscv/csrs.cc` 里的 `verify_permissions` 抽出来编成一个小 `.so`，
     用 ctypes 喂状态。改动小，但需要构造 `processor_t` 的桩。
  2. 子进程：生成一段只做 CSR 访问的裸机测试，用 `spike --isa=...` 跑，从 `mcause` 读判决。
     每点约 50 ms，但零侵入。形式化反例数量在个位数到几十个量级，选这条。

## 与现有流水线的接法

反例驱动，不穷举：

```
csrformal check → VIOLATED 的性质 → 反例模型（一组完整输入取值）
                                   → SpikeOracle 在同一输入上求判决
                                   → 三方投票写进报告的「候选发现」表
```

Spike 不参与全输入空间求解，只在形式化找到反例之后给该反例定性。

## 未实现的原因

优先级排在 P2，本轮预算用在了 P0/P1（工具整合、规则追溯、真空性门禁、规范漂移、变异回归）。
这里只留接口与判读表。
