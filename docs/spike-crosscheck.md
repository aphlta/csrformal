# Spike 交叉检查：反例定性，不穷举

形式化给出反例之后，用同一组输入问 Spike 的 CSR 权限，三方投票：

| RTL | Spike | 规格 | 判读 |
|---|---|---|---|
| 错 | 对 | 对 | RTL bug |
| 对 | 错 | 对 | Spike bug |
| 错 | 错 | 对 | 条文歧义或两家实现作同一理解 |
| 对 | 对 | 错 | 规格写错 |

Spike 不参与全输入空间求解。未默认启用：`csrformal check` 要加 `--spike`，或事后 `csrformal spike-cex out/reports/compliance.json`。本机没有能跑的 spike 时跳过，不假装跑过。

## 入口

```
./bin/csrformal check CSRPermitModule --only EQ --spike
./bin/csrformal spike-cex out/reports/compliance.json
./bin/csrformal spike-cex --controls-only
```

环境变量：`CSRFORMAL_SPIKE`、`CSRFORMAL_RISCV_GCC`、`CSRFORMAL_SPIKE_SRC`。
实现在 `csrformal/spike_oracle.py`：解析反例里的 priv / addr / wen / STCE，能跑则子进程编一段裸机；不能跑则打印手工步骤。`spike-cex` 额外跑两例固定对照（同一 `cex.S` 模板、同一 `--isa=`）。

## 源码对照

相关文件：riscv-isa-sim 的 `riscv/csrs.cc`，`stimecmp_csr_t::verify_permissions`。
宿主机 Ubuntu 20.04 上的 spike 因 glibc 过旧无法启动；实测走 Docker，见下一节。

`--isa` 必须带 `zicntr`。该函数在 STCE 检查通过后会解引用 `time_proxy`；不含 `zicntr` 时 Spike 不建 `time` CSR，合法读 `(v)stimecmp` 把 host spike SIGSEGV。非法路径先抛 II，碰不到这行。段错误是 harness / ISA 串问题，不是「Spike 认为合法访问也不行」。

## 实测（2026-09-03，同一容器 / 同一 `--isa=`）

具名容器 `csrformal-sstc-spike`，镜像 `spike-zvksh:local`（Ubuntu 22.04），`--user 537:513`。容器内 `gcc-riscv64-unknown-elf` 10.2.0（`-march` 不认 `h`，汇编回退 `rv64gc`）。Spike：`/opt/spike/bin/spike`，`1.1.1-dev`。

```
CSRFORMAL_SPIKE=/opt/spike/bin/spike \
CSRFORMAL_RISCV_GCC=/usr/bin/riscv64-unknown-elf-gcc \
./bin/csrformal spike-cex out/reports/compliance-2026-09-03.json
```

`spike --isa=rv64gch_zicsr_zicntr_sstc`。阳性对照是 **M 态**读 `vstimecmp`（`STCE=0` 也行，证明是特权不是 STCE）。没有用 HS+STCE=1：同一胶水下 HS+STCE=1 仍会被 `time_proxy` 的 `mcounteren.TM` 打成 II，要再写 `0x306`，就不算「同一套裸机参数」了。

| 用例 | 特权 | 地址 | STCE | tohost / 退出码 | Spike |
|---|---|---|---|---|---|
| `CSRPermit/S3` | HS | 0x24D | 0 | `tohost=2`，returncode=2 | **II** |
| `ctrl/illegal-HS-stimecmp` | HS | 0x14D | 0 | `tohost=2`，returncode=2 | **II** |
| `ctrl/legal-M-vstimecmp` | M | 0x24D | 0 | 无 FAILED 行，returncode=0 | **NONE** |
| `CSRPermit/EQ-permit`（附带） | VU 写 | 0x24D | 0 | `tohost=2`，returncode=2 | **II** |

日志在 `out/spike-cex/<pid>/run.log`。合法对照不再 SIGSEGV。

S3 三方：

| RTL (b90dbba) | spec | Spike |
|---|---|---|
| NONE（不抛 II） | II | II |

判读：RTL bug。这只覆盖 `menvcfg.STCE=0` 时非 M 访问 `(v)stimecmp`，不是 CSR 权限全空间。

缺 `zicntr` 的旧串（`rv64gch_zicsr_sstc`）上，同一份 M 态 / HS+STCE=1 elf 会让 spike `returncode=-11`（SIGSEGV）。现在优先试带 `zicntr` 的串；host 崩溃不当 mcause。

## 已知 S3 反例的手工步骤（HS, 0x24D, STCE=0）

输入与 `CSRPermit/S3` / `EQ-permit` 同类：HS（PRVM=S, V=0），地址 `0x24D`（vstimecmp），`menvcfg.STCE=0`，读或写均可。

1. 用 `riscv64-unknown-elf-gcc -nostdlib -march=rv64gc` 编一段裸机：M 态把 `menvcfg`（CSR `0x30A`）的 STCE 清零，设 `mstatus.MPP=S`、`MPV=0`，`mret` 进 HS，再 `csrr t0, 0x24D`。fesvr 要 `tohost`+`fromhost`，退出码写成 `(mcause<<1)|1`。
2. `spike --isa=rv64gch_zicsr_zicntr_sstc <elf>`，看 `mcause`：2 = II，22 = VI；成功路径 tohost=1、进程退出 0。
3. 源码对照：`stimecmp_csr_t::verify_permissions` 第一项是 `menvcfg.STCE=0` 且 `prv<M` → `trap_illegal_instruction`。`vstimecmp` 与 `stimecmp` 共用此类。

issue [#3329](https://github.com/riscv/riscv-isa-manual/issues/3329) 也曾用同一处 Spike 检查作为「原文被误删」的旁证。
