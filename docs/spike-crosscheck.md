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
```

环境变量：`CSRFORMAL_SPIKE`、`CSRFORMAL_RISCV_GCC`、`CSRFORMAL_SPIKE_SRC`。
实现在 `csrformal/spike_oracle.py`：解析反例里的 priv / addr / wen / STCE，能跑则子进程编一段裸机；不能跑则打印手工步骤。

## 源码对照

相关文件：riscv-isa-sim 的 `riscv/csrs.cc`，`stimecmp_csr_t::verify_permissions`。
本仓库开发机上的 spike 二进制因 glibc 过旧无法启动（2026-09-02 探测），所以没有实测数字。

## 已知 S3 反例的手工步骤（HS, 0x24D, STCE=0）

输入与 `CSRPermit/S3` / `EQ-permit` 同类：HS（PRVM=S, V=0），地址 `0x24D`（vstimecmp），`menvcfg.STCE=0`，读或写均可。

1. 用 `riscv64-unknown-elf-gcc -nostdlib -march=rv64gch` 编一段裸机：M 态把 `menvcfg` 的 STCE（bit 63）清零，设 `mstatus.MPP=S`、`MPV=0`，`mret` 进 HS，再 `csrr t0, 0x24D`。
2. `spike --isa=rv64gch_zicsr_sstc <elf>`，看 `mcause`：2 = II，22 = VI。
3. 源码对照（不跑也能定性）：`stimecmp_csr_t::verify_permissions` 第一项是 `menvcfg.STCE=0` 且 `prv<M` → `trap_illegal_instruction`。`vstimecmp` 与 `stimecmp` 共用此类（`csr_init.cc` 里两个地址都 `make_shared<stimecmp_csr_t>`）。

按源码，Spike=II，与恢复后的 `norm:menvcfg_stce_op2` / 本仓库 spec 一致，与 b90dbba 的 RTL（不门控 vstimecmp）不一致 → RTL bug。这是源码阅读结论，不是本机实测。

issue [#3329](https://github.com/riscv/riscv-isa-manual/issues/3329) 也曾用同一处 Spike 检查作为「原文被误删」的旁证。
