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
宿主机 Ubuntu 20.04 上的 spike 因 glibc 过旧无法启动；实测走 Docker，见下一节。

## 实测（2026-09-02，S3 / HS + 0x24D + STCE=0）

具名容器 `csrformal-sstc-spike`，镜像 `spike-zvksh:local`（Ubuntu 22.04），`--user 537:513`。容器内 `apt-get install gcc-riscv64-unknown-elf`（10.2.0；`-march` 不认 `h`，汇编回退 `rv64gc`）。Spike：`/opt/spike/bin/spike`，`1.1.1-dev`。

```
CSRFORMAL_SPIKE=/opt/spike/bin/spike \
CSRFORMAL_RISCV_GCC=/usr/bin/riscv64-unknown-elf-gcc \
./bin/csrformal spike-cex out/reports/compliance.json
```

输出：

```
  CSRPermit/S3: HS 0x24d STCE=0  RTL=NONE spec=II  Spike=II
    判读：RTL bug（Spike 与 spec 一致、与 RTL 不一致）
```

`out/spike-cex/run.log`：`spike --isa=rv64gch_zicsr_sstc …/cex.elf`，`returncode=2`，stderr `*** FAILED *** (tohost = 2)`。同一 elf 再跑仍是 `tohost=2`。同容器里 HS + `0x14D`（stimecmp）+ STCE=0 也是 `tohost=2`。M 态或 STCE=1 去真正读 `0x24D` 时这份 spike 段错误，没有当成阳性对照。

| RTL (b90dbba) | spec | Spike |
|---|---|---|
| NONE（不抛 II） | II | II |

判读：RTL bug。

## 已知 S3 反例的手工步骤（HS, 0x24D, STCE=0）

输入与 `CSRPermit/S3` / `EQ-permit` 同类：HS（PRVM=S, V=0），地址 `0x24D`（vstimecmp），`menvcfg.STCE=0`，读或写均可。

1. 用 `riscv64-unknown-elf-gcc -nostdlib -march=rv64gc` 编一段裸机：M 态把 `menvcfg`（CSR `0x30A`）的 STCE 清零，设 `mstatus.MPP=S`、`MPV=0`，`mret` 进 HS，再 `csrr t0, 0x24D`。fesvr 要 `tohost`+`fromhost`，退出码写成 `(mcause<<1)|1`。
2. `spike --isa=rv64gch_zicsr_sstc <elf>`，看 `mcause`：2 = II，22 = VI。
3. 源码对照：`stimecmp_csr_t::verify_permissions` 第一项是 `menvcfg.STCE=0` 且 `prv<M` → `trap_illegal_instruction`。`vstimecmp` 与 `stimecmp` 共用此类。

issue [#3329](https://github.com/riscv/riscv-isa-manual/issues/3329) 也曾用同一处 Spike 检查作为「原文被误删」的旁证。
