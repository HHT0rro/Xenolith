# AArch64 虚拟化引擎设计(vm-aarch64)——v3 修订版

- 工作树:`E:/XiangMu/Xenolith-android`(分支 `feat/android`,基线 commit `fbdb7cb` + 前轮未提交的 probe-mask 改动)。main 检出不动。
- v3 修订:吸收 v2 评审 4 条(§7.5 GSP/GUEST_FRAME 算术矛盾、§6.3 cmn 十谓词精确声明为假、§3.1#2/#3 imm6 未按 sf 封顶、§7.5 cap 数值与理由不合),并自查发现并修复同类缺陷(**tst/ands 的 hs/lo/hi/ls 消费分歧**,v2 评审未点名、缺陷类别与 cmn 相同)。全部编码事实本机 NDK 复核(§0.3,含 v3 新增行)。
- 基线测试本机执行:`cargo test --manifest-path E:/XiangMu/Xenolith-android/Cargo.toml -p xenolith-vm --lib` → 48 passed(0.22s)、`-p xenolith-pack --lib` → 101 passed(43.94s)、`-p xenolith-formats --lib` → 28 passed(0.00s)。NDK r27.2(12479018)在位,`xl_core_aarch64.o` 已构建于 `target/debug/build/xenolith-pack-02dabb80f82d9ca5f/out/`。

---

## 0. 现状锚点与编码事实底座

### 0.1 ELF 侧当前把 `--vm-export` 关死的门

`crates/xenolith-pack/src/platform/elf.rs:144-148`:

```rust
if !request.vm_exports.is_empty() || !request.select_rva.is_empty() {
    return Err(PackError::Invalid(
        "ELF function selection requires the SysV lift (stage 5); fail-closed here",
    ));
}
```

以及 `elf.rs:149-159`:`--strict-coverage` 直接拒绝;`--select-function/--select-all` 强制 `--allow-native-fallback`,coverage 一律 `mixed_native / sysv-lift-not-implemented`(`elf.rs:541-560`)。本设计把这个门替换成"aarch64 走新流水线,x86_64 ELF 保持命名拒绝"(§8.2)。

### 0.2 可复用资产(实读验证)

| 资产 | 位置 | 复用方式 |
|---|---|---|
| 白名单解码+CFG 提升(fail-closed 范式) | `xenolith-pack/src/lift.rs` | 算法与纪律照抄,ISA 层重写 |
| IR + 软件 oracle | `xenolith-vm/src/ir.rs`、`semantics/state.rs` | 枚举复用,新增 64 位模型(§6) |
| 逐块 PIC 发射(reg 分配/MBA/junk) | `xenolith-vm/src/superop.rs` | 算法照抄,发射器重写 |
| AArch64 手工编码器 + label fixup | `xenolith-pack/src/stub_aarch64.rs:31-251` | 直接泛化(§7.1);imm12 编码器仅 add/sub(`:78-89`),无 eor/and 立即数编码器(§7.3) |
| AArch64 重定位应用(白名单) | `xenolith-pack/src/runtime_image.rs:563-639` | 位段布局权威参照 |
| RX 页密封 + INIT_ARRAY 引导 | `elf.rs:197-237`、`756-895` | 不变,只改密封读取顺序(§5.4) |
| RELATIVE-into-RX 安全门 | `elf.rs:160`、`674-734` | 保留,新增内引用扫描(§5.2) |
| ifunc resolver 枚举 | `elf.rs:99-106`(`ifunc_resolvers` 在 99-102、`ifunc_symbol_values` 在 104-106) | 供选择器禁入(§8.4) |
| 协议平台字节 | `xenolith-protocol/src/lib.rs:15-27` | 不改协议(§8.1) |
| 禁入名单(JNI/CRT ABI) | `lift.rs:193-212` | 规则表共享,再增 ifunc 项 |

### 0.3 编码事实底座(本机实测)

命令(每轮实际执行):

```
E:/opt/android-sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe \
  --target=aarch64-linux-android35 -c enc.S -o enc.o
.../llvm-objdump.exe -d enc.o
```

关键实测字(v3 全部修正的依据):

| 源语句 | 机器字 | 结论 |
|---|---|---|
| `b.lo .+8` | `54000043` | **cond=3**(cc/lo 是 3,不是 4) |
| `b.mi .+8` / `b.al .+8` / `b.vs .+8` | `54000044` / `5400004e` / `54000046` | cond=4/14/6 → fail-closed 集 |
| `movz x0,#0x10` / `movz w0,#0x10` | `d2800200` / `52800200` | movz X 基 0xD2800000,W 基 0x52800000 |
| `movk x0,#0x1234` / `movk w0,#0x1234` | `f2824680` / `72824680` | movk X 基 0xF2800000,W 基 0x72800000 |
| `movk x0,#0x1234,lsl #16` | `f2a24680` | hw 位 [22:21] |
| `lsl x0,x1,#1` / `lsl w0,w1,#1` | `d37ff820` / `531f7820` | UBFM immr=(sz−m) mod sz(63/31),imms=sz−1−m(62/30) |
| `lsr x0,x1,#5` / `asr x2,x3,#7` | `d345fc20` / `9347fc62` | immr=m,imms=sz−1 |
| `lslv x4,x5,x6` | `9ac620a4` | 变移位形 |
| `b .+8` / `bl .+8` | `14000002` / `94000002` | b 仅 [31:26]=000101;bl=100101 |
| `adr x0, .` | `10000000` | adr(immlo=00)的 [31:26]=000100——与 b 双值匹配必撞码 |
| `adrp x0, .+0x1000` | `90000000` | adrp [31:24]=0x90 |
| `add x0,x1,x2` | `8b020020` | bit21=0 shifted-register 纯形(LSL #0),最常见形 |
| `add x0,x1,x2,uxtx` / `,lsl #3` / `,w2,sxtw #2` | `8b226020` / `8b020c20` / `8b22c820` | extended 形 option+**imm3**;shifted 形 imm6 |
| `add w0,w1,w2,lsl #31` | `0b027c20` | **W 形 imm6=31 合法(边界)** |
| `add w0,w1,w2,lsl #32` | 汇编报错(range [0,4] extend 通道 / [0,31] shift 通道) | **sf=0 且 imm6>31 是 UNDEFINED 编码,解码器必须命名拒绝** |
| `lsr w3,w4,#33` / `and w5,w6,w7,lsl #47` | 汇编报错 `immediate must be an integer in range [0, 31]` | 同上,W 形移位立即数上限 31 |
| `cmp x0,#-1` | `b100041f` = `cmn x0,#1` | 汇编器把负立即数比较自动转 cmn——cmn 必须支持 |
| `cmn x0, x1` / `cmn x0, #0` | `ab01001f` / `b100001f` | 寄存器形;**imm=0 形汇编器接受 → C 位角真实存在**(§6.3) |
| `adds x4,x5,x6` / `subs x7,x8,x9` | `ab0600a4` / `eb090107` | S=1 值+flags 形 |
| `tst x2, x3` / `tst x3,#0xff` | `ea03005f` / `f2401c7f` | ands xzr(寄存器/位掩码) |
| `cmp x1,x2` | `eb02003f` | subs xzr |
| `and x4,x5,#0xff` / `eor x16,x16,#0xfff` | `92401ca4` / `d2402e10` | 连续游程位掩码可编码 |
| `and x4,x5,#0x123`、`eor x16,x16,#0x123`、`#0x12345` | 汇编报错 `expected compatible register or logical immediate` | 无逻辑 imm12;非游程立即数不可编码;junk 不能用任意 SHA 派生立即数 |
| `ldr x0,[x1,#8]`…`strh w12,[x13,#6]` | `f9400420` `b9400c62` `39403ca4` `79401ce6` `f9000928` `39000d6a` `79000dac` | 无符号偏移族 size:opc + imm12 换算 |
| `ldp x0,x1,[sp,#16]` | `a94107e0` | 有符号 imm7 |
| `stp x29,x30,[sp,#-16]!` | `a9bf7bfd` | 前索引(与 stub_aarch64.rs:37 一致) |
| `ldp x2,x3,[sp],#16` | `a8c10fe2` | 后索引 |
| `cbz x0` / `cbnz w1` | `b4000040` / `35000041` | sf 位 |
| `tbz x0,#3` / `tbnz x0,#63` | `36180040`(显 w0)/ `b7f80040` | b5 同时决定 W/X 视角与 bit40 |
| `ret` / `nop` / `paciasp` | `d65f03c0` / `d503201f` / `d503233f` | |
| `mov x0,x1` / `mov x0,sp` | `aa0103e0` / `910003e0` | mov reg;SP 作普通源读(= add xD,sp,#0) |
| `add sp,sp,#32` / `sub sp,sp,#48` | `910083ff` / `d100c3ff` | SP 白名单写形态 |

---

## 1. x86-64 引擎架构提炼(移植的"宪法")

流水线(实读 `lib.rs:425-663`、`lift.rs`、`superop.rs`):

```
--vm-export 名单 (lib.rs:501-508 禁入预检)
  → FunctionSelector::resolve (selection.rs:31)
  → lift_function (lift.rs:37-106; thunk 解析 ≤4 跳)
  → decode_reachable (lift.rs:297-367; worklist, 256B 上限, 出窗即错)
  → lift_block/classify_instr (lift.rs:369-766; 白名单 → Stmt/Term)
  → IR oracle (state.rs:113-254; 软件解释器 = 等价性真值)
  → emit_superop_ex (superop.rs:31-44; 逐块重编译 PIC)
  → stub 内嵌 guest thunk (lib.rs:619-649; 数量守恒断言)
  → apply_vm_hook (lib.rs:1714-1782; 导出表改指 + E9 + 0xCC)
```

移植五纪律:fail-closed 默认(错误点名函数/指令/RVA/出路,`lift.rs:1453-1468`)、宽度门(aarch64 锁 64 位模型,§6.1)、flags 融合(**v3:按产生者×谓词矩阵精确放行/拒绝,§6.3**)、无溢出寄存器分配(`superop.rs:264-272`)、thunk 数量守恒(`lib.rs:642-649`)。

---

## 2. AArch64 引擎总体架构

```
--vm-export (ELF+aarch64) (elf.rs 门替换, §8.2)
  → FunctionSelector Elf64 flavor (§8.4; symtab 边界 + 禁入含 ifunc)
  → lift_function_aarch64 (xenolith-pack/src/lift_aarch64.rs)
      decode_reachable64:  自研白名单解码器 (xenolith-vm/src/aarch64_decode.rs)
      lift_block64:        指令 → ir64 (§3, §4, §6)
  → oracle: eval_machine64 (xenolith-vm/src/ir64.rs)
  → emit_superop_aarch64 (xenolith-vm/src/superop_aarch64.rs; §7)
  → stub 内嵌 guest thunk (stub_aarch64.rs 扩展, §8.3)
  → apply_vm_hook_elf: 4 字节 b rel26 + brk #0 填充 (§5.3)
  → 重引用/重定位安全门 (§5)
```

### 2.1 解码器选型:自研白名单解码器

同前(无新依赖、fail-closed by construction、与 §0.3 实测字 round-trip、与 `stub_aarch64.rs:60-118`/`runtime_image.rs:573-635` 编码侧常量互逆)。契约:未知字 `LiftError("unsupported instruction word {word:#010x} at {ip:#x}…")`;**不得 panic**(A6)。编码规约:**opcode 全掩码比较先于立即数字段提取**(adr/b 撞码教训,§0.3);**UNDEFINED 编码与非法宽度组合(sf=0 且 imm6>31 等)与未知字同权命名拒绝**(v3,§3.1#2/#3)。

crate 归置:新增 `aarch64_decode.rs`/`ir64.rs`/`superop_aarch64.rs`(xenolith-vm)与 `lift_aarch64.rs`(xenolith-pack);`stub_aarch64.rs` 的 `Asm/Fixup` 提为共享模块;不动 `ir.rs`/`semantics/state.rs`。

---

## 3. 指令类覆盖矩阵(v3 修正)

### 3.1 首批放行(编码要点以 §0.3 实测字为准)

| # | 指令类 | 编码要点(解码期校验) | IR64 建模 |
|---|---|---|---|
| 1 | `add/sub`(imm12,含 `<<12` 变体;X/W) | `op[30:23]`、`S=0` | `Bin{Add/Sub, sf}`;W 写零扩 |
| 2 | `add/sub` 寄存器,两种编码:(a) bit21=0 shifted-register:纯形(LSL #0)与 `lsl #imm6`;**imm6 上限按 sf 封顶:sf=1 时 0..63,sf=0 时 0..31(超过为 UNDEFINED,命名拒绝——实测 #31 合法 `0b027c20`、#32 汇编器拒绝)**;LSR/ASR/ROR 操作数移位首批 fail;(b) bit21=1 extended:`UXTB/UXTH/UXTX/SXTB/SXTH/SXTW` + imm3(0..3) | (a) `8b020020`/`8b020c20`/`0b027c20`;(b) `8b226020`/`8b22c820` | (a) 移位形发射器可直接再编码(imm6 原生);(b) extend+shift 进 scratch 再主 `Bin`(别名四象限法,`lift.rs:905-1018`) |
| 3 | `and/orr/eor`(寄存器,可选 LSL/LSR/ASR imm 移位;ROR fail) | N=0;**移位立即数同样按 sf 封顶(W:0..31,实测 `and w…,lsl #47` 拒绝),超限命名拒绝** | 移位进 scratch 再主 `Bin` |
| 4 | `and/orr/eor`(bitmask 立即数) | `N:immr:imms` 标准解码;UNDEF 保留形命名拒绝 | 立即数经 movz/movk 物化进 scratch 再寄存器形(§7.4) |
| 5 | `adds/subs/cmp/cmn/tst` | S=1;`cmp 负imm` 以 cmn 形到达(`b100041f`);寄存器/立即数形见 §0.3 | 值照常写;flags 经 §6.3 的**产生者×谓词矩阵**放行或命名拒绝(v3:不再声称全谓词支持) |
| 6 | `lsl/lsr/asr` imm(UBFM/SBFM 精确别名形) | 别名表:LSL #m(m>0): immr=(sz−m) mod sz, imms=sz−1−m;LSL #0 是 MOV 别名;LSR/ASR #m: immr=m, imms=sz−1;字段不匹配别名表 → fail-closed | `Bin{Shl/Shr/Sar, imm}`;计数按 sf 掩码 |
| 7 | `lslv/lsrv/asrv` | `9ac620a4` 族 | `Bin{…, Reg}`;oracle 掩码 `& (sz-1)`(`state.rs:440-453` 同型) |
| 8 | `movz/movk/mov` | movz X=0xD2800000 / W=0x52800000 / movk X=0xF2800000 / W=0x72800000;hw∈[22:21];`mov reg`=`orr rd,xzr,rm`(`aa0103e0`);`mov xD,sp`=`add xD,sp,#0`(SP 读放行 §6.1) | movz 直接;movk = `(old & ~(0xFFFF<<hw*16)) \| imm<<hw*16`(物化掩码 + and + or);mov reg → `Mov` |
| 9 | `b imm26` | 唯一操作码 [31:26]=000101(bl=100101 fail;000100 是 adr 空间) | `Term::Jmp`(leaders 算法照抄 `lift.rs:224-243`) |
| 10 | `b.cond` | cond ∈ {0,1,2,3,8,9,10,11,12,13} = eq/ne/cs-hs/cc-lo/hi/ls/ge/lt/gt/le;{4,5,6,7,14,15} = mi/pl/vs/vc/al/nv fail-closed。**可用谓词还受 §6.3 产生者矩阵约束** | `Term::BrCmp` |
| 11 | `cbz/cbnz`(X/W) | sf 位(`b4000040`/`35000041`) | `BrCmp{Eq/Ne}`;W 形低 32 位比较 |
| 12 | `tbz/tbnz` | b5 同时定 W/X 视角与 bit40;W 形(bit<32)只测低 32 位 | AndCmp 降级:`scratch = reg & (1<<bit)` 再比 0(仅产生 eq/ne 消费——tbz 自身就是 eq/ne,无 hs 语义,天然安全) |
| 13 | `ret`(Rn=x30) | `d65f03c0` | `Term::Ret` |
| 14 | `ldr/str` 无符号偏移 imm(X×8/W×4/H×2/B×1) | `size:opc` + imm12 换算(§0.3 七字) | `Load/Store{BaseDisp, width}`;窄读零扩 |
| 15 | `ldp/stp` X 对(有符号 imm7;含前/后索引) | `a94107e0`/`a9bf7bfd`/`a8c10fe2` | 前索引 = `Bin{Sub,dst:SP,imm}` + 2×Store(用更新后 SP);后索引 = 2×Load + `Bin{Add,dst:SP}`;`multi_step` 保序(`lift.rs:1025-1032`) |
| 16 | `adr` / `adrp` | adr imm21=immlo[30:29]+immhi[23:5];adrp 同字段 <<12,基 0x90 | 均为 `Stmt::Bias{dst, rva}`:adr→精确 rva;adrp→页基(lo12=0)。不折叠、不配对追踪(§4) |
| 17 | `nop` | `d503201f` | `Skip`(保守:仍清 flags 融合) |

SP 白名单写:`add/sub sp,sp,#imm`(真实 Bin)、ldp/stp 前后索引更新;`mov xD,sp` 为放行的 SP 读。其余 SP 引用 fail-closed。

### 3.2 首批 fail-closed(命名错误;stage-2 备注)

同前,补充明确:mi/pl/vs/vc/al/nv 谓词、**寄存器形 cmn/adds 的有序谓词消费与 tst/ands 的 hs/lo/hi/ls 消费**(§6.3,v3)、**cmn imm=0**、**sf=0 且移位立即数 >31 的 UNDEFINED 编码**(v3)、movn、乘除、csel 族、独立扩展、寄存器偏移/非缩放/字面量访存、bfm/extr/ror imm/rev/clz/rbit、系统/屏障/异常、一切调用、x18 引用、LR 非内存形写、SIMD/FP 全部、原子/独占、PAC 全部、BTI(输入侧)、add/sub 操作数移位中的 LSR/ASR/ROR。

---

## 4. ADR/ADRP 页边界处理

### 4.1 语义事实

- `adr xD, T`:`T = pc + SignExtend(immhi:immlo, 21)`,±1MiB。
- `adrp xD, T`:`T_page = (pc & ~0xFFF) + (SignExtend(immhi:immlo, 21) << 12)`。

页边界陷阱:adrp 立即数相对 **PC 所在页**;目标页与 pc_page 的关系依赖 lo12(pc) 与 lo12(T) 的相对大小,naive 两步合成跨页时错一页。

### 4.2 唯一语义(无折叠、无配对追踪,硬件同构)

提升侧:adr/adrp 均产单一自包含语句 `Stmt::Bias{dst, rva}`(adr:精确目标;adrp:页基,lo12=0),rva 按 §4.1 在解码期算出。**不折叠消费偏移**:其后 `add #imm12` 是普通 `Bin`,`ldr [reg,#off]` 是普通 `Load` 各自带偏移,与硬件逐位一致;消费者任意,无需配对识别。

发射侧:`movz/movk xT,#:rva; add xD, xBIAS, xT`;xBIAS 由 thunk 入口 stub 习语恢复(§7.2)。运行期 64 位加法无页边界条件;跨页/±4GiB/lo12 回绕全被 pack-time 常量吸收。发射器禁为 Bias 重发 adrp(§7.4)。`ldr literal` 首批 fail-closed。

oracle:`Bias` 求值 `BIAS_SENTINEL + rva`,参与普通算术与内存地址(与硬件同构;v1 的"禁止算术消费"文字已撤回)。

---

## 5. 重引用与重定位安全

### 5.1 门 1(既有,复用):RELATIVE-into-RX

`fail_closed_on_relative_into_rx`(`elf.rs:160`、`674-734`)拒绝 r_offset 落入密封 RX 页的 RELATIVE。挂钩字节在 RX 内,受保护。

### 5.2 门 2(新增):内标签引用扫描

- DT_RELA 全部 RELATIVE 的 addend(及 GLOB_DAT/JUMP_SLOT 的 st_value):`addend == entry_rva` 放行;`entry_rva < addend < entry_rva+native_len` 命名拒绝(switch 跳转表内标签)。
- 一遍 4 对齐扫描输入 RX:解为 b/bl 且目标落在虚拟化窗内部(非入口)→ 保守拒绝。

### 5.3 挂钩机制

调用路径(直接 bl / PLT-GOT 解析 / dlsym / 取地址)全汇到入口 → 4 字节 `b rel26` 覆盖。`apply_vm_hook_elf`(镜像 `lib.rs:1714-1782`):rva 4 对齐检查;rel26 有符号 26 位字偏移(±128MiB)检查,越界命名报错;窗内填 `brk #0`(`0xD4200000`);dynsym st_value 不改。

### 5.4 门 3(顺序不变量):密封读挂钩后缓冲

现行页提取读 `request.input`(`elf.rs:204-226`,第 218 行)。要求 lift+hook 移到页提取前、页循环改读 patched 缓冲(对齐 PE 侧 `working` 顺序,`lib.rs:373`/`661-663`)。回归测试 B3。

### 5.5 门 4(既有,复用):core 不重放 ELF 重定位

`xl_core.c:1318-1321`:DIR64 重放仅 platform==PE64。thunk 只做 bias+rva 算术。

---

## 6. IR64 数据模型与语义 oracle

### 6.1 宽度模型与 vreg

`ir64.rs`:`Src64::{Reg(u8), Imm(u64)}`、语句级 `W::{X,W}`(W 写零扩)、`Stmt64::{Mov, Bin{op,w}, Load, Store, Bias}`、`Term64::{Ret, Jmp, BrCmp{w}}`;`BinOp/CmpOp/Addr(BaseDisp{i32})` 复用 `ir.rs`。vreg:`0..=30`=x0..x30,**31=SP**(允许:Addr64.base、SP 白名单写语句的 dst、普通读源 `mov xD,sp`);xzr 读作 `Imm(0)`,写丢弃(保留 flags 融合资格)。移位计数按操作宽掩码(`state.rs:440-453` 同型)。oracle `eval_machine64`:入口 `eval_ir64(m,x0,x1)->u64`,SP 初值哨兵 S,步数上限 64_000。

### 6.2 oracle 是等价性唯一真值

发射代码与 oracle 在输入向量上逐点一致;A4b 字级解释器门补结构性盲区(§10)。

### 6.3 NZCV 融合纪律(v3 重写:产生者×谓词精确矩阵)

ARM 事实:`subs/cmp` 直接计算 lhs−rhs(C=NOT borrow=lhs≥ᵤrhs,V=减法溢出)——compare(lhs,rhs) 视图**全十谓词精确**。但取负视图 cmn(a,b)=adds 只有 Z/N 逐位恒等(回绕 a+b ≡ a−(−b)):

- **C 位**:ADDS 的 C=carry-out(a+b);rhs=0 时 C=0,而 compare(a,0) 的 C=(a≥ᵤ0)=1 → **rhs=0 时 hs/lo/hi/ls 分歧**("cmn x0,x1; b.hs" 在运行期 x1=0 时硬件取 lo、模型取 hs——无符号加溢出惯用法,license-check 类目标代码形态);
- **V 位**:rhs=INT_MIN 时 −rhs 回绕仍 INT_MIN;a=1 时硬件 N=1,V=0 → ge(N==V)=假,模型 SGe(1,INT_MIN)=真 → **ge/lt/gt/le 分歧**;
- 立即数形 cmn(cmp 负立即数产物,imm∈1..4095,实测 `b100041f`):rhs=imm≠0 时 C=(a≥ᵤ2⁶⁴−imm)⟺carry(a+imm) 精确;−imm 永非 INT_MIN,V 精确 → **全十谓词精确**;imm=0 形(实测 `b100001f` 汇编器接受)落入 C 位角 → 命名拒绝;
- **自查新增(v2 评审未点名,同类缺陷)**:`ands/tst` 恒置 C=V=0。N/V 派生谓词精确(ge=N==V=(a&b)≥ₛ0=SGe(a&b,0),lt/gt/le 同理);但 **hs=C=0 恒假,而 compare(a&b,0) 的 UGe 恒真 → tst 的 hs/lo/hi/ls 消费必须命名拒绝**。

**融合矩阵(lifter 强制)**:

| flags 产生者 | 比较视图 | 精确谓词 | 其余谓词 |
|---|---|---|---|
| `subs/cmp`(寄存器或 imm) | compare(lhs,rhs) | 全部十个 | — |
| `cmn/adds` **imm**(imm≠0) | compare(lhs, −imm) | 全部十个 | — |
| `cmn/adds` **imm=0** | — | — | **命名拒绝** |
| `cmn/adds` **寄存器** | compare(lhs, −rhs) | **仅 eq/ne** | hs/lo/hi/ls(rhs=0 C 角)、ge/lt/gt/le(rhs=INT_MIN V 角)→ **命名拒绝** |
| `ands/tst`(AndCmp 物化 a&b) | compare(a&b, 0) | eq/ne/ge/lt/gt/le | hs/lo/hi/ls(C 恒 0 vs 恒 1)→ **命名拒绝** |

b.cond 要求产生者紧邻(间隔任何语句/Skip/多步分解即清除;移植 `lift.rs:2022-2055` 回归);cbz/cbnz/tbz/tbnz 不读 flags,独立 Term。`adds/subs` 值结果照常写。stage-2 可为寄存器形 cmn 建精确 carry/overflow 谓词模型(carry ⟺ (a+b)<ᵤa),首批拒绝。

---

## 7. 发射器:superop_aarch64(v3 修正 prologue 算术)

### 7.1 基座

泛化 `stub_aarch64.rs:151-251` 的 `Asm/Fixup`(Branch/BranchCond/CompBranch/Adr/TestBranch + 范围检查)为共享模块;新增 `FixupKind::Adrp` 仅 stub 自用。

### 7.2 thunk 布局与寄存器约定(v3 修正)

```
; 入口: sp = C (caller 的 sp; LR = 返回地址——hook 是直接 b, 不动 LR;
;        guest 的"入口 SP" ≡ C: 正偏移读 [C,#k] 即调用方传入栈参数)
<guest thunk i>
  sub  sp, sp, #(SAVES+F)          ; SAVES = 16·k (k=保存对数, x29/x30 恒存, k∈1..6)
  stp  x19, x20, [sp]              ; 各保存对落在保留区底部, 固定偏移 0..SAVES-16
  ...                              ;   (imm7 偏移 ≤ 80, 恒可编码, 与 F 无关)
  stp  x29, x30, [sp, #SAVES-16]
  add  x15, sp, #(SAVES+F)         ; x15 = GSP = C   (与 sub 同一 imm12 值)
  adr  xT, meta ; ldr wT2,[xT,#META_SELF_RVA] ; sub x17, xT, wT2   ; x17 = BIAS
  <entry shuffle: id_map → entry_map, 仅 x0..x7 活参>
  b    L_entry_block
<每块: junk + 调度语句 + MBA>
<terminators: 块间 shuffle + b/b.cond/cbz/tbz>
L_epilogue:
  mov  x0, <map[guest_x0]>         ; 先取结果——可能驻留在待恢复的 callee-saved 物理寄存器
  ldp  x19, x20, [sp]              ; 固定偏移恢复
  ...
  ldp  x29, x30, [sp, #SAVES-16]
  add  sp, sp, #(SAVES+F)          ; sp = C
  ret                              ; 返回 LR (caller 返回地址, 从未被动过)
```

- **核心不变量(v3 修正)**:`x15 ≡ C ≡ guest 入口 SP`——先一次性 `sub #(SAVES+F)`,保存对放保留区**底部**(固定小偏移),再 `add x15,sp,#(SAVES+F)`。v2 的"先压两对 stp 再 sub 再 mov x15,sp"使 x15=C−32−F 且正偏移落保留区,已废弃。
- **保留区划分**:`[C−SAVES−F, C−SAVES)` = 保存对;`[C−F, C)` = guest 下探区(互不重叠);guest 下探幅度 ≤ F 由 pack-time 静态 SP 轨迹仿真强制。
- **保留寄存器**:`TMP=x16`、`BIAS=x17`、`GSP=x15`、`x18` 永不分配、SP 排除;分配池 = x0..x14 + x19..x28(+x29 若已存)≈26。live 超池命名报错(镜像 `superop.rs:264-272`)。
- AAPCS64 免 shuffle 面:x0-x7 与 vreg 同位(`superop.rs:80-84` 同型)。FP/SIMD 零触碰。epilogue golden 锁 post-index ldp 非零、`sub/add sp,#(SAVES+F)` 成对同值。

### 7.3 混淆要素

| x86 机制 | aarch64 对应 |
|---|---|
| `block_stream` seed 流(`superop.rs:557-563`) | 原样 |
| junk `xor tmp,imm; xor tmp,imm`(`:565-569`) | 成对 `add x16,x16,#k; sub x16,x16,#k`(k∈[0,4095] 取自流;imm12 编码器 `add_x_imm/sub_x_imm` 在 `stub_aarch64.rs:78-89` 实存;净零、必可编码);可选族 `eor x16,x16,#mask` 仅当 mask 过 N:immr:imms 可编码性测试(实测 `#0xff/#0xfff` 可、`#0x123/#0x12345` 拒) |
| 永不取 junk 边(`:222-240`) | `eor x16,x16,x16; b.ne L_junk`(寄存器形恒可编码) |
| MBA 家族(`mba.rs:38-70`) | 家族选择共享;`AddLea` 替换为 `AddOrAnd`(a+b==(a|b)+(a&b),u64 回绕恒等) |
| 语句调度(`:361-387`) | `stmt_regs` 向 Stmt64 泛化 |
| trace_diverge | 首批不实现 |

### 7.4 立即数物化纪律

bitmask 立即数与 Bias 常量一律 movz/movk 物化(§0.3 四基);禁为 Bias 重发 adrp;编码不了的形态命名报错。

### 7.5 guest-SP 发射策略(v3 重写,不变量以 §7.2 布局为准)

- `map[31]`(guest SP)固定映射 x15(GSP),永不进分配池;
- guest [sp,#d] → [x15,#d];imm 范围由指令形态天然限定(无符号 imm12×size ≤32KB;ldp/stp imm7 −512..504);
- guest SP 更新(add/sub imm、前后索引分解)= x15 上的普通 Bin;SP 白名单只含 imm 形 → **发射后无动态 SP 写**,pack-time 可静态仿真全窗 SP 轨迹,得下探幅度 D;
- **`GUEST_FRAME`(F)与 cap(v3 修正)**:F = 16 对齐(max(D,0)+8);**总检查 `SAVES+F ≤ 4080`**(4080 = ≤4095 内最大 16 倍数,sub/add imm12 可编码;F 上限随实际 SAVES 收缩,SAVES=16 时 F≤4064)。`add/sub sp,sp,#imm<<12` 单条即可下探 0xFFF000——cap 靠自身成立而非 imm12 推导,越限(含深下探)一律命名拒绝 `"vm-export {name}: guest stack frame {n} exceeds the emitter cap (SAVES+F ≤ 4080)"`。v2 的"上限 4096(sub imm12)"表述作废(4096 不可编码、且 <<12 变体使该理由不充分)。
- **正偏移正确性(v3 修复)**:x15 ≡ C,guest 对 [entry_sp,#k] 的访问直达真实调用方栈(传入栈参数),与硬件一致;v2 布局下 x15=C−32−F 导致正偏移落入保留区(差 32+F),已废弃。
- **契约固化(v3 修正)**:oracle 哨兵 SP 记 S;A4b 字级解释器初始架构 sp = **S**(直接相等,v2 的 "+GUEST_FRAME" 作废)——发射码自算 `x15 = sp − (SAVES+F) + (SAVES+F) = S`,任何 prologue/cap/映射错误在该门直接暴露;
- 结构断言:`sub/add sp,#(SAVES+F)` 成对同值;x15 仅被 prologue 初始化与映射的 SP 语句触碰;保存对偏移 < SAVES。

---

## 8. 与协议平台字节及打包选择的接线

### 8.1 协议层零改动

`platform=PLATFORM_ELF64_AARCH64(2)`(`elf.rs:256-259`),平台字节入每 region AAD(`protocol lib.rs:184-197`、`xl_core.c:504-511`)→ 旧 core/CLI fail-closed。thunk 与 stub 同栖 appended PT_LOAD 明文区(PE 侧 `stub.rs:1529-1540` 同地位)。`XL_MAX_REGION=16384` 不变。

### 8.2 elf.rs 门替换 + profile 门补齐

machine==Aarch64 进新流水线;x86_64 ELF 保持命名拒绝(文案"requires the SysV x86-64 lift");补上与 `lib.rs:425-427` 对等的 `vm-export requires standard or max` 门。

### 8.3 stub 扩展

`emit_elf_stub_aarch64` 增 guest 参数;thunk 字流在 shim 后、meta 前依序 append;`ElfStub` 增 `guest_thunk_offs: Vec<u32>`(镜像 `stub.rs:67-68`);数量守卫照抄 `lib.rs:642-649`。thunk 经直接 b 进入,无需 bti;golden 测试锁 prologue/epilogue。

### 8.4 选择器:Elf64 flavor

`resolve_elf(&Elf64,…)`:dynsym/symtab(`elf.rs` `symtab_functions`)给 name/rva/st_size;`fn_{:#x}`、`--select-rva <rva>:<len>` 沿用;错误文案模板照搬 `selection.rs:151-158`。禁入 = `forbidden_vm_rule`(`lift.rs:193-212`)+ **ifunc 禁入**:入口 rva 等于任一 IRELAITVE addend 目标或落在 resolver carve-out 页(`elf.rs:99-106` 枚举,carve-out 在 `elf.rs:500-524`)→ 命名拒绝,理由:"IFUNC resolver 在 ld.so 重定位阶段执行,早于 INIT_ARRAY 解包 stub;pre-init 窗内挂钩入口与 trap 填充可见性未论证"。

### 8.5 报告与覆盖

`PackReport.vm_functions` 真实化(现行写死 0,`elf.rs:596`);coverage 桶/strict-coverage 对齐 PE(`lib.rs:571-597`);inspect 沿用。

---

## 9. Fail-closed 边界汇总(实现对照清单)

十四条 + v3 增补:寄存器形 cmn/adds+有序谓词、tst/ands+hs/lo/hi/ls、cmn imm=0(§6.3);sf=0 且移位立即数>31 的 UNDEFINED 编码(§3.1#2/#3);GUEST_FRAME cap 以 `SAVES+F ≤ 4080` 计(§7.5);ifunc 禁入(§8.4);解码 opcode 全掩码先行(§2.1)。每条配命名测试。

---

## 10. 验收标准

**A. 宿主单元/差分(本 Windows x64 宿主可执行)**

1. A1 解码器 golden:§3.1 每类以 §0.3 实测字为期望;负例单列:adr/b 撞码(0x10000000 不得解为 b)、**W 形 imm6=32(0x0B027C20 的 #31 为正例上界)**、bitmask UNDEF 形。
2. A2 oracle 差分:宽度混合、**cmn 角向量(rhs=0、rhs=INT_MIN、a=1;cmn imm≠0 全谓词)**、移位计数 0/31/32/63、tbz W/X 位号边界(b5)。
3. A3 fail-closed 命名测试:§9 逐条(含 §6.3 矩阵的每个拒绝格:`cmn x0,x1;b.hs`、`tst x0,x1;b.hs`、`cmn x0,#0`、`adds x0,x1,x2;b.ge`)。
4. A4(量化):re-decode→re-lift→oracle 等价门,每指令类 ≥32 seed、每 fixture ≥32 seed。
5. **A4b(字级解释器门)**:测试态 Rust 解释器直接执行 re-decode 后的发射字流(实现 §3.1 白名单类执行语义),**初始架构 sp = 哨兵 S**(v3 契约),比对全架构状态(x0..x28+触及内存)与 `eval_machine64`;专门含 ldp/stp 前后索引 + [sp,#k] 读写 + cmn/b.cond + tst/b.eq 的栈形函数。宿主可跑,直接暴露 x15/SAVES+F/映射错误。
6. A5 编码 golden:thunk prologue/epilogue 字、保存对成对、`sub/add sp,#(SAVES+F)` 成对同值、post-index ldp 非零。
7. A6 解码器 fuzz:SHA 派生字流 ≥10⁶ 字不 panic、错误可命名、**UNDEFINED 编码不作为合法指令提升**(v3)。
8. A7 MBA u64 恒等式(含 AddOrAnd)。

**B. 打包级(宿主;NDK core 在位)**

1. B1 NDK fixture `.so`(叶函数覆盖 §3.1 全类,含栈形函数)→ `pack_elf --vm-export` 成功;报告真实。
2. B2:NDK llvm-objdump(`E:/opt/android-sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-objdump.exe`,实测在位)脚本化字级比对:窗 = `b rel26`+`brk #0`、thunk 偏移一致。
3. B3 密封顺序回归(§5.4)。
4. B4 内标签门正反 fixture。
5. B5 基线回归:vm 48 + pack 101 + formats 28 全绿。

**C. OS 级(环境受限,如实申报)**

1. C1 arm64 OS 加载+调用虚拟化导出(含栈形函数):需 arm64 镜像或真机;当前两台在线模拟器均 x86_64,**not run,不以替代冒充**。A4b 已覆盖宿主语义面,C1 留真机硅验证。
2. C2 qemu-user/ndk_translation 仅参考,不作门。

---

## 11. 风险与未决

1. 解码器字段拼接工作量(§0.3 已给全部 golden 值)。
2. **flags 融合矩阵是 v3 最大语义风险面**:cmn/tst 的拒绝格必须在 lifter 强制(A3 逐格测试),stage-2 若建 carry/overflow 精确谓词(carry ⟺ (a+b)<ᵤa)再放行。
3. W32 混合宽度静默错码:A2/A4b 专测。
4. movn 未入首批 → mixed_native(覆盖面问题,stage-2)。
5. profile 门补齐属文案级行为变化。
6. ifunc 禁入保守(未论证 pre-init 窗,不冒险)。
7. A4b 字级解释器是测试态组件(≈oracle 语义白名单重接线),同时加固 reg-map/SP/常量三类风险。
8. 实现全在 worktree,不 commit;本文档在 main 检出 `/out`(git-ignored,commit 8d40073)。

---

## 附:评审修订记录

**v1 → v2**(十条:b.cond cond 集、movk 四基、LSL 别名、b 单操作码、junk eor imm12、adrp 折叠矛盾、cmn 变换、SP 发射策略+验收盲区、寄存器 add 双形、ifunc 禁入、A4 量化/B2 工具——v2 评审已全部独立复核通过)。

**v2 → v3**:

| 意见 | 修正 |
|---|---|
| §7.5 GSP/GUEST_FRAME 算术矛盾(x15=C−32−F,正偏移差 32+F) | §7.2 prologue 重构:先 `sub #(SAVES+F)`、保存对置保留区底部(固定偏移)、`add x15,sp,#(SAVES+F)` ⇒ **x15 ≡ C ≡ guest 入口 SP**;保留区划分与互不重叠论证入 §7.2;A4b 契约改为"初始 sp = 哨兵 S 直接相等"(§7.5/§10) |
| §6.3 "cmn 十谓词全精确无降级"为假(rhs=0 C 位、rhs=INT_MIN V 位) | §6.3 重写为**产生者×谓词矩阵**:subs/cmp 全精确;cmn imm≠0 全精确;cmn imm=0 拒;**cmn/adds 寄存器形仅 eq/ne,有序谓词命名拒绝**;并自查补上 **tst/ands 的 hs/lo/hi/ls 拒绝**(ANDS 恒 C=0 vs compare(·,0) 恒 C=1,同类缺陷);A2 角向量(rhs=0/INT_MIN/a=1)与 A3 逐格测试入 §10 |
| §3.1#2/#3 imm6 未按 sf 封顶(W 形 ≥32 UNDEFINED) | §3.1#2/#3 增封顶规则;实测 #31 合法(0x0B027C20)/#32 拒绝入 §0.3;A1 负例、A6 "UNDEFINED 不提升"断言 |
| §7.5 cap "4096(sub imm12)" 数值理由不合 | §7.5 改 **`SAVES+F ≤ 4080`**(≤4095 内最大 16 倍数;F 随 SAVES 收缩);<<12 深下探命中 cap 即拒,cap 自身成立不依赖 imm12 推导 |
| 行号漂移 ifunc_symbol_values 104-106 | §0.2/§8.4 引用改 `elf.rs:99-106` |
