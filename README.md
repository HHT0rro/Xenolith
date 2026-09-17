# Xenolith

<p align="center">
  <img src="assets/icon.png" width="220" alt="Xenolith 图标:可执行文件被封入合拢中的琥珀色装甲壳" />
</p>

开源原生代码加壳器:输入 Windows x86_64 PE64 或 Linux AMD64 ELF64 二进制,输出带认证加密信封与自举 stub 的受保护映像。不需要源码,不需要重编译。

Xenolith 最重要的设计决定是一个否定:**不做共享指令集虚拟机**。VMProtect 与 Themida 的路线是 "handler 表 + guest 字节码 + 中央分发器",[NoVmp](https://github.com/can1357/NoVmp) 已经证明这类结构可以在没有壳源码的前提下被静态提升为 IR。Xenolith 把"虚拟化"实现为一个打包期编译器:选定函数被提升为内部 IR,每个基本块编译成一份仅存在于本次构建的位置无关原生代码(superoperator),块间用直接 `jmp`/`jcc` 连接。镜像里没有 guest 字节码,没有可复用的 opcode 表,没有 `l_gloop` 式分发循环。代价是保护成本随函数的块数增长;收益是攻击者无法靠"学会一次 VM"把成本摊销到所有样本上——每次打包都是一个新程序。

- 仓库:<https://github.com/HHT0rro/Xenolith>
- 语言:Rust(workspace,9 个 crate)+ 一个 freestanding C 核心(`xl_core.c`)
- 协议:**GPL-3.0-or-later + Stub Exception**(见[开源协议](#开源协议)与 [LICENSE](LICENSE))
- 产品契约:[docs/SUPPORT.md](docs/SUPPORT.md) · 威胁模型:[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)

## 它是什么,它不是什么

**是**:一个独立的二进制加壳器。`pack` 吃进 PE/ELF,输出 `.xl.dll` / `.xl.exe` / `.xl.so` / `.xl.elf`。真正在目标系统上运行的对象是注入的 PIC boot stub 加上 freestanding 的 `xl_core`(无 CRT、无导入、无全局变量)。`--vm-export` 把你指定的命名导出虚拟化为逐块唯一 PIC;CRT 代码和 `DllMain` 永远保持原生。

**不是**:全 `.text` 虚拟化,也不是 VMProtect 式共享 ISA 的克隆。强度主张只存在于 CI 门表和 docs/ 里,不写在营销文案里。默认档(W1/W2)的强度大约在 OLLVM 层级:变异后的 x64 仍然可读,CFG 与原函数同构。质变从 W3(`--trace-diverge`)开始:同一输入、同一返回值、因进程而异的指令流,朴素 trace 对齐失效。不可逆性、商业壳对等、"无限 AI 攻击失败"从来不是主张。

**诚实的边界**(白盒威胁模型 W0):源码是 GPL 公开的。攻击者拥有本仓库、专业逆向工具和无限的 AI 协助,可以自行打包训练样本。"自定义 ISA 不在 LLM 训练数据里"在这个前提下不是安全主张,项目文档从不这样声称。W0 的真实目标是:不存在一个通用的 `xenolith-devirt`,拿公开源码加一个打包产物就能把所有受保护函数恢复成稳定 ISA——成本必须随受保护函数增长,而不是随"学会 VM 一次"增长。

不支持的输入和未接线的开关一律 **fail closed**:报错、拒绝打包,不静默降级。CLI、TUI、项目文件 schema 只列出真正接了线的选项。

## 快速开始

```
cargo build --release -p xenolith-cli
cargo build -p license-toy --release

cargo run --release -p xenolith-cli -- pack target/release/license_toy.dll -o target/release/license_toy.xl.dll --profile max --vm-export check_license

cargo run --release -p xenolith-cli -- inspect target/release/license_toy.xl.dll --json
```

打包后的 DLL 导出同名 `check_license`,函数体已经变成 stub 内部的逐块 PIC。要验证 trampoline 与语义,跑强度门脚本 `scripts/ci-gates.ps1`(与 CI 相同)。

## 总体架构

| Crate | 职责 |
| --- | --- |
| `xenolith-formats` | fail-closed 的 PE64 + ELF64 AMD64 解析器 |
| `xenolith-crypto` | MBA 密钥分片、ChaCha20-Poly1305 AEAD、页 MAC、API 哈希 |
| `xenolith-protocol` | EnvelopeV2(`XLV2`)磁盘布局、AAD 绑定、fail-closed 解析(拒绝旧 `NSEN`/`NSV2`) |
| `xenolith-pack` | lift、superoperator 流水线、EnvelopeV2 写入、PIC boot stub 与 `xl_core` 嵌入 |
| `xenolith-vm` | stub 密钥混合 VM、pack 内部 IR、`eval_ir` 语义 oracle、superop/MBA 代码生成 |
| `xenolith-guard` | 打包期记录的反调试 / 反 dump **策略**;syscall 在 PIC stub 里 |
| `xenolith-loader` | 宿主侧信封类型与测试模拟器。**不注入**,不代表 OS 加载真相 |
| `xenolith-runtime` | rustc cdylib 实验(不注入)。真正注入的核心是 `core/xl_core.c` |
| `xenolith-cli` | 命令行、项目文件、TUI(唯一带 TUI 依赖的 crate) |

信任边界:

```
输入二进制 → packer(GPL,攻击者已知)
    ↓
磁盘:密文页 + EnvelopeV2 + PIC stub     ← 磁盘可执行页被 0xCC/0x90 填充
    ↓ 系统加载器(受信,ASLR/DEP/W^X/CFG 全保留)
进程内映射 → PIC stub 自举 → xl_core 认证解封(RW→RX)→ IAT 回填 → stolen OEP 恢复
    ↓
可执行页 + 原始 IAT 槽位就绪 → 跳转原入口
```

`xenolith-loader` 在这条边界之外:模拟器跑绿不构成"打包文件在 Windows/Linux 上加载成功"的证据。OS 加载测试在 `crates/xenolith-pack/tests/` 里真实执行。

## 技术细节

### 1. 磁盘格式:EnvelopeV2(`XLV2`)

信封是生产级磁盘契约,不是混淆格式:

```
magic "XLV2" | version u16 | platform u8 | profile u8 | flags u32 | region_count u32   ← 16 字节前缀
mba[96]      ← 8 个 (mul, add, xor_mask) 肢体,主密钥的分片形式
opcode_seed[16] | api_salt[16] | opcode_map[8]
stolen bytes | key-mix program | policy u32
regions[]    ← 每个 region:index/rva/len/nonce[12]/ciphertext/tag[16]
imports[]    ← 哈希导入记录:name/dll 可为密封形式(nonce+tag+ct)
keep[] | relocs[] | lazy[]
```

- 每页一个 region,独立 nonce 和 Poly1305 tag。AAD 绑定 `platform/profile/flags/region index/rva/len/policy/重定位数`,密文无法跨页拼接或换位。
- 解析器 fail closed:拒绝 v1 `NSEN` 与遗留 `NSV2`,不提供兼容解码;所有来自输入的 count 在分配前先对剩余字节数做下界校验(fuzz 驱动的 TASK-037 输入安全修复)。
- 磁盘上的可执行页是 `0xCC` 陷阱字节,原文只存在于 AEAD 密文里。ELF 例外:`e_entry` 前 64 字节保持原样,因为 glibc 会解码入口点附近的指令窗口,失败则跳过整个 init 阶段(实测 2.39);这 64 字节是 `_start` 序言,不是受保护逻辑。

### 2. 密钥体系(`xenolith-crypto`)

32 字节主密钥从不以连续形态出现在镜像里。打包期拆成 `MbaKeyShare`:8 个肢体,每个肢体存 `(mul, add, xor_mask)` 三元组,满足 `xor_mask[i] = word[i] · mul[i] + add[i] (mod 2^32)`,`mul` 强制为奇数。运行时用牛顿迭代 4 轮收敛求模逆重建(`mul_inverse_odd`),重建后立即 `zeroize`。

运行时密钥 = 重建密钥 ⊕ image measurement ⊕ 16 字节二进制域常量。measurement 是对整个镜像的 SHA-256(`"XLIM\x01v1"` 域):镜像改一个字节 → measurement 变 → 运行时密钥错 → AEAD open 失败 → 加载失败。没有 `SHA-256(identity || ASCII 标签)` 这类可搜索的密钥包装。

stub 侧的密钥重建走 key-mix VM:操作码映射用 SHA-256(`"XLVMOP\x01" || seed`)从 256 个槽位中洗出 8 个不重复操作码,每个 build 不同。stub 执行一段 `load_imm`/`mix_key` 程序走完重建流程,内存转储里看到的是 VM 指令序列而不是线性解密循环。这个 VM 是 **stub 解包机器**,与用户代码虚拟化不共享 opcode 表——WHITEBOX.md 明文禁止两者共用。

两套加密分工明确:磁盘与防篡改用 ChaCha20-Poly1305(RustCrypto `chacha20poly1305`);解封后的内存页流用 `xor_page` XOR 流(`key[i%32] ^ nonce16视图 ^ i·0x9d ^ i>>8`),设计目标是几百字节的 PIC stub 不带 ChaCha 也能复现。API 导入名哈希用加盐 SHA-256(`"XLAPI\x01"` 域)。

### 3. 注入运行时(PIC stub + `xl_core.c`)

启动流程(Windows PE):

1. 系统 `LoadLibrary` 加载映像,入口指向 PIC stub(原 OEP 字节已被 stolen)。
2. stub 遍历 PEB 定位 kernel32,解析 `LoadLibrary` / `GetProcAddress` / `VirtualProtect`,连同镜像基址、信封位置、measurement 填进 `XlHostCtx`。
3. `xl_core_activate` 逐 region 做 ChaCha20-Poly1305 认证解密,页面临时 RW 写入后翻回 RX(无长期 RWX);落在受保护页内的 DIR64 重定位在解密后重放。
4. 哈希导入解析:stub 用信封里的哈希记录还原 DLL/函数名,解析后把 VA **写回原始 IAT 槽位**,保证 CRT `DllMain` 正常运行。
5. keyed FNV-1a 页摘要校验(G-TAMPER):翻转任何一个已映射字节,`LoadLibrary` 直接失败。
6. 恢复 stolen 入口字节,返回;stub 跳转原入口。ELF 路线对应为追加 R+X `PT_LOAD` 并重定向 `INIT_ARRAY[0]`,`ld.so` 仍然是加载器。

`xl_core.c` 是 freestanding C:无 CRT、无导入、无静态存储、无字符串字面量、自带 `memcpy`/`memset`(防止编译器 loop-idiom 识别降级为 CRT 调用),ChaCha20 quarter-round 手写。宿主 API 全部经 `XlHostCtx` 注入,不出现导入表项。

dump 与调试对策(现状,不夸大):

- 内存 section table 垃圾化 + `SizeOfImage` 谎报,导出的转储不可直接作为 PE 重载;MZ 头与导出目录保留,`GetProcAddress` 不受影响。
- `max` 档 stub 探针:PEB.BeingDebugged、`NtSetInformationThread(HideFromDebugger)`、`NtQueryInformationProcess(ProcessDebugPort / ProcessDebugObjectHandle / ProcessDebugFlags)`、NtQuery 前 INT3。CI 不附加调试器、不跑 Frida、不测 RPM。
- **已知残余**:解包后可执行页保持明文(C2 再加密未接线,因为加密 hello_dll 的 `.text` 页会破坏 `hello_add`);Scylla 式 IAT 写断点在解包窗口内仍然成立;暂停的进程可以读当前页。这些写在 docs 里,不假装不存在。

兼容性不是靠关安全特性换来的:ASLR/`DYNAMIC_BASE`/`HIGH_ENTROPY_VA` 与重定位目录保留;DEP/NX、W^X、Windows CFG/CET、Linux RELRO/PIE 全部保持。TLS 目录保留且首个 TLS callback 被包装,保证解包先于 CRT TLS;有 TLS callback 的映像保留磁盘导入目录(loader lock 下 `LoadLibraryA` 不安全)。异常处理在两侧都合成展开元数据:PE 侧 XDATA + 重定位 `.pdata` 携带 stub 的 RUNTIME_FUNCTION,ELF 侧追加 `.eh_frame` + `PT_GNU_EH_FRAME`。C++ 异常、`setjmp/longjmp`、varargs、8 字节结构体返回、尾调用都在**打包后的映像**上验证过(`packed_eh_matrix` / `packed_elf_eh_matrix`)。

### 4. 选择性虚拟化(lift → IR → SuperOp)

对每个选定的导出函数:

```
导出机器码
  → iced-x86 CFG lift(cmp+jcc 融合为 BrCmp;mem/call/RIP 相对寻址/SEH/未融合 flags → fail closed)
  → pack 内部 IR(绝不写入镜像)
  → 每个基本块一个 SuperOp
  → 逐块独立 PIC 代码生成(调度、MBA 重写、seed 垃圾、逐块寄存器分配)
  → thunk 保存非易失 GPR 后跳入首块;块间直接 jmp/jcc
  → 原导出改写为 jmp rel32 / 重定向导出目录 RVA
```

- **IR**:16 个虚拟寄存器的块级 IR,语句覆盖整数运算、内存、直接调用、SSE/SSE2 标量浮点、128 位向量、RMW 原子(`cmpxchg/xadd/xchg`)。`eval_ir` 是语义 oracle:`MachineState` 解释 IR 得到的 EAX,必须与生成的 PIC 在相同输入下一致。spill 被禁止——放不进寄存器的块直接让打包失败,而不是引入栈槽。
- **代码生成**:每个基本块独立做寄存器分配(12 寄存器池,即除 RAX/RCX/RDX/RSP 外的全部 GPR;r11 兼作 shuffle/MBA 临时),语句调度顺序、垃圾立即数、不透明假边全部由 16 字节 seed 派生的流控制。两个 seed 打同一个函数,助记符与寄存器直方图不塌缩到同一形态(G-WB-DIVERSE)。
- **MBA 重写**:发射期应用混合布尔算术恒等式,`pick_family` 按 seed 选择:`a+b → (a^b)+2(a&b)`、`a+b → lea`、`a-b → a+(~b+1)`、`a^b → (a|b)-(a&b)`、`a&b → (a+b)-(a|b)`。乘法与移位暂不重写,原样发射。
- **选择面**:命名导出、`--select-rva RVA:LEN`、`--select-function`(经导出表 / COFF 符号 / PE `.pdata` unwind 边界解析 `fn_0x...`)、显式 `--select-all`。lift 窗口当前 256 字节(`MAX_LIFT_BYTES`);64 位数据、超过两个参数、间接调用、函数指针、递归、跳转表仍 fail closed,配 `--allow-native-fallback` 时如实报告为 `mixed_native`,绝不计入受保护函数。`--strict-coverage` 则要求全部转换成功否则整体失败。
- **JNI 形态**:`JNI_OnLoad` / `Java_*` / `qp_r1_*` 在存在性检查之前就被拒绝虚拟化——JVM 按精确名字调用这些入口,不能经过 thunk;这类映像强制保留磁盘导入目录。`.jsms`/`.jsmk`/`.jsmd` 作为输入数据节按字节原样保留。

### 5. W3:拒绝 trace 对齐(`--trace-diverge`)

每个 superoperator 块发射两条语义等价的路径,由进程唯一硬币选择:

```
r11 = TEB            ; gs:[0x30]
r10 = PEB.ProcessHeap ; gs:[0x60]+0x18
r11 ^= r10
r11 ^= RSP
ZF = r11 移位后的某一位(seed 决定)
```

禁用 RDTSC 作硬币(计时是 G-BEH 风险,且可被 tracer 钉住)。TEB、用户堆、线程栈在系统 ASLR 下即使映像基址不变也在移动:两个普通进程吃同一输入,返回同一个 `eax`(由 `eval_ir` 保证),指令流哈希可以不同(G-WB-TRACE)。残余:钉住堆与栈的调试器、或复制整个地址空间的克隆,仍能对齐;逐块符号执行依然可行,成本随块数增长。W3 的主张是"正常负载下进程唯一的指令流",不是"不可对齐"。

### 6. ELF 路线

Linux 打包不接管加载器:追加一个 R+X `PT_LOAD`(迁移后的 PHDR 表 + PIC stub + `xl_core` + EnvelopeV2),把 `INIT_ARRAY[0]` 重定向到 stub;`ld.so` 照常完成重定位与符号解析,PIE/RELRO/GOT-PLT 不动。可执行 `PT_LOAD` 的文件字节 `0x90` 填充后密封进信封。已在 WSL Ubuntu 24.04 验证:打包后的 `hello-elf` 正常输出,`libhello-elf.so` 可 `dlopen`/`dlclose`;IFUNC resolver 保持原生并支持,符号版本(`DT_VERNEED/VERDEF`)保留且 `dlvsym` 验证通过。IFUNC 导入、TLS 描述符、local-exec TPOFF32、copy 重定位、`PT_TLS`、静态链接 fail closed 直到 stage 5。ELF 符号选择本版本只报告,同样要求 `--allow-native-fallback`。

### 7. 工程面

- **CI**:Windows + Linux 矩阵跑同一套测试命令;夜间定时任务跑有界 libFuzzer(pe/elf/envelope/inspect 四个目标)与 soak;回归 fixture 冻结在 `tests/corpus/manifest.json`。缺失样例、未执行的子进程、缺失工具一律算失败,不算跳过。
- **发布**:`scripts/build-exe.ps1 -ReleaseBundle` 产出带 SBOM、哈希、来源与预算门(性能基准 `benches/g8_perf.rs` 对比发布预算)的 bundle。
- **压测**:900 秒持续打包/加载压力采样(`resilience` 测试)。
- release profile:`panic = "abort"`、`codegen-units = 1`、符号剥离。

## 强度门(CI)

这是全部强度主张,别的说法不算数。细节见 [docs/TECHNIQUES.md](docs/TECHNIQUES.md) 与 [docs/POLICY.md](docs/POLICY.md)。

| ID | 攻击 | 通过标准 |
| --- | --- | --- |
| G-UPX | `upx -d` | 失败(装有 upx 时;未装则 CI 跳过该步) |
| G-SIG | UPX/Themida/VMP 节名与 `UPX!`/`.packed` 字符串 | 尽力扫描不命中 |
| G-KEY | 连续 32 字节主密钥 + 可搜索 KDF | 信封保持闭合 |
| G-IAT | 磁盘导入目录 | `standard`/`max` 下 RVA 为 0;TLS 回调 / JNI 映像按契约保留磁盘目录(loader lock 下 `LoadLibraryA` 不安全),其余保留即失败;PIC stub 解析后回写原 IAT 槽位 |
| G-OEP | 入口追踪 | 打包入口是 PIC stub,不是原 OEP |
| G-DUMP | MiniDump / 全映像转储 | **部分通过**:内存节表垃圾 + `SizeOfImage` 谎报;可执行页解包后仍明文(C2 未接线) |
| G-TAMPER | 翻转已映射页一个字节 | `LoadLibrary` fail closed;keyed FNV 页摘要 |
| G-BEH | 导出语义 | `hello_add(3,4)=7`;`check_license` 与 `eval_ir` 一致 |
| G-POLY | 同输入打包两次 | 输出文件不同 |
| G-WB-NOLIFT | GuestMap 解码打包后的 PIC | 失败;stub 里没有 guest `movzx/inc/cmp/je` 四元组 |
| G-WB-DIVERSE | 两个 seed | 助记符/寄存器直方图不塌缩 |
| G-WB-TRACE | `--trace-diverge`,双进程 | 同 `eax`;指令流哈希**可以**不同 |
| G-WB-META | 两次打包 | 无跨包可复用的 opcode→语义表 |
| G-VM | 选定导出 | trampoline 进入 stub PIC |

## 与其他加壳器的思路对比

先给一张总表,再逐个展开。对比对象的选择有讲究:UPX 是开源加壳器的事实基线,OLLVM 系是开源混淆的主流形态,VMProtect/Themida 是闭源商业参照系(Xenolith 文档里明确把它们列为"不要克隆的架构")。

| | 变换时机 | 需要源码 | 核心结构 | 公开的自动脱壳情况 | 许可 |
| --- | --- | --- | --- | --- | --- |
| UPX | 链接后 | 否 | 压缩 + 小恢复 stub | `upx -d` 官方支持,签名稳定 | GPL-2.0+ 产物例外 |
| OLLVM 系 | 编译期 | 是 | IR 级替换/扁平化/虚假控制流 | 符号执行类工具可复原扁平化(公开研究多次演示) | 开源,各分支许可不同 |
| Tigress | 编译期(源到源) | 是(C) | 函数虚拟化、数据编码、谓词 | 无通用脱壳;研究工具众多 | 研究用途许可,非 OSI 开源 |
| VMProtect | 链接后 | 否 | 共享 handler 表 + guest 字节码 + VIP/VSP | NoVmp 静态提升 3.0–3.5 到 VTIL | 商业闭源 |
| Themida | 链接后 | 否 | 多 VM 骨架 + 每 build 变异,仍是 handler 表 + 字节码 | "找 dispatcher、分类 handler"循环成熟 | 商业闭源 |
| **Xenolith** | 链接后 | 否 | 逐块唯一 PIC superoperator,无 dispatcher/无字节码 | 目标是让泛化 lifter 不可复用(W0),非不可逆 | GPL-3.0+ Stub Exception |

### UPX:压缩壳解决的是体积,不是分析成本

UPX 压缩可执行段,配一个小型恢复 stub,加载时解压、还原、跳回 OEP。这个目标直接决定了它的两个性质:官方工具 `upx -d` 能解开标准构建——它本来就是为了可逆分发设计的;`UPX0`/`UPX1`/`UPX!` 节名与 stub 特征是稳定签名。许可上 UPX 用 GPL-2.0-or-later 加一条产物例外,允许闭源商业软件分发压缩结果——Xenolith 的 Stub Exception 是同一模式。

分叉点:Xenolith 不压缩、不追求可逆。每个 build 随机节名、变异 stub;G-UPX 门直接断言 `upx -d` 失败,G-SIG 断言无已知壳家族签名。磁盘载荷是 ChaCha20-Poly1305 密文加 `0xCC` 陷阱页,不是压缩流。两者的共同点在工程形态:都是链接后的独立二进制变换器,都不碰源码。

### OLLVM 系:编译期混淆,以及 Xenolith 为什么不做扁平化

obfuscator-llvm 及其延续(Hikari、Pluto、Arkari 等)在 LLVM IR 上做指令替换(SUB)、虚假控制流(BCF)、控制流扁平化(FLA)。它们需要源码与重编译,保护的是整个编译单元。

控制流扁平化把函数改写成"状态变量 + 分发循环"。这恰是 Xenolith 明令禁止的结构:一个中央 dispatcher 是白盒攻击者最好的路标,它把"理解函数"降维成"跟踪一个状态变量",公开研究已多次演示用符号执行复原扁平化代码。Xenolith 的立场写在 [docs/WHITEBOX.md](docs/WHITEBOX.md) 的 Forbidden design 一节:共享 handler 表、全局 guest 字节码、中央解释循环,任何一条出现都是 W0 级回退。

Xenolith 与 OLLVM 的真正关系是同一强度档、相反结构:项目文档直接承认默认档(W1/W2)与 OLLVM 处在一个 band。差别在:OLLVM 守编译期,Xenolith 守链接后(拿不到源码的场景);OLLVM 的 FLA 打散 CFG 换来一个 dispatcher,Xenolith 保持 CFG 与原函数同构,把多样性花在块内部(逐块寄存器分配、调度、MBA、seed 派生);W3 的运行时指令流发散是 OLLVM 家族现有 pass 不提供的能力。

### VMProtect / Themida:Xenolith 与商业虚拟化的分叉

VMProtect 3.x 的架构:共享 handler 表、VIP/VSP 寄存器、滚动 key、可模式匹配的 handler(push-imm/add/read/jmp…)、`VMENTER`。NoVmp 在**没有壳源码**的条件下把 x64 3.0–3.5 提升到 VTIL——共享 ISA 正是可被训练、可跨样本复用的目标。Themida / Code Virtualizer 用多个互不兼容的 VM 骨架(TIGER/FISH/LION…)加每 build 变异,但核心仍是 handler 表 + 字节码流;多骨架抬高单二进制的人力成本,没有取消"找 dispatcher、分类 handler"这个循环,Oreans 自己的文档也警告不要无限制插 VM 并建议跨版本轮换架构。

Xenolith 的分叉:把"虚拟化"从运行时解释变成打包期编译。选定的导出函数提升为内部 IR 后,每个基本块生成一份仅本次构建存在的 PIC;IR 不进镜像,不存在可解码的 guest 指令流;两次打包之间没有可迁移的 opcode→语义表(G-WB-META)。旧 guest 解释器只作为测试 fixture 保留,`G-WB-NOLIFT` 断言它解不开打包产物。

同样的差距要讲清楚:Xenolith 不提供 VMProtect 的覆盖率(只虚拟化选定导出,CRT/`DllMain` 保持原生;不支持 64 位数据、间接调用、跳转表等一大类语义,全部 fail closed),不主张不可逆性,W1/W2 下分析师直接读变异 x64 依然可行。这个项目的判断是:在源码 GPL 公开的前提下,"私有 ISA"的安全叙事已经死了,可设计的东西只有"每次打包的产物互不可复用"。

### Tigress 与 M/oVfuscator

Tigress 是 Collberg 的源到源 C 混淆器,能力全面(函数虚拟化、数据编码、谓词插入),但需要 C 源码且许可限于研究用途。M/oVfuscator 把整个程序降级为 `mov` 单指令,研究性质,仅 x86-32。它们与 Xenolith 是互补关系:编译期手段守得住有源码的工作流,链接后场景留给 Xenolith。

## 使用

```
xenolith                              # 无参数 → TUI(键盘 + 鼠标)
xenolith tui [input.dll]
xenolith pack IN -o OUT [flags]
xenolith inspect IN [--json] [--exports]
xenolith project init IN -o FILE [--profile P] [--vm-export N ...]
xenolith project show FILE
```

### `pack` 标志

| 标志 | 取值 | 默认 | 说明 |
| --- | --- | --- | --- |
| `INPUT`, `-o/--output` | 路径 | 必填(除非 `--project`) | PE DLL/EXE 或 ELF |
| `--profile` | `fast` \| `standard` \| `max` | `max` | 见 Profiles |
| `--vm-export` | 逗号分隔名字 | 无 | 选定导出被虚拟化;`fast` 拒绝;未知名字 fail closed |
| `--trace-diverge` | 开关 | 关 | W3:每块两条等价路径;硬币 TEB⊕heap⊕RSP |
| `--select-rva` | `RVA:LEN` | 无 | 显式区间;不可 lift 则 fail closed;可重复 |
| `--select-function` | 名字 / `fn_0x...` | 无 | 经导出 / COFF 符号 / `.pdata` 边界解析 |
| `--select-all` | 开关 | 关 | 显式全映像函数发现(导出 + COFF + `.pdata`) |
| `--strict-coverage` | 开关 | 关 | 无选中或未全部转换成功则失败 |
| `--allow-native-fallback` | 开关 | 关 | 允许不可转换函数保持原生;报告为 `mixed_native`;与 `--strict-coverage` 互斥 |
| `--seed-hex` | 32 hex | 随机(OsRng) | 仅 G-POLY 复现;报告**永不打印** |
| `--project` | `*.xenolith.json` | — | CLI 标志覆盖/扩展文件内容 |
| `--json` | 开关 | 关 | 机器可读报告 |

### Profiles

| Profile | 实际行为 |
| --- | --- |
| `fast` | 变异 + 分片载荷加密;保留磁盘导入目录;拒绝 `--vm-export` |
| `standard` | + 哈希 IAT、stolen 入口字节、keyed FNV |
| `max` | + 页窗口、dump 干扰、stub VM、运行时探针、全量探针 |

### 项目文件

`xenolith project init IN -o app.xenolith.json` 写出、`pack --project` 读回:schema v2,已知键白名单,**未知键 fail closed**——未来的 `c2: true` 无法伪装成已实现。v1 文件自动迁移。TUI(`xenolith` 无参数启动)是四屏向导(Pick → Configure → Packing → Result),构建同一个 `PackRequest`,没有第二个引擎、没有额外选项;导出勾选即触发与命令行相同的预 lift,失败留在日志里。需要交互终端,无 TTY 时非零退出并提示用命令行。

## 构建与测试

```
cargo build --release -p xenolith-cli
cargo build -p hello-dll --release
cargo build -p license-toy --release
cargo test --workspace --exclude xenolith-runtime
```

`xenolith-runtime` 被排除是因为它是 `no_std` `#[panic_handler]` crate:workspace 级 feature unification 会把 `std` 链接进去(E0152)。排除不等于验证了它。打包测试需要 `target/release/hello_dll.dll` 与 `target/release/license_toy.dll`——先构建样例;缺样例算测试失败,不是跳过。

分发用可执行文件:

```
powershell -ExecutionPolicy Bypass -File scripts/build-exe.ps1
```

产出 `dist/xenolith.exe` 与 sha256;加 `-RunTests` 连样例与工作区测试一起跑,加 `-ReleaseBundle` 组装发布 bundle(SBOM、哈希、来源、预算门)。

样例:`samples/license-toy`(C 真值样例,冻结 `-O1`,手写 `DllMain`;`check_license(x,y): t=x^y; t+=0x9E3779B9; t>0x10000 ? t-y : t+y`)、`hello-dll`(rustc 构建的对齐检查:rustc 与 C 会让 lifter 分化成两个特例时,**C 是真相**)、`hello-elf`、`eh-dll`、`jni-host`、`jni-rust`。

## 开源协议

Xenolith 采用 **GPL-3.0-or-later,附加 Stub Exception**——GPLv3 第 7 条意义上的附加许可(全文见 [LICENSE](LICENSE) 末尾):

- **加壳器本体**(CLI、全部 crate、注入 stub 与 `xl_core` 的源码)是 GPL 软件。修改并分发它,必须提供源码。
- **被打包的程序**——Xenolith 注入用户程序的 stub、loader、VM 代码、运行时守卫,连同用户程序本身——可以按用户自选的任何条款分发。加壳不传染许可证。

例外的两个条件:(1) 对应的 Xenolith 源码保持 GPL-3.0-or-later 可得;(2) 例外只覆盖注入产物与独立用户程序的组合,不覆盖 Xenolith 自身及其作为加壳器分发的库。

实际效果:用 Xenolith 打包闭源商业软件并分发成品,是被许可的;修改 Xenolith 本体再分发,仍受完整 GPL 约束。修改者可以保留这条例外,也可以删除(删除后你的版本变为纯 GPL)。

这与 UPX 的产物例外、GCC Runtime Library Exception 属于同一设计:copyleft 停在工具,不延伸到工具的输出。另有一层法律上的诚实:GPLv3 第 3 条规定本项目不构成反规避法意义上的"技术保护措施",不赋予任何人禁止他人对 GPL 版本进行逆向的法律权力——Xenolith 的全部强度主张都是工程意义上的,不是法律意义上的。

## 文档

[SUPPORT](docs/SUPPORT.md)(当前支持矩阵 vs 生产目标)· [THREAT-MODEL](docs/THREAT-MODEL.md) · [WHITEBOX](docs/WHITEBOX.md)(选定导出虚拟化的白盒分级)· [ENTROPY](docs/ENTROPY.md)(W3 硬币与残余风险)· [TECHNIQUES](docs/TECHNIQUES.md) · [POLICY](docs/POLICY.md)

## 非目标

- 全 `.text` / CRT / `DllMain` 虚拟化
- 克隆 VMProtect / Themida 的共享 handler 表 ISA(白盒回退,见 [docs/WHITEBOX.md](docs/WHITEBOX.md))
- 商业壳对等、不可逆性、CI 里的"无限 AI 攻击失败"
- 杀死其他进程、注入其他进程、修改磁盘 ntdll、对抗 EDR
- macOS、ARM、.NET mixed-mode、内核驱动(内核协助是 G7,无签名前被阻塞)
- 把 `xenolith-loader` 或 `xenolith-runtime` 当作打包映像的运行时
