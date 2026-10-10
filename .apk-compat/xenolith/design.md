# Xenolith 安卓 ELF 加壳设计（aarch64-linux-android 主目标 + x86_64-linux-android 验证路径）

实现工作树：`E:/XiangMu/Xenolith-android`，基线 `main@8d40073`（本会话已核实：工作树存在、clean、HEAD 即 8d40073）。
本文档位于 `E:/XiangMu/JavaShroud-public/.apk-compat/xenolith/design.md`。**本稿为 v2 修订版**（评审 8 条意见全部处置，见 §9 修订记录）。

依据材料：
- 勘察报告（任务随附 JSON：androidGaps / architecture / peAssumptions / repoRules / risks / stubDesign）。
- 本会话亲自复核的源码锚点（附录 A 列出全部 file:line，含 v2 新核：protocol 三处 PAGE_SIZE 闸、xl_core 四处 4096、docs/THREAT-MODEL.md 实位等）。
- 本会话亲自运行的环境核查（附录 B：emulator-5554 = x86_64 / API 34 / `libndk_translation.so`；SDK 组件清单；`.apk-compat/samples` 样本盘点）。

---

## 0. 范围与非目标

**目标（本设计覆盖）**
1. `aarch64-linux-android`（EM_AARCH64=183，ET_DYN 共享库 `.so`）整页 AEAD 加壳，产物仍是可被 bionic `dlopen` 的合法 ELF。
2. `x86_64-linux-android`（EM_X86_64=62，ET_DYN `.so`）同步支持：复用现有 x86-64 ELF 路径 + 新增 bionic 验证门禁（模拟器原生 ABI）。
3. CLI 完全向后兼容（`pack` 动词 / `--profile` 档位 / `--json` 输出形状，见 §6）。
4. 16KB 页设备正确性（全链参数化，**不写死 4096——同变清单见 A-3，共 14 处**）。
5. 装载与功能验证闭环：NDK 合成 victim + runner、真实 App arm64 `.so` 重打包安装启动、llvm-readelf 结构断言、每类用例先跑未打包基线。

**非目标（fail-closed 具名拒绝，不静默降级）**
- armeabi-v7a / 任何 ELF32：`Unsupported` 具名错误，记为后续可选项。
- Android PIE **可执行体**（带 PT_INTERP 的 ET_EXEC/ET_DYN）：本里程碑只接受 `.so`（无 PT_INTERP）。理由：dlopen 对象只依赖文件 `e_phoff`（platform/elf.rs:269-273 既有结论），而 PIE 路径还需 PT_PHDR/auxv 一致性在 bionic 上实证——留待 `.so` 稳定后扩展。
- Android 上的函数虚拟化（`--vm-export`/`--select-rva`）：ELF 路径维持既有 fail-closed（platform/elf.rs:77-81）。superop 代码生成是 x86-64 专属，Android 强度 = 整页密封，文案必须如实（§7 风险 R-6，记忆规则 whitebox-superoperator-not-vmp-isa：不得宣称 W0）。
- Android 反调试探测（ptrace/TracerPid）：guard 在 ELF 路径维持空集（现状 platform/elf.rs:430 `probes: Vec::new()`），报告如实输出 0 探测；新增探测属后续策略工作且受 docs/POLICY.md 禁止清单约束。
- `--lazy-regions`：ELF 一律具名拒绝（§1 A-7；修复勘察指出的"接受标志但 dormant 页以 SIGSEGV 收场"缺陷）。
- **DT_INIT 与 DT_INIT_ARRAY 并存的输入**：具名拒绝（§1 A-14——现状打包会静默丢弃原 DT_INIT 函数，Android 是新工具链面，必须显式 fail-closed 而非沿袭隐式假设）。

**范围治理义务**（勘察 repoRules/risks）：docs/SUPPORT.md:36 平台表（"Android … Out of scope"）与 :188 完成标准、**docs/THREAT-MODEL.md**（v1 误写 `dist/THREAT-MODEL.md`；实测仓库只有 docs/THREAT-MODEL.md，dist/ 目录不存在且属构建输出，见附录 A——v2 已全部改指 docs/）、仓内计划文档需随实现一次性更新。计划文档实际位于**主仓** `E:/XiangMu/Xenolith/.zcode/plans/plan-sess_48aa7d2c-b9c7-49b8-ae99-932711452015.md`（未跟踪本地文件；本会话核实存在，:57 附近即 "Android / ART / macOS" 非目标行；android 工作树内无 `.zcode/` 目录）。本设计 §8/§10 把文档更新列为完成标准的一部分，避免"report 虚报能力"违反仓库诚实性规则。

---

## 1. 总体架构决策（A-1 … A-14）

| # | 决策 | 理由（锚点） |
|---|------|--------------|
| A-1 | **双轨策略**：arm64 = 新常量表 + 新 stub 发射器 + 新 core 对象；x86_64-android = 复用现有 x86-64 ELF 路径（stub/机器码/`__NR_mprotect=10` 内核 ABI 与 Linux 相同），只新增 bionic 验证与页尺寸参数化消费 | formats/src/elf.rs:7（EM_X86_64=62）；stub.rs ~:1866-1877（x86-64 裸 syscall，`-4096` 对齐；v2 核准锚点）；勘察 androidGaps[0]/[7] |
| A-2 | **协议新增 `PLATFORM_ELF64_AARCH64 = 2`**；x86_64-android 沿用 `PLATFORM_ELF64 = 1`（它就是 AMD64 ELF64，bionic 与否是部署属性，不进 AAD 域）。platform 字节进入 region/import AAD（protocol/src/lib.rs:172/:107），旧 CLI/旧 core 打不开新平台信封 = fail-closed | protocol/src/lib.rs:16-17、:168-181、:97-115；JavaShroud 仓 AGENTS.md 兼容性断裂原则 |
| A-3 | **页尺寸参数化（16K 支持的同变清单，共 14 处，缺一即目标 4 不可达）**。`page_size = clamp(max(PT_LOAD.p_align), 0x1000, 0x4000)`，Android 仅存在 4K/16K 两档；输入 p_align > 16384 具名拒绝。同变点清单（v2 按评审意见补全，全部本会话核读）：**protocol 三闸**——encode() 区域密文>PAGE_SIZE 即 Invalid（lib.rs:204）、parse() ct_len>PAGE_SIZE 即 Invalid（:304）、seal_region() plaintext>PAGE_SIZE 即 Invalid（:439），上限改为新共享常量 `XL_MAX_REGION = 16384`（Rust/C 两侧同名同值；`PAGE_SIZE` 语义保留为 x86 chunk 默认）；**pack 三对齐 + p_align**——new_phoff=align_up(len, **0x1000**)（platform/elf.rs:235）、seg_filesz=align_up(content_len, **0x1000**)（:246）、load_vaddr=align_up(max_va_end, **0x1000**)（:250）全部改用 page_size，新 LOAD `p_align`（:302，现写死 0x1000）同值——p_offset 与 p_vaddr 同按 page_size 对齐后 PT_LOAD 同余约束 `(p_vaddr-p_offset)%p_align==0` 自然成立，否则 bionic/内核拒载整个追加段；**resolver 页掩码三处**——`(rva as u32) & !0xfff`（:59、:399、:411）改 `& !(page_size-1)`（16K chunk 下 carve-out 必须 chunk 粒度：4K 子明文窗无法存在于以 16K 为密封单元的记录中，否则该 chunk 无从整块密封）；**xl_core 四处 4096**——:541（envelope 预扫描）、:772（xl_build_region_table）、:1082（activate 主循环）三处长度闸 + **:871 `uint8_t ct[4096]`（G5 re-seal 栈缓冲，本会话自查发现、评审未列）**，统一改 XL_MAX_REGION（ELF 已禁 lazy，:871 仅 PE 走到，但常量必须同值防漂移）；**stub**——新 meta 字段 `META_PAGE_SIZE`（u32 @ meta[72..76]，STUB_META_LEN 保持 80；已核对字段占用 0..64/63/64..68(TLS,PE)/68..72(SELF_RVA)，72..76 空闲），x86/aarch64 两 shim 按 meta 值对齐；**chunk 循环**——platform/elf.rs:117 现用 `xenolith_crypto::PAGE_SIZE`，改传入 page_size | 勘察 risks[0]；protocol lib.rs:204/:304/:439、platform/elf.rs:59/:117/:235/:246/:250/:302/:399/:411、xl_core.c:541/:772/:871/:1082（全部本会话核读，见附录 A） |
| A-4 | **build.rs 交叉编译 xl_core.c**：探测 `ANDROID_NDK_HOME`/`ANDROID_NDK_ROOT`/`ANDROID_HOME/ndk/*`，用 `toolchains/llvm/prebuilt/<tag>/bin/aarch64-linux-android24-clang -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fpie -c` 产出第二个 ET_REL 对象；**NDK 缺失不 panic**（PE/x86 构建不受影响），改为 rustc-env 标记缺失，pack 期 arm64 具名报错 `aarch64 runtime core not built (NDK not found)`。单个 CLI 二进制同时内嵌 x86-64 与 aarch64 两个 core | build.rs:11-58（现状仅宿主 cc）；勘察 androidGaps[3]/[4]；NativeShroudPacker.kt spawn 模型（POLICY.md:36） |
| A-5 | **aarch64 stub 手写定宽编码器**（新文件 `stub_aarch64.rs`）：AArch64 指令定宽 4 字节，`Vec<u32>` + 标签 fixup 回填，无第三方汇编依赖；iced-x86 不支持 AArch64。间接入口（stub entry、vprotect shim）首指令 `bti jc`/`bti c`（§3.5 BTI）；`svc #0`、`x8=226`（__NR_mprotect）。x86 ELF stub 同步改为读 `META_PAGE_SIZE` 做对齐 | stub.rs:1649-1883（现有 ELF 发射器全量核读）；勘察 androidGaps[7]/[8] |
| A-6 | **INIT_ARRAY[0] 自举平移**：bionic 与 glibc 一样在重定位后、调用前把 `INIT_ARRAY[0]` 的 `R_AARCH64_RELATIVE(1027)` addend 算成 `load_bias+addend` 再间接调用——把该 addend 重定向到 stub（既有机制 platform/elf.rs:596-677 的 aarch64 对应物，换常量 + 新 fixture）。`DT_INIT` 删除逻辑（rebuild_dynamic_without_init, platform/elf.rs:682-714）是字节手术，架构无关，直接复用；其"只回放 INIT_ARRAY[0] 原 addend"的语义边界见 A-14 | 勘察 androidGaps[2]；platform/elf.rs:596-677 本会话核读 |
| A-7 | **`--lazy-regions` 在 ELF（含 Android）改为具名拒绝**：`lazy regions require the G5 fault-wake runtime (not available on ELF in this release)`。ELF 无 fault-wake（emit_elf_stub 无 trampoline），现状接受标志写 lazy 表 = dormant 页 SIGSEGV 静默崩溃缺陷。JavaShroud 侧已禁 lazy（NativeShroudPacker.kt:542 `require(!flags.lazyRegions)`，本会话核实），无消费者受损 | platform/elf.rs:143-151；勘察 risks[6] |
| A-8 | **RELR / packed-relocation 输入具名拒绝（v2 修正常量）**。拒绝标签全集：`DT_RELR(36)`、`DT_RELRSZ(35)`、`DT_RELRENT(37)`、`DT_ANDROID_REL(DT_LOOS+2=0x6000000F)`、`DT_ANDROID_RELSZ(DT_LOOS+3=0x60000010)`、`DT_ANDROID_RELA(DT_LOOS+4=0x60000011)`、`DT_ANDROID_RELASZ(DT_LOOS+5=0x60000012)`（DT_LOOS=0x6000000D）。v1 所写 "RELA=0x6000000F+1" 是 RELSZ 之误——按 v1 数值实现 ANDROID_RELA 输入会漏拒，而 scan_rela 只扫 DT_RELA（elf.rs:159）、fail_closed_on_relative_into_rx 也只扫 DT_RELA（platform/elf.rs:519-576），漏拒即密封页相对重定位被 ld 应用后又被明文恢复覆盖。本组数值本会话经 bionic linker 源检索核实（REL=LOOS+2/RELSZ=LOOS+3/RELA=LOOS+4/RELASZ=LOOS+5），**实现期仍须以 NDK sysroot 头文件复核并固化**（本机暂无 NDK，见附录 B）。拒绝文案附 workaround：`-Wl,--pack-dyn-relocs=none` / CMake `ANDROID_PACK_DYN_RELACS_OFF` | formats/src/elf.rs:159；platform/elf.rs:519-576；评审问题 3 |
| A-9 | **guard 维持空集 + 诚实报告**：Android profile max = 同等密封、0 反调试探测；PackReport/notes 如实记录 | platform/elf.rs:430；勘察 androidGaps[13] |
| A-10 | **vm 维持不可用**：ELF `--vm-export`/`--select-rva` fail-closed 不变；Android 文档明确"页级密封，无每函数虚拟化" | 记忆 virtualize-selected-exports-not-full-text |
| A-11 | **装载验证双宿主**：新 `xl-dlopenhost`（Android 专用 dlopen 宿主，镜像 xl-loadhost 契约：dlopen→dlsym→打印一行 JSON→dlclose，绝不调用导出）+ 合成 victim 的 **runner**（可执行体，负责功能性调用断言，如 `hello_add(2,3)==5`）。本地门禁 `scripts/android-e2e.ps1` 跑 emulator-5554（x86_64 原生 + ndk_translation 跑 arm64）；CI android job 做交叉构建/打包/结构断言（模拟器不进 CI，理由见 §8.4 与 SUPPORT.md:196 文化） | xl-loadhost/src/main.rs:1-19 契约（本会话核读）；勘察 androidGaps[15] |
| A-12 | **JavaShroud 契约（跨仓，另行实现）**：spawn CLI 不链接 crates（POLICY.md:36）；Android 分支接受 `format=elf64-dyn` + 新增 `machine` 字段（§6）。勘察所谓 ":413 强制 report format" 经本会话核实实为 **profile 回显校验**（~:407-415），format 仅在日志行输出（:425）——JavaShroud 真正锁死 Android 的是**调用点结构**（只有 Windows `qp_ffi.dll` 走 xenolith，Linux `libqp_ffi.so` 固定 unpacked 流程并打日志 :235），改造成 Android 分支接线 + 校验放宽 | NativeShroudPacker.kt:53-54/:184/:235/:244/:378/:407-415/:425/:482（本会话核读） |
| A-13 | **许可证延续**：`stub_aarch64.rs` 与两个架构的 xl_core 注入物继续走 LICENSE:653 STUB EXCEPTION（打包产物可任意条款分发；GPL 停在工具本身）。新 stub 文件头注明与既有 stub.rs 相同的例外声明 | LICENSE:653（本会话核读）；README.md:145 |
| A-14 | **DT_INIT 与 DT_INIT_ARRAY 并存 → 具名拒绝**（v2 新增，评审备注项落实）。现状语义：rebuild_dynamic_without_init 删除 DT_INIT（platform/elf.rs:682-714），而 META_ORIGINAL_ENTRY 回放的只是原 INIT_ARRAY[0] 的 RELATIVE addend（:362-363 写入、:381 重定向）——若输入同时带 DT_INIT 与非空 DT_INIT_ARRAY，原 DT_INIT 函数被**静默丢弃**（ELF 规定 DT_INIT 先于 INIT_ARRAY 执行，属语义改变）。NDK clang 产出的 .so 构造器全走 init_array、通常无 DT_INIT，但 Android 是新工具链面，本设计显式化该假设为 fail-closed：检测到 DT_INIT≠0 且 DT_INIT_ARRAYSZ≥8 → 具名错误 `input has both DT_INIT and DT_INIT_ARRAY: packing would drop the original DT_INIT function`（workaround：无需——NDK 输出不触发；如遇手写链接脚本产物请重链）。DT_INIT-only 输入维持既有拒绝（init_array_bootstrap 无槽即报错，platform/elf.rs:651-653） | platform/elf.rs:362-363/:380-381/:682-714/:638-654；评审问题 8 |

---

## 2. 分层落点（formats / crypto / protocol / pack / vm / loader / guard / CLI / hosts / CI / docs）

### 2.1 xenolith-formats（解析层，fail-closed）
改 `crates/xenolith-formats/src/elf.rs` + 新增 `elf_aarch64.rs`：
- `Elf64` 增加 `machine: ElfMachine { Amd64, Aarch64 }`；`parse()` 接受 e_machine ∈ {62, 183}（现 :73-75 只认 62，错误文案具名区分）。
- `elf_aarch64.rs`：aarch64 重定位常量表（实现时以 NDK `llvm/elf.h` 复核数值；与勘察一致的锚点值：`RELATIVE=1027`、`ABS64=257`、`GLOB_DAT=1025`、`JUMP_SLOT=1026`、`IRELATIVE=1032`、`TLS_TPREL64=1030`、`TLSDESC=1031`、TLSLE text 内嵌类 ≈549/550/551）。
- `scan_rela` 按架构选择拒绝集：
  - x86-64（不变）：`R_X86_64_TPOFF32(23)` 拒（elf.rs:349-357）。
  - aarch64（新增）：`TLSLE_ADD_TPREL_*` 拒（局部执行 TLS 偏移嵌在指令立即数 = 密封 RX 页，TPOFF32 直接对应物）；GLOB_DAT/JUMP_SLOT/TLS_TPREL64/TLSDESC 目标在 RW GOT，bionic 于 init_array 前解析——沿用 x86 侧论证（elf.rs:340-348 注释体系），不拒。
  - 两架构共同：A-8 的 RELR/ANDROID 七标签具名拒；DT_REL-only 维持拒。
- **`tls_reloc_census` per-arch 参数化（v2 新增，评审问题 5）**：现 :603-645 硬编码 x86 编号（:636-642 `18|22 → ie`、`16|17 → ld`），arm64 输入上按 x86 语义计数 → PackReport 的 TLS note（platform/elf.rs:499-501 直接消费）在 arm64 包上输出错误统计，违反报告如实义务。参数化映射：x86 不变；aarch64 `ie ← TLS_TPREL64(1030)`、`ld ← TLS_DTPMOD64(1028) | TLS_DTPREL64(1029)`、TLSDESC(1031) 不计数（镜像 x86 对 TLSDESC 的处理）。与 ifunc_resolvers(37→1032) 同 PR 完成，杜绝同类半改动。
- `ifunc_resolvers`/`ifunc_symbol_values` 常量参数化，逻辑不变。
- `packed_bootstrap_target`（elf.rs:905-950）：`R_X86_64_RELATIVE_TYPE=8`（:952）分支并列增加 1027。
- SONAME/DT_NEEDED：**继续字节原样保留**（`rebuild_dynamic_without_init` 只删 DT_INIT；DT_NEEDED 现被显式丢弃不解析，elf.rs:156）——对 bionic 依赖解析是必要条件且现状满足；新增保真断言（§8.3 readelf 集合相等）而非运行时逻辑。

### 2.2 xenolith-crypto
- `PAGE_SIZE`（lib.rs:20，0x1000）语义降级为"x86 路径默认 chunk"；协议/核心的硬上限改用共享常量 `XL_MAX_REGION=16384`（A-3）。crypto 内部 AEAD 与页尺寸无关（nonce/tag 不变）。

### 2.3 xenolith-protocol
- `PLATFORM_ELF64_AARCH64: u8 = 2`（lib.rs:16-17 旁新增）；`encode()`/`parse()` 校验 platform ∈ {0,1,2}，未知值 `ProtocolError::Invalid`（fail-closed）。
- **三处 PAGE_SIZE 长度闸改为 XL_MAX_REGION（v2 新增，评审问题 1）**：encode() 区域密文闸（lib.rs:204）、parse() ct_len 闸（:304）、seal_region() 明文闸（:439）。16K chunk 在 :439 打包期即 Invalid——不改则目标 4 与 §8.1 的 16K victim 用例必然失败。
- `region_aad`/`import_aad` 不改结构（platform 字节透传，aad[6]/aad[7] 语义不变）。
- **同变义务**（仓库规则：协议变更同 PR 全链同步）：xl_core.c 镜像（§2.5）、inspect 展示、fuzz fixtures（elf_parse/envelope_parse 增 arm64 用例）、docs、JavaShroud 侧报告消费文档（§6）。

### 2.4 xenolith-pack
- `build.rs`：A-4 双 core 编译（host + NDK aarch64），`rerun-if-env-changed=ANDROID_NDK_HOME` 等；输出 `XL_CORE_OBJ_PATH`（既有）+ `XL_CORE_OBJ_AARCH64_PATH`（或 `NONE` 标记）。
- `runtime_image.rs`：
  - `load_builtin()` → `load_builtin(arch: CoreArch)`；
  - 新 `extract_elf_rel_aarch64`：e_machine==183 校验（对照现 :309-311 的 62 校验）；`.text*`+`.xlg` 扁平化契约不变；符号偏移提取不变；
  - 重定位白名单（clang `-fpie` 静态 C 期望集，实现首跑后按实测收紧）：`CALL26(266)/JUMP26(265)`、`ADR_PREL_PG_HI21(275)+ADD_ABS_LO12_NC(277)`（页对+低 12 位指令立即数回填）、`ADR_PREL_LO21(276)`、`LDST*_ABS_LO12_NC(278..282)`、`CONDBR19(264)/TSTBR14(263)`；GOT 类或任何未列类型 → `RuntimeImageError::Relocs` fail-closed（与 x86 侧 PC32/PLT32-only :469-482 同哲学）。COFF 0x8664 门（:63）不动。
- `stub.rs`（x86 ELF 发射器）：共享常量迁出到新 `stub_meta.rs`（`STUB_META_LEN/META_*/CTX_*`，现散在 stub.rs:13-18/:1647-1660）；x86 vprotect 对齐从 `-4096` 常量改为读 `META_PAGE_SIZE`（~:1866-1877）；其余流程不动。
- 新 `stub_aarch64.rs`（§3 详述）。
- `platform/elf.rs`（主改造点，pack_elf :37-514）：
  1. classify 后按 `parsed.machine` 分派 stub 发射器与 core 对象（A-4 缺失即具名错）；
  2. `page_size = clamp(max PT_LOAD.p_align, 0x1000, 0x4000)`；p_align > 0x4000 或含 PT_INTERP → Android 具名拒；**A-3 的三处 align_up（:235 new_phoff、:246 seg_filesz、:250 load_vaddr）与 :302 p_align 全部换 page_size**（v2 补全——PT_LOAD 同余约束要求 p_offset/p_vaddr 同粒度对齐）；
  3. **resolver 页掩码三处（:59、:399、:411）`& !0xfff` → `& !(page_size-1)`**（v2 补全——16K chunk 下 carve-out 必须 chunk 粒度；v1 遗漏会在盘上多留最多 12K 明文，属密封强度缺口）；
  4. chunk 循环 :114-129 用 page_size；
  5. envelope `platform`：arm64 → 2，x86 → 1（现 :168 恒 1）；
  6. `fail_closed_on_relative_into_rx`（:519-576）与 `init_array_bootstrap`（:596-677）常量按架构取 8/1027；**A-14 的 DT_INIT 并存检测加在 init_array_bootstrap 的 dynamic 扫描处**（同一循环已读出全部 tag，零额外成本）；
  7. `--lazy-regions` → 具名错（A-7），删除 :143-151/:185-195 的 lazy 表写入；
  8. ENTRY_KEEP=64（:391）**暂时保留**（glibc 实测魔法数；bionic 无已知同类入口指令窗口检查，缩窗需真机证据——开放问题 O-2）；
  9. IFUNC 解析器页保持明文窗口（:397-417 逻辑复用，常量换 1032）；
  10. u32 vaddr 上限检查（:251-253）不变；
  11. report：`format` 取值不变（:458-463），新增 `machine` 字段，notes 增 android 页尺寸/自举条目；TLS note 随 §2.1 census 参数化自动正确。
- `unwind/dwarf.rs`：`eh_frame_stub`/`eh_frame_hdr` 增加 aarch64 CIE 变体（返回寄存器列 x30 而非 RAX）；PT_GNU_EH_FRAME 追加逻辑（platform/elf.rs:325-354）架构无关复用。

### 2.5 xl_core.c（注入运行时核心）
- `platform != 1` 的 PE DIR64 重放跳过条件（~:1064）改为 `platform != PLATFORM_PE64(0)` 语义——1 与 2 都走 ELF 分支；未知 platform 提前 fail-closed 返回 0。
- **区域长度/密文长度上限四处同变（v2 补全，评审问题 4）**：`:541`（envelope 预扫描）、`:772`（xl_build_region_table）、`:1082`（activate 主循环）三处 `ct_len > 4096 || len > 4096` 闸 + **`:871 uint8_t ct[4096]`（G5 re-seal 栈缓冲，本会话自查发现）**，统一改共享常量 `XL_MAX_REGION 16384`（与 protocol/§2.3 同 PR 原子修改）。只改主循环一处时 16K 信封在 :541 预扫描即 return 0，装载期失败——四处必须一次到位。
- `region_aad`/`import_aad` 镜像（:443-490）不改布局。
- 其余 freestanding 特性可移植：GCC/clang 原子分支（:975-996）与 `xl_final_protect` 泛化 phdr 解析无需改动；vprotect 对齐语义由各架构 shim 承担。

### 2.6 xenolith-vm
不动。ELF fail-closed 路径维持（platform/elf.rs:77-81）。

### 2.7 xenolith-loader
- `MAX_PAGES=65535`（:34）不变（16K chunk 下覆盖能力反而更大）；`LAZY_REGION_STATE_MAX`（:43）随 A-7 在 ELF 路径不再被引用（PE G5 逻辑保留）。
- `PageRecord.original_len: u32` 已可容 16384。

### 2.8 xenolith-guard
不动（ELF 空集，A-9）。

### 2.9 xenolith-cli
- `pack`/`inspect` 子命令、参数集、`--json` 输出结构不变（§6）；新增 fail-closed 错误文案（NDK 缺失/ELF lazy/RELR 七标签/PT_INTERP/p_align>16K/ELF32-v7a/DT_INIT 并存）。
- inspect：platform/machine 展示 + aarch64 自举标记（INIT_ARRAY[0] 的 1027 addend 落在末个 R+X LOAD → packed 标记）。

### 2.10 xl-loadhost / 新 xl-dlopenhost / samples
- `crates/xl-dlopenhost`（新 bin，workspace 成员）：`#[cfg(target_os = "android")]` 真身（`dlopen(RTLD_NOW)` → `dlsym` 逐导出 → 一行 JSON（path/export/ok/errno）→ `dlclose` → 退出码）；非 Android 目标编译为报错占位（镜像 xl-loadhost 的 `#[cfg(windows)]` 门控 :21/:173）。
- `samples/hello-android/`（新）：`libhello_jni.c`（导出 `hello_add`、`JNI_OnLoad`、`hello_string`）+ `runner.c`（dlopen→dlsym→调用→打印 `hello_add(2,3)=5` 等→PASS/FAIL）。双 ABI 构建。

### 2.11 CI
- 新 `.github/workflows/android.yml`（ubuntu-22.04）：安装固定版本 NDK（建议 r27c，`sdkmanager "ndk;27.2.12479018"`；版本钉死写进 job 与 docs）→ `cargo build -p xenolith-cli --release`（build.rs 自动产双 core）→ `cargo test -p xenolith-formats -p xenolith-pack`（arm64 fixture 单测）→ NDK clang 产双 ABI 合成 victim → pack → inspect 断言 → `llvm-readelf` 结构断言脚本 → 双包多态 + 翻转字节拒载（inspect/核心模拟器层断言）。
- 既有 windows/linux 腿零改动预期（NDK 不在时 build.rs 走缺失标记）。
- **CI 不含模拟器**（runner 无 KVM，bionic 二进制不能在 ubuntu 宿主直跑）——OS-load/功能级门禁在本地 `scripts/android-e2e.ps1` + release 检查单（§8.4），符合 SUPPORT.md:196 "Host emulator success is not OS-load success" 的反向同理：**结构绿 ≠ 模拟器装载绿 ≠ 真机绿**，三层各自记录（v2 修正锚点：该句在 :196，:36/:188 两处不变）。

### 2.12 docs（完成标准的一部分）
- `docs/SUPPORT.md`：平台表新增行——Android arm64 `.so`：Packer+结构 CI 支持；装载验证 = emulator x86_64 原生 + ndk_translation；真机矩阵另列；v7a Rejected。:188 完成标准同步。
- `docs/THREAT-MODEL.md`（**v2 修正：唯一在树路径；v1 误指 `dist/THREAT-MODEL.md`——实测 dist/ 目录不存在，仅为构建输出名，见附录 A**）：Android 强度如实（页级 AEAD，无 vm，无探测）。
- `docs/POLICY.md`：syscall 许可清单确认 Android 路径只用 `mprotect`；JavaShroud 节不变。
- README 平台矩阵行更新。

---

## 3. aarch64 stub 详细设计（`stub_aarch64.rs`）

### 3.1 交付物
`emit_elf_stub_aarch64(core: &[u8], core_entry: u32) -> Result<ElfStub, String>`：产出与 x86 版同契约的 `ElfStub { bytes, meta_off, entry_off }`——`[代码][core 字节][meta 80B]`，entry 是首字节（INIT_ARRAY[0] 重定向目标），meta 尾部 80B 布局两架构共享（stub_meta.rs，含 META_PAGE_SIZE@72..76）。

### 3.2 编码器
- `Vec<u32>` 定宽发射 + `Fixup { kind, at_word, label }` 回填。无第三方依赖；指令编码常量集中在文件头，逐条注释指令语义。
- 单元测试：黄金字节向量；结构断言（entry_off==0、首字 `bti jc`、meta 尾 80B、core 偏移=代码长度）；CI android job 用 NDK `llvm-objdump -d` 反汇编 round-trip 断言。

### 3.3 流程（与 x86 ELF stub 语义逐行对应，stub.rs:1686-1883）
```
bti jc                          // 间接入口防护（见 3.5）
stp x29, x30, [sp,#-16]!
stp x19, x20, [sp,#-16]!
adr  x16, meta                  // ±1MB PC 相对，core(~10-20KB) 远在范围内
ldr  w17, [x16, #META_SELF_RVA]
sub  x19, x16, x17              // x19 = load bias（对应 x86 lea/sub，stub.rs:1729-1733）
ldr  w17, [x16, #META_UNPACKED]
cbz  w17, …                     // !=1 走激活；==1 直接 forward（幂等门）
sub  sp, sp, #0xC0              // XlHostCtx(120B)+对齐；CTX_* 布局共享 stub_meta.rs
// 填 ctx：image_base/envelope/buf_len/orig_entry/gate/measurement(32B)/
//        load_library=NULL/get_proc=NULL/vprotect=shim/模块目录槽=NULL
adr  x0, ctx                    // AAPCS64：ctx 经 x0（对应 x86 rdi/rcx 分派 :1787-1793）
bl   core_entry                 // 编译期已知偏移，直接 bl
cbz  w0, fail
// 标记 META_UNPACKED：vprotect(meta, 4, RW) → str → vprotect(meta, 4, RX)（:1803-1824 同款两段式）
forward:
  ldr w17, [x16, #META_ORIGINAL_ENTRY]   // = 原 INIT_ARRAY[0] addend（A-14 语义边界）
  cbz w17, ret
  add x17, x19, x17(UXTW)
  blr x17                        // 转发原 INIT_ARRAY[0] 目标
ret:  ldp x19,x20; ldp x29,x30; ret
fail: 同 ret                      // fail-closed 静默返回：受保护页全是 0x90，下一次调用即崩
```

### 3.4 vprotect shim（`bti c` 入口，ctx 经 x0..x3 间接调用）
```
bti c
// 入参 x0=addr, x1=len, x2=prot(0x04/0x20/0x40), x3=*old（xl_core vp() 调用约定）
// *old 回显请求常量（x86 版同语义）；prot 映射 0x04→3 / 0x20→5 / 0x40→7，其它返回 0
// 对齐：page = meta[META_PAGE_SIZE]（启动时读入 callee-saved 寄存器）
//   addr &= -(page);  len = round_up(len + (orig_addr & (page-1)), page)
mov x8, #226                    // __NR_mprotect（arm64 通用表）
svc #0
// x0<0 → 0；否则 1
ret
```
关键差异 vs x86：mprotect 参数寄存器即 AAPCS64 x0..x2（x86 版需 rcx/rdx/r8→rdi/rsi/rdx 搬运，~:1846-1877），shim 更短。

### 3.5 BTI/PAC 说明
- bionic 读 `.note.gnu.property` 的 `GNU_PROPERTY_AARCH64_FEATURE_1_BTI` 时对可执行段施加 PROT_BTI；INIT_ARRAY 间接调用与 ctx->vprotect 间接调用都必须落在 `bti` 指令上，否则 BTI 设备 SIGILL。入口 `bti jc`、shim `bti c`。core 只被 stub 直接 `bl`，无需 bti；build.rs 显式 `-mbranch-protection=none` 钉死 core 编译，防 NDK 默认值漂移。
- PAC：被保护代码自身的 PACIASP/AUTIASP 恢复明文后照常执行；stub 不签名 LR；victim 启用 pac-ret 出现问题记 device-matrix 而非 packer 改动。
- 指令编码数值（bti/adr/svc 等）实现时以 NDK `llvm-mc` 输出核对并固化为常量。

---

## 4. bionic 装载约束对照表（要求 3 落实）

| bionic 约束 | 设计应对 | 验证 |
|---|---|---|
| 合法 ELF 头/phdr；dlopen 读文件 e_phoff | 追加 LOAD 策略整体保留；仅 e_phoff/e_phnum 指向尾部新表（platform/elf.rs:224-308）；.so 无 PT_PHDR/auxv 问题（:269-273） | readelf -h/-l 断言；xl-dlopenhost 实载 |
| PT_LOAD 同余/页对齐（16K 设备） | A-3 全清单：三处 align_up + p_align + 掩码三处 + protocol 三闸 + xl_core 四处 + meta/stub/chunk | 4K 模拟器 + 16K 对齐 victim 双跑 |
| SONAME/DT_NEEDED 完整 | 动态数组仅删 DT_INIT，.dynstr 字节不动；字符串表在非可执行 LOAD，不在密封集 | readelf -d 集合相等断言（§8.3 C-5） |
| Android M+ 拒 DF_TEXTREL；Android 10+ 拒 W+X 段 | 不引入 text reloc（新 LOAD 无动态重定位项指向）；新段 R+X，解密瞬时 RW 后还原为段声明权限（xl_final_protect） | readelf -d 无 TEXTREL；-l 无 W+X |
| 构造器语义：DT_INIT vs INIT_ARRAY | **A-14：两者并存具名拒绝**（现状会静默丢弃原 DT_INIT；NDK .so 通常无 DT_INIT，该假设显式化）；DT_INIT-only 维持既有拒绝 | 单测 fixture：伪造并存输入必须拒 |
| JNI_OnLoad/Java_* 导出可用 | dynsym/dynstr/hash 不动；System.loadLibrary→dlopen→init_array（先）→JNI_OnLoad（后）顺序保证 stub 先完成 | hello-android runner + 真实 App 启动门禁 |
| IFUNC（IRELATIVE 1032）在 init_array 前解析 | 解析器页保持明文窗口逻辑复用（:397-417 思路，常量换 1032，掩码 page 粒度） | 单测 fixture：含 IRELATIVE 的 NDK victim |
| BTI | §3.5 | `llvm-readelf -n` + BTI victim 实载 |
| eh_frame/unwinder | aarch64 CIE 变体 + PT_GNU_EH_FRAME（§2.4） | readelf -wf 结构 + 冒烟 |

---

## 5.（并入 §4 表，保留编号连续性）——占位说明：v1 §4 即 bionic 对照表，v2 未拆分。

## 6. CLI 兼容性（要求 2）

**保持不变**：
- 动词 `pack IN -o OUT [--profile fast|standard|max] [--json]` 及全部现有旗标（xenolith-cli/src/main.rs:39-126 本会话核读；profile 档位 = JavaShroud XENOLITH_PROFILES :28 同集）。
- `--json` 输出 = PackReport serde 结构，既有字段名/类型/取值域不变（`format` 仍只产 `pe64-dll/pe64-exe/elf64-exec/elf64-dyn`）。
- 输入按 magic 自动识别（formats classify：MZ→PE，\x7fELF→ELF），JavaShroud 侧调用形状（NativeShroudPacker.kt:482 首参 "pack"）零改动。

**新增（纯增量，不破坏解析方）**：
- PackReport 新增 `"machine": "x86_64" | "aarch64"` 字段（PE 路径填 "x86_64"）。
- fail-closed 具名错误（stderr，exit≠0）：ELF32/EM_ARM、arm64+PT_INTERP、p_align>16384、DT_RELR/DT_ANDROID_* 七标签、ELF `--lazy-regions`、DT_INIT 与 DT_INIT_ARRAY 并存（A-14）、NDK 缺失时 arm64 打包。错误文案附 workaround。

**JavaShroud 消费方影响评估**：现有 Windows 流程零变化；未来 Android 分支需接受 `format=elf64-dyn` + 校验 `machine=aarch64`。profile 回显校验（:407-415）天然兼容。

---

## 7. 风险清单

- R-1 协议双仓同步：platform=2 与 XL_MAX_REGION 上限需 protocol/xl_core.c/inspect/fixtures/docs/JavaShroud 消费方原子同变，漏一处即互相 fail-closed；单一 PR 清单 + fixture 矩阵门禁。
- R-2 NDK 依赖与钉版：NDK 缺失时 arm64 不可用（具名报错，x86/PE 不回归）；clang 版本漂移可能改变 ET_REL 重定位形态——白名单 fail-closed 安全但需跟进；CI 钉 r27c；白名单实测后收紧（O-3）。
- R-3 glibc→bionic 语义未实证项：ENTRY_KEEP=64 必要性、INIT_ARRAY/IFUNC 时序、loader lock 内 mprotect 的 SELinux 边界——阶段 A/B 实证，ENTRY_KEEP 保守保留待真机证据缩窗（O-2）。
- R-4 ndk_translation ≠ 真机：BTI/PAC/页尺寸行为可能被翻译层掩盖——SUPPORT 表分列『模拟器+翻译层验证』与『真机』；真机门禁列为后续项（O-4）。
- R-5 **16K 页全链同变（v2 按评审重写）**：A-3 枚举 14 处（protocol 闸 ×3 @ lib.rs:204/:304/:439；pack align_up ×3 @ platform/elf.rs:235/:246/:250 + p_align @ :302 + resolver 掩码 ×3 @ :59/:399/:411；xl_core ×4 @ :541/:772/:871/:1082；stub/meta ×2 + chunk ×1）——v1 声称"单条决策覆盖全链"与代码事实不符，v2 改为清单化同变 + §8.1 的 16K victim 专项用例（`-Wl,-z,max-page-size=16384`）逐处回归。漏任一处：protocol 侧打包期 Invalid / pack 侧同余违约拒载 / core 侧装载期预扫描失败，均为 fail-closed 但"16K 支持"目标落空。
- R-6 产品强度缩水：Android 无 vm、无探测——文档/报告如实（强度声明写入 docs/THREAT-MODEL.md，不沿用 Windows 虚拟化承诺）。
- R-7 x86_64-android 绿 ≠ Linux CI 绿 ≠ 真机绿：bionic≠glibc，三层门禁各自记录；CI 不含模拟器，OS-load/功能级在本地 android-e2e.ps1 + release 检查单。
- R-8 真实 App 样本偏差：PPSSPP libppsspp_jni.so 不能代表全部 App 形态（Termux 对照已列；VLC 无 arm64 lib 已排除）——失败模式记档并按需扩样。
- R-9 常量数值待 NDK 头文件终核：AArch64 reloc 号（1027/257/1025/1026/1032 与勘察一致；其余锚点值）与 A-8 的 DT_ANDROID_*（本会话经 bionic 源检索核实为 REL=LOOS+2/RELSZ=LOOS+3/RELA=LOOS+4/RELASZ=LOOS+5）——实现首日以 NDK `llvm/elf.h` + `llvm-mc` 双核对并固化；本机暂无 NDK（附录 B），该项为未终核项。
- R-10 JavaShroud 侧改造为跨仓后续：任一侧先合入均无破坏（现状 windows-only 接线保持无害；JavaShroud 未改前 android .so 仍走 unpacked 流程）。

开放问题：
- O-1 NDK 具体版本（建议 r27c；以操作员环境偏好钉死）。
- O-2 ENTRY_KEEP 在 bionic 的最小安全值（64 保守起步）。
- O-3 aarch64 ET_REL 白名单的实测终集（首跑后回填本档）。
- O-4 真机 arm64 门禁是否进入本期完成标准（当前：SUPPORT 表"后续"列，不阻塞本期）。

---

## 8. 验证计划（要求 4；每类用例先跑未打包基线）

### 8.0 环境现状（本会话实测，非计划假设）
- 模拟器 `emulator-5554` 在线：`ro.product.cpu.abi=x86_64`、`ro.dalvik.vm.native.bridge=libndk_translation.so`、API 34（adb getprop 实测）。
- SDK（`.apk-compat/android-sdk`）：platform-tools、emulator、system-images/android-34/x86_64、cmdline-tools/latest（含 sdkmanager.bat）、build-tools/34.0.0（**无 llvm-readelf，无 NDK**——首步 `sdkmanager "ndk;27.2.12479018"`，llvm-readelf 随 NDK 提供）。
- 样本：PPSSPP.apk arm64-v8a 含 `libppsspp_jni.so` + 4 个 hook 库（主 victim）；Termux.apk `libtermux.so`（对照）；VLC.apk 无 arm64 lib（排除）。

### 8.1 阶段 A——合成 victim（NDK，x86_64 与 aarch64 双 ABI）
1. 构建 `samples/hello-android` 双 ABI。
2. **基线**：push runner+lib → 运行 → 记录 stdout（`PASS hello_add(2,3)=5 …`）与 dlopen JSON。
3. 打包（三档 profile）→ `xl-dlopenhost` 装载断言（dlopen ok、导出全命中、退出码 0）→ runner 断言（stdout 与基线逐字节相等）。
4. ASLR：同包 3 次独立进程重跑。
5. 负向：翻转 payload 1 字节必拒；二次打包必拒；`--lazy-regions`、RELR/DT_ANDROID_* 输入、PT_INTERP 输入、DT_INIT+INIT_ARRAY 并存输入各自具名拒绝。
6. **16K 页专项（A-3/R-5 清单的逐处回归）**：`-Wl,-z,max-page-size=16384` victim 重复 2-4；另跑 4K chunk 包在 16K 对齐输入上的拒绝/接受矩阵按 A-3 语义验证；断言打包产物新 LOAD 的 (p_vaddr-p_offset)%p_align==0。
7. IFUNC victim（含 IRELATIVE）：解析器页盘上明文断言 + 功能等价。
8. TLS victim（initial-exec TLS 变量）：census 参数化后 report 统计与 readelf -r 实际计数一致（§2.1 v2 项）。

### 8.2 阶段 B——真实 App arm64 `.so`（PPSSPP）
1. 解包取 `lib/arm64-v8a/libppsspp_jni.so`。
2. **基线**：原样重打包 APK（zipalign+debug 签名）→ 安装 emulator-5554 → 冷启动 → logcat 主 Activity/GL 标记 → 卸载。
3. 打包 → 替换回 APK → 重签名 → 安装启动 → 同一 logcat 标记 + 无 `SIGSEGV/SIGILL/FORTIFY`（超时看门狗）。
4. Termux `libtermux.so` 同流程一轮。
5. ndk_translation 局限如实标注『模拟器+翻译层验证』，不冒充真机。

### 8.3 阶段 C——llvm-readelf 结构断言（每类用例打包前后各跑）
- C-1 `-h`：Machine、e_phoff 指尾部新表、phnum=原+2。
- C-2 `-l`：新增 PT_LOAD flags=R+E、p_align≥输入最大对齐、**(p_vaddr-p_offset)%p_align==0（v2 新增，对应 A-3 同余）**；无 W+X；PT_GNU_EH_FRAME 存在。
- C-3 `-d`：DT_INIT 消失；INIT_ARRAY/INIT_ARRAYSZ 保留；SONAME/DT_NEEDED 集合与打包前逐项相等；无 DF_TEXTREL。
- C-4 `-r`：INIT_ARRAY[0] RELATIVE(8/1027) addend 落新 LOAD 区间。
- C-5 密封面抽查：原可执行段磁盘字节 0x90（entry 保留窗与 IFUNC 解析器页除外），python 抽样脚本。
- C-6 inspect JSON：platform/machine/自举标记/pages 计数与报告一致；TLS note 计数与 readelf -r 实际一致。

### 8.4 阶段 D——CI 与门禁归位
- `android.yml`（§2.11）绿 = 交叉构建+单测+打包+结构断言层。
- 本地 `scripts/android-e2e.ps1` 跑 A/B 全量；release 检查单引用其产物。
- 完成标准矩阵写入 SUPPORT.md：arm64 .so 打包=支持；装载=emulator(x86_64 原生)+ndk_translation(arm64) 验证；真机=后续项——不虚报。

### 8.5 单元/集成测试组织（要求 5 后半）
- formats：aarch64 头/拒绝矩阵、1027 自举标记、RELR/DT_ANDROID 七标签拒、**DT_INIT 并存拒（A-14 fixture）**、**tls census per-arch 计数断言**——纯 Rust 字节 fixture 单测（仿 elf.rs 既有测试 :729-899 风格）。
- runtime_image：aarch64 ET_REL fixture + 白名单外重定位拒绝单测。
- stub_aarch64：黄金字节 + 结构断言；CI 用 NDK llvm-objdump round-trip，零新 Rust 依赖；**xenolith-runtime 维持既有 workspace 排除模式**（Cargo.toml:23 `exclude = ["fuzz", "crates/xenolith-runtime"]`，注释块 :20-22；v2 修正锚点）。
- protocol：platform=2 往返 + 未知 platform 拒 + **XL_MAX_REGION 边界（16384 过 / 16385 拒）往返** + fuzz fixtures 增补。
- e2e 全部经 `XL_SKIP_ANDROID_TESTS=1` 逃生阀（对称既有 XL_SKIP_WSL_TESTS，os_load.rs:826-829 模式）。

---

## 10. 里程碑

| 里程碑 | 内容 | 出口门禁 |
|---|---|---|
| M0 | formats arm64 解析/拒绝矩阵（含 census、A-8/A-14）+ protocol platform=2 与 XL_MAX_REGION 三闸 + fixtures 单测 | `cargo test -p xenolith-formats -p xenolith-protocol` 绿 |
| M1 | build.rs NDK 双 core + runtime_image aarch64 抽取 | arm64 core 偏移单测绿；无 NDK 环境构建不回归 |
| M2 | stub_aarch64 + meta 页尺寸 + pack 路径 arm64 端到端（A-3 的 14 处同变全落）+ inspect | 4K 与 16K 产物过 §8.3 C-1..C-6 |
| M3 | xl-dlopenhost + hello-android + android-e2e.ps1 阶段 A（双 ABI，含 16K/IFUNC/TLS/负向） | 基线-先行的装载+功能+负向断言全绿 |
| M4 | PPSSPP/Termux 真实 .so 阶段 B | logcat 标记断言 + 无崩溃看门狗 |
| M5 | CI android job + docs（SUPPORT/POLICY/**docs/THREAT-MODEL.md**/README）+ JavaShroud 契约文档 | CI 绿 + 文档过审（能力/验证层级分列，v2 修正文档落点） |

---

## 9. 修订记录（v1 → v2，逐条处置评审 8 项）

1. **protocol 三处 PAGE_SIZE 闸**：确认 lib.rs:204（encode）/ :304（parse）/ :439（seal_region）——已写入 A-3 同变清单、§2.3、modify[]；R-5 重写为清单化。
2. **pack 层三处 align_up + resolver 掩码三处**：确认 platform/elf.rs:235/:246/:250 与 :59/:399/:411——A-3/§2.4 补全；新增 §8.3 C-2 同余断言与 §8.1.6 专项；强度缺口（掩码 4K 粒度在 16K 下多留明文）定性为密封强度缺口并在 §2.4.3 说明。
3. **DT_ANDROID_RELA 常量错**：v1 "0x6000000F+1"（=RELSZ）纠正为四标签全集 REL=0x6000000F/RELSZ=0x60000010/RELA=0x60000011/RELASZ=0x60000012（本会话经 bionic linker 源检索核实；实现期 NDK 头终核，见 R-9）；A-8 重写并补 scan_rela/fail_closed 只扫 DT_RELA 的漏拒后果说明。
4. **xl_core 4096 三处→四处**：确认 :541/:772/:1082，另自查发现 :871 `ct[4096]` 栈缓冲（评审未列）——四处统一 XL_MAX_REGION，§2.5/R-5 更新。
5. **tls_reloc_census 未参数化**：确认 elf.rs:603-645（:636-642 硬编码）——§2.1 新增 per-arch 映射（arm64 ie←1030、ld←1028|1029、TLSDESC 不计），§8.1.8/§8.3 C-6 增报告一致性断言。
6. **THREAT-MODEL.md 落点**：实测仓库只有 docs/THREAT-MODEL.md，dist/ 不存在——§0/§2.12/M5/R-6/modify[] 全部改指 docs/。
7. **锚点漂移**：SUPPORT.md 引语改 :196（:36/:188 不变）；Cargo.toml exclude 改 :23（license :28）；.zcode/plans 计划文档改注"位于主仓 E:/XiangMu/Xenolith/.zcode/plans/（本会话核实存在且 :57 为 Android 非目标行），android 工作树无此目录"；stub vprotect 锚点改 ~:1866-1877。附录 A 同步。
8. **DT_INIT 丢弃语义**：新增 A-14（并存具名拒绝 + 显式假设声明），§4 对照表新增行，§8.1.5/§8.5 增 fixture 与负向用例。

---

## 附录 A：本会话亲自核读的源码锚点（E:/XiangMu/Xenolith-android @8d40073）

v1 已核（此处列目，行号见正文引用）：formats/src/elf.rs 全文；build.rs 全文；platform/elf.rs 全文；stub.rs :1-70 与 :1640-1883；protocol lib.rs :1-200；runtime_image.rs :55-80/:290-320/:440-500；xl_core.c :440-500/:975-1100；crypto lib.rs:20；loader lib.rs:34/:43；xl-loadhost main.rs:1-19/:21/:173；cli main.rs:39-130；NativeShroudPacker.kt 各段；POLICY.md:34-36；LICENSE:653；SUPPORT.md:36/:188。

v2 新核（评审复核）：
- `crates/xenolith-protocol/src/lib.rs` :200-210（encode 闸 @ :204）、:300-310（parse 闸 @ :304）、:432-448（seal_region 闸 @ :439）——sed 逐段确认三处 `PAGE_SIZE` 比较。
- `crates/xenolith-runtime/core/xl_core.c` `grep -n 4096` → :541、:772、**:871（`uint8_t ct[4096];`，G5 re-seal 路径栈缓冲）**、:1082；:860-880 上下文核读（re-seal 用 aead_seal 逐字节比对 orig_ct）。
- `ls docs/` + `find . -name "THREAT-MODEL*"` → 仅 `docs/THREAT-MODEL.md`；`ls dist` → 不存在。
- `Cargo.toml` :18-30 → exclude 单行在 :23（注释块 :20-22），license 在 :28。
- `docs/SUPPORT.md` :108-112（无该句）与 :194-198 → "Host emulator success is not OS-load success." 位于 :196。
- `ls .zcode/plans`：android 工作树无此目录；**主仓** `E:/XiangMu/Xenolith/.zcode/plans/` 存在，含 plan-sess_48aa7d2c-…md 等 5 个文件；`sed -n 55,60p` 确认 :57 附近列出 "Android / ART / macOS" 为非目标。
- A-8 常量：本机无 NDK 头文件可查（附录 B），经 bionic linker 源（aosp mirror）检索核实 REL=LOOS+2/RELSZ=LOOS+3/RELA=LOOS+4/RELASZ=LOOS+5、DT_LOOS=0x6000000D——标记为"已双源核实、待 NDK 头终核"。

## 附录 B：本会话运行的命令与关键输出（环境事实）
- v1 已列：git log/status（worktree @8d40073 clean）；adb getprop（emulator-5554 = x86_64/API34/libndk_translation.so）；SDK 组件与 NDK 缺失；samples zipfile 盘点。
- v2 新增：`grep -n 4096 xl_core.c`（四处）；protocol 三段 sed（三闸）；`ls docs`/`find THREAT-MODEL`/`ls dist`；`sed -n 18,30p Cargo.toml`；`sed -n 108,112p` 与 `194,198p docs/SUPPORT.md`；`ls .zcode/plans`（worktree 无、主仓有）；`sed -n 55,60p plan-sess_48aa7d2c…md`；bionic 源检索（WebSearch，android.googlesource/aosp-mirror；直连 raw 与 googlesource 均超时，改用检索摘要，数值已与评审一致互相印证）。
- 未运行任何构建/测试/打包命令（纯设计任务）。
