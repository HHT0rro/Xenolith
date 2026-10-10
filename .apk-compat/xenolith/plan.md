# Xenolith Android 生产级补齐 — 端到端实施方案(第 3 轮修订版)

依据: `out/android-production/parity.md`(8 项差距矩阵,commit `fbdb7cb` 勘察)+ 第 2 轮评审(9 条,已落实并经评审方核验为 resolved)+ 第 3 轮评审(2 阻塞 / 2 轻微 / 1 备注,本轮实读核验并落实,见 §0.5)。
所有 file:line 相对 worktree `E:/XiangMu/Xenolith-android`(分支 `feat/android`),标注"实读"的锚点均在修订时核对过。

## 0. 约束与环境(已实测)

### 0.1 硬约束
- **只改 worktree** `E:/XiangMu/Xenolith-android`;`E:/XiangMu/Xenolith` 是 main 检出,不动、不切分支、不提交 main。
- **实现类子代理一律不执行 git commit**;最终由集成收口工程师统一提交(§5.4)。
  worktree 有**非本任务产生的脏文件** `README.md`/`README.zh-CN.md`(已修改未提交)——各工作流线不得触碰,收口时由集成工程师裁决。
- 所有 cargo 命令带 `--manifest-path E:/XiangMu/Xenolith-android/Cargo.toml`。
- 本文件写入 `E:/XiangMu/Xenolith/out/android-production/plan.md` 是工作流发布产物:`/out/` 已被 main 仓 `.gitignore:52` 忽略,不构成对 main 检出仓库内容的改动。
- 宿主实际 shell 是 Git Bash(平台标注 cmd.exe 不符);脚本按仓库既有约定用 PowerShell(`scripts/compat2/*.ps1` 先例)。

### 0.2 环境(第 1 轮实测)
- `git log -1 --oneline` → `fbdb7cb`;`git branch --show-current` → `feat/android`。
- `adb devices -l` → `emulator-5554` / `emulator-5556` 在线(x86_64,Android 14 / API 34)。**主用 serial=emulator-5554**。
- NDK: `E:/opt/android-sdk/` 仅 cmdline-tools;`ANDROID_NDK_HOME` 统一指向
  `E:/XiangMu/JavaShroud-public/.apk-compat/android-sdk/ndk/27.2.12479018`(实测 clang.exe 在位,与 CI 钉死版本一致,
  `android.yml:19-21`;build.rs 发现链实读 `build.rs:136-158`)。
- arm64 转译组件在位(勘察轮实测 native-bridge 属性与 `/system/bin/arm64/linker64`),**但 arm64 ELF 进程从未实测执行**——M-B1 首跑即验证。
- WSL Ubuntu 可用,仅备选,主流水线不使用。

### 0.3 撰写时实读核验过的关键锚点
- `stub_aarch64.rs:1-657`: 两遍发射器 `Asm`(B/BL ±128MiB、B.cond/CBZ ±1MiB、ADR ±1MiB、TBZ ±32KiB,`:113-243`)
  + 参数化编码器(`:59-111`,movz imm16 上限 0xFFFF)、golden 单测(`:529-657`)、fail 态(`:421-428`)、
  ctx 128 字节预留 `CTX_FRAME=0xC0`(`:263-264`)、四槽置零 88/96/104/112(`:338-341`)、META_TABLE_RVA 读取 `:344-345`。
- `stub.rs`: emit_elf_inner `sub rsp,0xB0` 构 128B ctx(`:1712`/配对 `:1760`),struct-tail 事故注释(`:1710`);
  仅置零 104/112(`:1735-1737` 一带);fail 注释 "0xCC" 过期(`:1799-1800`);sysv 参数决定 ctx 传参寄存器(`:1747-1752`);
  **PE 路径 ctx 建在 0x2FF8 大栈区内**(`sub rsp,0x2FF8` `:308`,`:1248` 注释 "XlHostCtx at rsp+0x200 (**112 bytes**)" 的
  112 为过期值,ctx 实为 128B、扩容后 136B——PE 补零写 ctx+128 安全)。
- `build.rs:22-40`: **is_like_msvc → cl.exe 编译宿主 x86_64 core(MSVC x64 无内联汇编)**;`:41-61` gcc 分支;
  `:64-134` NDK aarch64 core(`-fpie -mbranch-protection=none -mno-outline-atomics -ffreestanding`,`:108-122`);
  仅产宿主+aarch64 两对象,**不存在 NDK x86_64-linux-android core**。
- `runtime_image.rs:305-310`: COFF 路径 `sysv_abi: false`;`extract_elf_rel_machine`(`:328` 起)只收集 `.text*`/`.xlg`
  到扁平 blob、其余节丢弃;`runtime_image.rs:641-662` aarch64 core 缺失 named-error fail-closed。
- `xl_core.c`: XlHostCtx 布局(`:55-75`: 88=veh_handle、96=veh_remove、104=get_module_file、112=load_library_ex(112..120)、
  120=phdr_va,止于 128B);**运行时状态契约——`.xlg` 必须是 INITIALIZED(非 .bss)节,注入镜像内联携带字节,
  "a zero initializer would land in .bss, whose bytes the injected image cannot carry"(`:681-685`,`:709-711`),
  且 ".xlg state page is not writable until the G5 publish"(`:733-735`)**;两条 RX 写路径:
  **`xl_region_open`(`:849-869`:`vp(RW)`→`aead_open(...,dst)` 写回解密明文(内部 `chacha20_xor` out=dst,`:345`)→final protect)**
  与 **`copy_rx`(窃取字节恢复,`xl_core_activate` gate≥1 调用,`:1305-1308` 一带)**;
  平台门(`:1053-1055`)、ELF 跳过 DIR64(`:1280-1300`)、`xl_region_seal` 写回密文后置 PAGE_NOACCESS(`:873-907`,G5 专用不执行)。
- `superop.rs`: VM 无字节码无调度器(`:1`);发射树全绑 iced(`emit_inner:46`/`emit_block_body:139`/`emit_term:164`/
  `emit_coin:204` 读 `gs:[0x30]` TEB/PEB `:209-215`/`emit_shuffle:523`);中性纯函数文件私有:
  `alloc_map:242`、`used_vregs:286`、`schedule_stmts:361`、`block_stream:557`。
- `mba.rs:1-29`: IR 级纯 u32 恒等式,可全量复用。
- `ir.rs:6-11,52-72,137-158`: SSA IR,u32 值域,G4 扩展为 x86 语义;`lift.rs:6-7` 32 位纪律;`MAX_LIFT_BYTES=256`(`:18`);
  `forbidden_vm_rule` 含 JNI ABI(`:193-211`)。
- `platform/elf.rs`: aarch64+PT_INTERP 拒(`:61-66`)、lazy 拒(`:66-72`)、**三道选择门 `:143-158`**、
  `fail_closed_on_relative_into_rx`(`:159`)、报告恒空(`:565-567`)、RWX 注记(`:612-616`)、
  **密封页盘上 0x90 填充(`:508`),ENTRY_KEEP=64 入口窗(`:481-483`)**、stub 自含 .eh_frame=CIE+单 FDE+空 hdr(`:304-317`)。
- `stub_meta.rs`: 80B meta 表,**`META_TABLE_RVA=76`(`:41`)——文档块 `:19` "76..80 reserved" 过期**;两 ELF stub 都在读它。
- `xenolith-guard/src/lib.rs:11-101`: 16 Windows 探针(id 1-16)+ 模块哈希名单。
- `formats/elf.rs`: dynsym/IFUNC/符号遍历 API(`:815,:1004`)可复用。
- `.github/workflows/android.yml:1-10,26-118`: 结构层 CI,无模拟器。
- `docs/SUPPORT.md:36-37,190-195`: Android 现只声明结构层。
- `tests/os_load.rs:1-11`: 非 Windows host 显式 BLOCKED 不算通过。

### 0.4 与 ask 的对齐声明
四条工作流线覆盖 parity 的 G1(WS-C)、G2(WS-A)、G7+G8(WS-B)、收口(WS-D),G6 静态部分随 WS-A(§2.4)。
**G3(GOT/PLT 密封)、G4(RELATIVE-into-RX)、G5(lazy-regions on ELF)不在本轮范围**(§6 R9)。

### 0.5 评审修订记录
**第 2 轮(9 条,评审方已核验 resolved)**: meta[76..80] 碰撞撤回改 ctx 136B;x86_64 探针显式 aarch64-only+MSVC 构建断言;
BrkScan v1 剔除;FDE 任务重立项(入口 CFI 论证+实测+限制声明);TAMPER 三通道判定;§7 改 e2e 产物路径;M-C0 中性 helper 抽取;R10 新增。

**第 3 轮(本轮,实读核验后落实)**:
| # | 评审点 | 核验证据(本轮实读) | 处置 |
|---|--------|--------------------|------|
| 3-1【阻塞】 | (a)"core 内 .bss static 幂等标志"不可实现且自相矛盾 | `xl_core.c:681-685` 契约原文"runtime state lives in an INITIALIZED data section so the injected image carries its bytes (zero) inline - .bss would need separate allocation";`:709-711` 同义;`:733-735` ".xlg state page is not writable until the G5 publish";`extract_elf_rel_machine`(`runtime_image.rs:328` 起)只收 .text*/.xlg 其余丢弃;且每次 dlopen 映射全新 blob,blob 内 static 必然随 dlclose 重置——(a) 声称解决 soak 冲突却依赖会被重置的存储,逻辑死结 | **删除 (a) 及其单测预期**;soak 冲突完全由 (b) 三歧消解规则解决(dlopen 重载→TRACEME EPERM→TracerPid==getppid()→良性);探针无需任何持久状态(probe_mask 每次激活由 stub 常量重建) |
| 3-2【阻塞】 | 探针交叉误报未消解:PtraceSelfAttach 自附成功后 TracerPid==getppid()≠0,TracerPidScan 朴素判定必误报,gate 5 构造性失败 | 逻辑推演成立;第 2 轮把消解规则只写在 PtraceSelfAttach 的 TRACEME 失败路径内 | **三歧消解上提为探针层共享纯函数**(TracerPidScan 与 PtraceSelfAttach 共用):`classify_tracerpid(tracer_pid, ppid) → {POLICY_DENY, BENIGN_SELF, HIT}`;fixture 补 `TracerPid==getppid()` 用例(§2.2.1);父进程即调试器的不可分辨性如实入 R5 |
| 3-3【轻微】 | `movz w9,#MASK` 编不出探针位图(id 17+ → 0x60000 超 imm16=0xFFFF) | `stub_aarch64.rs:59-64` movz imm16 字段确认 | **probe_mask 改为 Android 平台局部位图**(bit i = android_probes()[i],v1 三位 ≤7,单条 movz 必可编码);guard 提供 `android_probe_mask()` 映射并 **pack 期断言 mask≤0xFFFF**,超限时发射器回退 movz+movk 对(M-C1 已列 movk);core 侧以 `XL_PROBE_BIT_*` 局部常量消费,与全局 id 17+ 解耦(§2.2.3) |
| 3-4【轻微】 | cache 维护只挂 copy_rx,漏主解密写路径 | `xl_region_open`(`xl_core.c:849-869`)是主密封代码页解密写回(vp(RW)→aead_open 写 dst→final protect);copy_rx 是窃取字节恢复;两条都是 RX 写后取指 | cache sync 覆盖**两条路径**(§2.2.2) |
| 3-5【备注】 | stub.rs:1248 注释 "112 bytes" 过期;PE ctx 在 0x2FF8 大栈区,补零 ctx+128 安全 | `stub.rs:1248` 实读命中;`sub rsp,0x2FF8` `:308` | 与 `:1799-1800` 0xCC 同族,**一并列入过期注释修复**(§5.3) |

---

## 1. 里程碑与依赖

```
M-B0 环境自举(NDK 接线 + 双核构建)────────────┐
M-B1 OS-load 基线 harness(原生 victim 先行)──┤
                                              ├─> M-B2 打包产物 OS-load 门
M-A1 bionic 探针(aarch64 core)──> M-A2 ctx 扩容/装配/报告 ──┐│
M-C0 中性 helper 抽取 ─> M-C2 解码/提升 ─> M-C3 发射 ────────┼─> M-C4 钩子/选择器/报告
                (M-C3 功能门依赖 M-B1/B2 的 harness)────────┘
M-D1 差分+回归 → M-D2 文档收口 → M-D3 交接提交
```
- WS-B 先行:它是 WS-C 执行层验收的唯一通道(宿主 x86-64 Windows,aarch64 机器码无法本机执行)。
- WS-A 与 WS-C 并行;两者共同触碰 `stub_meta.rs`/`xl_core.c`/stub 发射器时,**ctx 扩容(M-A2)必须先于 M-C3 落地**。
- 每个里程碑有验收命令,全部本机可执行;不能本机执行的项按 `os_load.rs:1-11` 先例**显式 BLOCKED,不算通过**。

---

## 2. WS-A — bionic 反调试与策略对齐(parity G2 + G6 静态部分)

### 2.1 目标
ELF 产物具备 Android 语义的反调试探针集(v1 **仅 aarch64**,§2.2.2 决策),装配/报告/执行闭环;G6 静默开关显式化。
**诚实边界**: 主张"探针在干净进程上不误报(含探针间交叉场景)+ 解析/装配正确";**不**主张 attach 拦截实测(§6 R5)。

### 2.2 任务
1. **策略面** `crates/xenolith-guard/src/lib.rs`:
   - `Probe` 增加 Android 变体(id 17+): `TracerPidScan`、`PtraceSelfAttach`、`MapsScan`;**v1 不含 BrkScan**
     (解密前密封页是 0x90 填充,`elf.rs:508`,扫 BRK 无意义;正确设计=AEAD open 后自扫或扫 linker text,列 follow-up)。
   - 新增 `android_probes()`(对标 `max_probes()`,`lib.rs:39-58`)、**`android_probe_mask(&[Probe]) -> u32`**
     (平台局部位图映射:bit i = android_probes()[i];配 pack 期断言 mask≤0xFFFF,评审 3-3)、
     Android 分析模块哈希名单(`frida-agent.so`/`frida-gadget.so`/`libxposed_art.so`/`libsubstrate-dvm.so`/`libdlopen-hook.so`,
     复用 `module_name_hash`,`lib.rs:81-101`)。
   - **fixture 解析单测**(评审 3-2 要求的全矩阵):
     `TracerPid: 0` → 无 tracer;`TracerPid: <getppid()>` → BENIGN_SELF(自附残留,不判命中);`TracerPid: <其他 pid>` → HIT;
     maps 含/不含 frida 名;**加一条跨探针用例**:同一激活内 PtraceSelfAttach 成功后,TracerPidScan 以 `tracer_pid==getppid()`
     输入复跑必须仍判 BENIGN(gate 5 交叉场景的构造性回归)。
2. **core 执行面** `crates/xenolith-runtime/core/xl_core.c` —— **架构范围显式决策(评审点 2-2)**:
   - 探针实现整体包在 `#if defined(__aarch64__)`(NDK clang 构建的 aarch64 core 生效)。理由: 本机与 CI 的 x86_64 core 由宿主编译器产出
     ——Windows 宿主是 MSVC cl(`build.rs:22-40`,x64 无内联汇编,`__asm__` 直接 G1 panic;`_M_X64`≠`__x86_64__`,
     `#if defined(__x86_64__)` 则被静默跳过),且 build.rs 不产出 NDK x86_64-linux-android core(`runtime_image.rs:308 sysv_abi:false`)。
     **不做"x86_64 分支 syscall 内联汇编"**;NDK x86_64 core 接入 / ML64 .asm 列 follow-up。
   - syscall 封装(aarch64 `svc #0`,x8=nr): `openat(56)/read(63)/close(57)/ptrace(117)/getppid(172)`(aarch64 generic 表,均正确)。
     core `-ffreestanding` 且 stub 置 `load_library/get_proc=null`,**不得引入 libc**。
   - 探针在平台门(`xl_core.c:1053-1055`)之后、AEAD open 之前执行;命中 → 返回 0 走既有 fail 态。
   - **三歧消解为探针层共享纯函数(评审 3-1/3-2)**:
     `classify_tracerpid(uint32_t tracer_pid, uint32_t ppid) → {POLICY_DENY, BENIGN_SELF, HIT}`:
     `TracerPid==0` → 无 tracer;`==ppid()` → BENIGN_SELF(自附残留);其他 → HIT。
     - **TracerPidScan**: 读 `/proc/self/status`,解析 TracerPid 后交给 classify——0→通过,ppid→通过,其他→fail-closed;
     - **PtraceSelfAttach**: TRACEME 成功→保持(占据 tracer 槽,后续外部 PTRACE_ATTACH 被内核拒绝);TRACEME 失败→
       classify(当前 TracerPid): 0→环境/策略拒绝(Yama/SELinux,**不判命中**,记入 gate 观察位)、ppid→良性通过、其他→判命中;
     - **无幂等标志、无持久状态**(评审 3-1: 删除第 2 轮 (a) 项及关联单测预期)——每次激活从零执行,
       dlclose/dlopen 重载后的 TRACEME EPERM 由 classify 的 ppid 分支吸收,soak 门不误报;
     - 若未来确需 ELF 侧持久状态,必须走 `.xlg` INITIALIZED 节(`xl_core.c:681-685,709-711`)并解决其写权限
       (`:733-735` "not writable until the G5 publish")——记为 follow-up 设计约束,**v1 明确不做**;
     - 已知不可分辨性(如实入档): 自 spawn 起即为父进程的调试器(如 `gdb ./prog`)与自附残留同样呈现 TracerPid==getppid(),
       本设计选择放行该场景——tradeoff 写入 SUPPORT.md。
   - **aarch64 cache 维护(评审 3-4: 两条 RX 写路径全覆盖)**: `#if defined(__aarch64__)` 下新增
     `xl_cache_sync(addr,len)`(逐 64B 行 `DC CVAC + DSB + IC IVAU + DSB + ISB`),挂在:
     a) **`xl_region_open`(`xl_core.c:849-869`)** 的 `aead_open` 写回之后、final protect 之前(主密封代码页解密);
     b) **`copy_rx`** 的窃取字节恢复写之后(`xl_core_activate` gate≥1 调用)。
     `xl_region_seal`(`:873-907`)写回密文后置 PAGE_NOACCESS、永不被取指,**不需要** cache sync(注释注明,防后续误加)。
     转译层掩盖其正确性(§6 R10),真实 arm64 设备未验证——如实入档。
   - 单测: C 纯函数(classify/解析器)fixture 测;Windows/MSVC 与 NDK 双编译保持绿(探针代码在 MSVC 下被 `#if` 排除,
     **必须加构建断言测试确认 MSVC 构建仍成功**,防 #if 漂移挂掉 PE 路径)。
3. **装配与 ctx 扩容(评审点 2-1/2-6 联合修正 + 3-3)**:
   - `xl_core.c:55-75` XlHostCtx **追加字段到 136 字节**: `uint32_t probe_mask; uint32_t _pad2;`(偏移 128/132,既有字段偏移全部不动)。
     **不占用 88/96/104/112/116 任何槽**(112 是 load_library_ex 低半段,116 是其高半段)。
   - `stub_meta.rs`: ctx 常量新增 `CTX_PROBE_MASK=128`;**meta 80B 布局不动**(76..80 是 META_TABLE_RVA)。
   - **aarch64 stub** `stub_aarch64.rs`: `CTX_FRAME 0xC0→0xD0`(`:264`);probe_mask 以 pack 期常量直接编码进机器码——
     **平台局部位图**(guard `android_probe_mask()` 产出,v1 三位 ≤7)→ 单条 `movz w9, #MASK; str w9, [sp,#128]` 必可编码;
     guard 侧 pack 断言 mask≤0xFFFF,若未来位图超 16 位,发射器回退 `movz+movk` 对(M-C1 已列 movk)。
   - **x86_64 ELF stub** `stub.rs`: `sub rsp,0xB0→0xC0`(`:1712`/`:1760`),补写 `mov dword_ptr(rsp+0x20+128), 0`
     (x86_64-ELF 零探针但必须显式置零,core 读 probe_mask 不得吃栈垃圾);104/112 置零保持;顺带修过期 fail 注释(`:1799-1800`)。
   - **PE stub**(Win64 路径,`stub.rs:308` 0x2FF8 大栈区内构 ctx): 补零 ctx+128 字段(PE probe_mask=0,行为不变;
     `:1248` 注释的 "112 bytes" 一并修正为 136)。
   - **golden 帧尺寸断言**: 两条 stub 结构单测新增"ctx 预留 ≥136 且 saved-register 槽不被 struct tail 覆盖"显式断言
     (`stub.rs:1710` 事故注释,回归锁死)。
   - 装配逻辑(pack 侧): profile==Max → 全部 android_probes;否则 `TracerPidScan|PtraceSelfAttach`(对标 PE `lib.rs:1006-1009`)。
   - 报告: `elf.rs` PackReport 增加 `probes: Vec<String>`——**aarch64 填真实清单;x86_64-ELF 恒空并追加 note
     "anti-debug probes are aarch64-only in this release"**(禁止虚假透传)。
4. **G6 显式化** `elf.rs`(对齐 `:66-72` 风格): `protect_imports=true` → named error;`strict_constants=true` → 同款。
   `trace_diverge` 不在此拒(随 WS-C 落地)。

### 2.3 验收门
- `cargo test --manifest-path ... -p xenolith-guard -p xenolith-runtime -p xenolith-pack --lib` 全绿
  (含 classify 全矩阵 fixture、**TracerPid==getppid 交叉用例**、帧尺寸、MSVC 构建断言)。
- gate 5(aarch64 only): WS-B loadhost 以探针全开配置加载打包 .so,exit 0——该门即探针交叉误报的端到端回归
  (PtraceSelfAttach 首次自附后,同进程后续激活/TracerPidScan 不得误报)。
- `inspect --json`: aarch64 产物含 `"probes":[...]`;x86_64 产物 `"probes":[]` + aarch64-only note。
- 负样本: `pack <elf> --protect-imports` 非 0 且文案含 `protect-imports`(strict-constants 同)。

---

## 3. WS-B — 模拟器 x86_64 OS-load 验证基础设施(parity G7 + G8)

### 3.1 目标
把"从未验证"变成"本机实测门": 真实 bionic dlopen、导出差分、篡改拒绝、(转译)arm64 通道。CI 保持结构层(`android.yml:5-8`)。

### 3.2 任务
1. **M-B0 环境自举**(零安装): `ANDROID_NDK_HOME=<r27c 路径>`;`cargo build --manifest-path ... -p xenolith-cli --release`;
   以 aarch64 victim pack 成功证明 `XL_CORE_OBJ_AARCH64_PATH != NONE`(`runtime_image.rs:656-662` named-error 兜底)。
2. **M-B1 `scripts/android-e2e/`**:
   - `victim.c`: 构造函数 + `hello_add/hello_mul/hello_xor/hello_string`。
   - `loadhost.c`(对标 `xl-loadhost/src/main.rs`):
     - 模式1 OS-load: `dlopen` → `dlsym` → case 表调用 → 打印 `RESULT <name> <args> = <value>` → `dlclose` + `dl_iterate_phdr` 计数;
     - 模式2 TAMPER(评审 2-7): 判定面 = **SIGILL/SIGSEGV/SIGBUS handler(sigsetjmp)+ 看门狗超时 + 结果表逐项比对**三通道并联;
       "TAMPER-REFUSED" 充分条件 = 期望结果表未被忠实复现(陷阱、超时、错误返回值任一)——不主张"密封页必然陷阱"
       (0x90 在 aarch64 是合法 ADRP 链 `0x9090_9090`;x86_64 是 NOP 雪橇);首跑用手动翻转信封字节的 .so 实测两台模拟器表现后固化阈值;
     - 模式3 BLOB-ORACLE(供 WS-C): (blob,输入,期望) → mmap RW→写→mprotect RX→调用→比对,`ORACLE <case> PASS/FAIL`。
   - 编译: NDK clang `--target={x86_64,aarch64}-linux-android34`,脚本驱动,不进 cargo workspace。
3. **M-B2 `run_e2e.ps1`**(对标 `scripts/compat2/run_corpus.ps1`): 参数 `-Serial -Ndk -Abis -Pages`;
   五门: ① OS-load 差分(先原生基线后打包版) ② 模块计数 +1 ③ 篡改拒绝(负样本内置) ④ 10 次 dlopen/dlclose soak
   ⑤ 探针不误报(aarch64 only,含交叉场景: 同进程 10 次 soak 全程探针全开)。产物路径 `scripts/android-e2e/out/`。
   arm64 行带 `[via-ndk-translation]` 标记;设备不在线显式 fail(BLOCKED 语义)。**不得重启模拟器**。
4. CI 不新增模拟器门(workflow_dispatch 模拟器作业为可选 follow-up,不承诺)。

### 3.3 验收门
- `powershell -File scripts/android-e2e/run_e2e.ps1 -Serial emulator-5554 -Abis x86_64,aarch64 -Pages 4096,16384` 退出 0;
- `-Serial emulator-5556` 复跑通过;
- 门 3 负样本: 人为篡改判 TAMPER-REFUSED(门 1 正样本判 PASS,防永真/永假)。

---

## 4. WS-C — AArch64 函数虚拟化引擎(parity G1)

### 4.1 架构决策(复用边界如实表述)
- VM 无字节码无调度器(`superop.rs:1`),lift→IR→逐块唯一原生机器码。引擎 = AArch64 解码 → 复用 `IrModule` → 新 aarch64 后端发射。
- **复用边界**: 语义层全复用——`ir.rs`(SSA IR/eval oracle)、`mba.rs`(IR 级 u32 恒等式)、`lift.rs` 规则与 `forbidden_vm_rule`;
  **架构中性 helper 先抽取**(现为 `superop.rs` 文件私有: `used_vregs:286`、`alloc_map:242`、`schedule_stmts:361`、
  `block_stream:557`);**发射树完全并行重写**——`emit_inner:46`/`emit_block_body:139`/`emit_term:164`/`emit_shuffle:523`/
  `emit_opaque_junk_edge`/`emit_coin:204` 全绑 iced 类型且 `emit_coin` 读 Windows TEB/PEB(`:209-215`),
  aarch64 版独立实现(硬币源 `mrs x_, tpidr_el0 ^ sp`,EL0 可读)。IR 的 G4 x86 扩展(`ir.rs:59-72`)不进 aarch64 提升面。
- 值域纪律: IR 严格 32 位(`lift.rs:6-7`)→ 提升只接受 w 寄存器形态,x 寄存器运算 fail-closed。
- 编码器: `stub_aarch64.rs:113-243` 的 `Asm`/`Fixup` 抽出共享。

### 4.2 任务
1. **M-C0 中性 helper 抽取**: 新建 `crates/xenolith-vm/src/superop_common.rs`,上列纯函数原样迁出(不改语义,
   `superop.rs` 改 `use`);**既有 superop 测试逐字保留并通过**——纯迁移步,先落,给 M-C3 解耦。
2. **M-C1 共享汇编模块** `crates/xenolith-pack/src/aarch64_asm.rs`: 迁入 `stub_aarch64.rs` 的固定字/编码器/`Asm`/`FixupKind`/`Target`
   (pub(crate)),**`:529-657` golden 单测逐字保留**;新增编码器各配 golden 单测: `orr/eor`(reg)、`mul`、`lslv/lsrv/asrv`、
   `ubfm`、`movk/movn`(movk 兼作探针位图超 16 位时的回退,评审 3-3)、`ldrb/strb`、`adds/subs`、`mrs`(tpidr_el0)、
   **`patch_bl(blob, at_word, image_rva)`**(CallDirect 跨段 BL,±128MiB 越界报错,同 `Asm` Branch 语义 `:201-207`)。
3. **M-C2 解码/提升** `crates/xenolith-pack/src/lift_a64.rs`:
   - 手写 4 字节定长解码器(零新依赖);**v1 支持集**(全 w 形态): MOVZ/MOVK/MOVN、ADD/SUB(imm+reg)、ADDS/SUBS(仅喂 b.cond)、
     AND/ORR/EOR、MUL、LSL/LSR/ASR、CMP、LDR/STR(32/8-bit base±imm)、B、B.cond、CBZ/CBNZ、RET、NOP、函数内 BL→CallDirect。
   - **fail-closed 清单**(每类带指令字+偏移): x 寄存器 ALU/访存、LDP/STP、ADR/ADRP、CSEL/CCMP/CSET、浮点/SIMD 全类、
     LDXR/STXR、BLR/BR、TBZ/TBNZ、MRS(除 tpidr 类)、越 MAX_LIFT_BYTES=256、跨块 flags 复用。
   - **选择器**: `selection.rs` 增 SysV 分支——`.dynsym` 取 st_value(复用 `formats/elf.rs:815,1004` 先例),边界 `st_size`,
     `st_size==0` named-error 拒(不解析 .eh_frame);**IFUNC 符号前置拒绝**。
   - 禁令复用: `forbidden_vm_rule`(JNI ABI)、`profile==Fast 拒 vm-export`(`lib.rs:419-421`)。
4. **M-C3 发射后端** `crates/xenolith-vm/src/superop_a64.rs`: 完整并行发射重写(§4.1 边界),发射 AAPCS64:
   VREG_RAX→w0(返)、VREG_RCX→w0(参0)、VREG_RDX→w1(参1),`abi.rs` 增 `Abi::Aapcs64`;其余 VREG→x9-x15/x19-x25
   (被调保存者入 prologue stp/ldp);mba/junk/trace_diverge 双路径按 `superop.rs:86-123` 同构重写,`emit_coin_a64` 用
   `mrs tpidr_el0`;oracle=eval_ir case → WS-B BLOB-ORACLE 模拟器真执行(N≥50 覆盖全部支持类与 mba 家族)。
   产出挂接: `emit_elf_stub_aarch64` → `with_guests` 版,布局 `[code][guest blobs][core][meta 80B]`(meta 不扩容),
   thunk 区每函数固定 4 字节 `b <blob>`;`stub_meta.rs` 文档块同步。
5. **M-C4 钩子/门/报告**(对标 `apply_vm_hook`,`lib.rs:1703-1763`):
   - 导出重指向: `.dynsym` st_value → thunk RVA(新增 `formats::set_dynsym_value`;哈希链按名字;IFUNC 已前置拒绝)。
   - 内部改写: 原函数体首 4 字节 `b thunk`(±128MiB 越界 named-error),其余 `BRK #0` 填充;`<4 字节` 纯填充。
   - **unwind 任务重立项(评审 2-5)**: 不做输入镜像 .eh_frame 的 DWARF 解析/重写。v1 = a) 论证并实测"被改写函数入口的
     原 FDE 仍安全"(改写发生在入口 4 字节,thunk 地址仍在原 FDE PC 区间内,入口处 CFI 处于 initial state,
     常规 unwind 可正确回溯;模拟器带 unwind victim 实测);b) **声明限制**: VM guest blob 无 FDE(追加 PT_LOAD 不在
     .eh_frame 覆盖内,stub 自含 eh_frame 只覆盖 stub 自身,`elf.rs:304-317`)→ 不得经虚拟化帧做异常展开;
     JNI 边界不受影响(`forbidden_vm_rule` 保 JNI native)。写入 SUPPORT.md 不主张项。
   - 门更新 `elf.rs:143-158`: aarch64 放行;**x86_64-ELF 继续拒**,文案精确化("SysV x86-64 ELF lift not implemented;
     aarch64 is supported in this release")。
   - 报告 `elf.rs:565-567`: `vm_functions`/`export_surface`/coverage 真实值;`trace_diverge` 直通。
   - TUI/CLI 文案 `tui/mod.rs:569,614-618`、`tui/render.rs:433` 同步。
6. **CI**: android.yml 增 aarch64 `--vm-export hello_add` 打包 → inspect 断言 `vm_functions==1` + readelf 断言 dynsym st_value
   落追加 PT_LOAD;x86_64 `--vm-export` 非 0 且文案含 "aarch64 is supported"(负样本门,防伪装)。

### 4.3 验收门
- L1(宿主): `cargo test -p xenolith-pack -p xenolith-vm` —— golden + fail-closed 矩阵 + 选择器边界 + oracle 一致性。
- L2(模拟器): ORACLE 门 100% PASS(经 ndk_translation 真执行发射码)。
- L3(模拟器): `--vm-export hello_add,hello_mul` → 门 1 差分一致;篡改门 TAMPER-REFUSED;`vm_functions==2`。
- L4: CI 新步骤绿。

---

## 5. WS-D — 差分验证 + 回归 + 文档收口 + 交接提交

### 5.1 差分
`scripts/android-e2e/run_diff.ps1`: 每 ABI/页组合,同一 case 表逐行 diff 原生 victim 与打包 .so(loadhost RESULT 行);
分类结构对标 `scripts/compat2/classification.json`;语料: `samples/hello-elf` + e2e victim + vm-export 变体。
x86_64 全原生;**aarch64 行显式标注转译层**。

### 5.2 回归
- `cargo test --manifest-path E:/XiangMu/Xenolith-android/Cargo.toml --workspace`(Windows host 上 PE os_load 系列实跑)。
- MSVC 构建断言(§2.2.2)作为 PE 路径回归哨兵;fuzz 目标编译期回归即可。

### 5.3 文档收口(只主张实测过的)
- `docs/SUPPORT.md:36-37`: x86_64 → "OS-load verified on API 34 x86_64 emulator (dlopen+diff+tamper+soak, scripts/android-e2e)";
  arm64 → "OS-load verified **via ndk_translation** on x86_64 emulator; native-arm64 device remains an open gate;
  decryption write paths include aarch64 cache maintenance (DC/IC/ISB), correctness on real silicon unverified"。
- `docs/SUPPORT.md:190-195`: vm-export aarch64 支持集与 fail-closed 清单原文;x86_64-ELF 仍拒;guard 探针清单
  (**aarch64-only** + 不主张 attach 拦截实测 + **TracerPid==getppid() 放行的父进程调试器不可分辨 tradeoff**);
  **不得经虚拟化帧展开异常**;G3/G4/G5 三缺口明示保留;BrkScan/NDK-x86_64-core/DWARF-FDE 重写/ELF 侧持久状态
  (.xlg INITIALIZED+写权限约束)列 follow-up。
- 顺带修复过期注释(评审 3-5): `stub.rs:1799-1800`("0xCC"→0x90 表述)与 `stub.rs:1248`("112 bytes"→136)。
- README(工作树)不动。

### 5.4 交接提交(实现代理不 commit)
提交序列建议: ① M-C0 helper 抽取(纯迁移) ② aarch64_asm 抽取(纯迁移) ③ lift_a64+selection ④ superop_a64+stub guests
⑤ 钩子/报告/门 ⑥ ctx 扩容+guard/core 探针 ⑦ e2e 脚本+CI ⑧ SUPPORT.md+注释修复。
提交前清单: `git -C E:/XiangMu/Xenolith-android status` 无意外文件;README 脏改交集成裁决;全 workspace 测试 + run_e2e.ps1 最终复跑贴输出。

---

## 6. 风险登记(诚实纪律)
- **R1 ndk_translation 保真度(最高)**: VM 发射码/BTI/RWX 解密窗口在转译层从未验证(`elf.rs:612-616`)。缓解: x86_64 原生通道是首要主张;
  若转译层跑不起发射码,aarch64 VM 主张降级为 L1+结构断言并如实入档,不伪装 L2/L3。
- **R2 arm64 ELF 进程从未实测执行**: M-B1 首跑即验证;不可用则 aarch64 OS-load 门显式 BLOCKED。
- **R3 篡改语义非"必然陷阱"**: 0x90 在 aarch64 是合法 ADRP 链、x86_64 是 NOP 雪橇(`elf.rs:508`;`stub.rs:1799-1800` 注释过期);
  loadhost 判定面=陷阱∨超时∨结果表失配三通道,先实测后固化阈值。
- **R4 st_value 重指向副作用**: 符号版本化/ifunc/.eh_frame 联动;以 IFUNC 前置拒绝+入口 CFI 论证实测+readelf 断言收口。
- **R5 attach 拦截不可 e2e 实测 + 两个不可分辨场景**: (a) 模拟器 shell 域 ptrace SELinux 策略未测——classify 的
  POLICY_DENY 分支保证不误报但保护价值降级;(b) **自 spawn 即为父进程的调试器(gdb ./prog 类)与自附残留都呈现
  TracerPid==getppid(),本设计放行该场景**(评审 3-2 认可的 tradeoff,如实入档 SUPPORT.md)。
- **R6 ctx 槽位/帧尺寸回归**: 候选槽 116 已证伪(xl_core.c:55-75);扩容 136B 动两条 stub 栈帧预留(0xC0→0xD0、0xB0→0xC0),
  `stub.rs:1710` 记载过 struct-tail 事故——golden 帧尺寸断言锁死;PE 侧 ctx 在 0x2FF8 大栈区(`stub.rs:308`),补零安全。
- **R7 手写解码器**: 支持集外编码必须默认拒绝;fail-closed 矩阵是主防线。
- **R8 共享基础设施**: 模拟器不重启;NDK 用现成 r27c;README 脏改不触碰。
- **R9 范围纪律**: G3/G4/G5 不在本轮;对应开关 ELF 侧显式拒绝防"看起来支持";x86_64-ELF vm-export 继续 fail-closed;
  探针 aarch64-only 且报告如实。
- **R10 aarch64 I/D-cache 维护**: 解密写后执行需 DC CVAC+DSB+IC IVAU+DSB+ISB,**两条 RX 写路径
  (`xl_region_open` 主解密 + `copy_rx`)都已挂任务**(评审 3-4);转译层大概率掩盖其正确性——本地只能验证
  "不破坏转译路径",真实 arm64 硅片未验证,如实入档。
- **R11 MSVC/双编译面**: `#if defined(__aarch64__)` 代码块必须保持 MSVC 构建绿(build.rs:22-40 无内联汇编能力),
  配构建断言测试,否则 PE 路径整体回归。
- **R12 探针无持久状态的设计边界(评审 3-1)**: v1 探针刻意无任何 blob 内持久化(.bss 不可携带/`.xlg` 不可写,`xl_core.c:681-685,733-735`),
  代价是每次激活重复执行探针(开销可忽略)且依赖 classify 规则吸收重载场景——若未来需要持久化,走 `.xlg` INITIALIZED
  节+解决写权限,列为 follow-up 设计约束。

## 7. 验收命令汇总(逐条可复制;标注"先跑脚本"的命令依赖 e2e 产物)
```
# 环境
adb devices -l
export ANDROID_NDK_HOME="E:/XiangMu/JavaShroud-public/.apk-compat/android-sdk/ndk/27.2.12479018"
# 构建+全测试
cargo build --manifest-path E:/XiangMu/Xenolith-android/Cargo.toml -p xenolith-cli --release
cargo test  --manifest-path E:/XiangMu/Xenolith-android/Cargo.toml --workspace
# OS-load 门(WS-B;同时产出 scripts/android-e2e/out/ 的 victim 产物)
powershell -File scripts/android-e2e/run_e2e.ps1 -Serial emulator-5554 -Abis x86_64,aarch64 -Pages 4096,16384
# VM 门(WS-C,L3;victim 先由上一条脚本生成)
target/release/xenolith pack scripts/android-e2e/out/libvictim-aarch64-4096.so --vm-export hello_add,hello_mul -o out/e2e/vm.xl.so
target/release/xenolith inspect out/e2e/vm.xl.so --json
# 负样本(防伪装;victim 路径来自 e2e 脚本产物,不引用 CI-only 的 target/android-ci/)
target/release/xenolith pack scripts/android-e2e/out/libvictim-x86_64-4096.so --vm-export hello_add -o out/e2e/x64.xl.so   # 须非0,"aarch64 is supported"
target/release/xenolith pack samples/hello-elf/libhello-elf.so --protect-imports -o out/e2e/pi.xl.so                        # 须非0,named error
```
