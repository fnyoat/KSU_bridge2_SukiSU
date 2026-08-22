# KSU_bridge2_SukiSU — KSU-Next × SukiSU 桥接内核模块

**版本：1.0**

## 简介

`sukisu_bridge.ko` 是一个 LKM（可加载内核模块）垫片，作用是让 **SukiSU 系管理器**
（SukiSU-Ultra `com.sukisu.ultra`、ReSukiSU、mmrl 等）能在内核实际运行
**KernelSU-Next**（GKI 5.10 / ARM64）的设备上正常工作。

官方 SukiSU manager 走自己的 uapi 协议（特定的 ioctl 命令号、776 字节的
`app_profile`、version=4），而内核里的 KSU-Next 实现协议不同（784 字节布局、
不同内部接口）。本模块在 syscall 分发器 / ioctl 入口拦截 manager 的请求，做
**翻译 + 身份伪装**，再按 SukiSU 协议回给 manager，让官方 manager 在 KSU-Next
内核上以 **built-in（GKI 内置）** 模式工作。

**纯 .ko 方案**：不改 manager 前端、不改内核、不碰 KSU-Next 的写入接口。

> 工作原理（双通道拦截、身份伪装、命令处理、安全模型等）见 `PRINCIPLE.md`，
> 本 README 只负责使用与开发指南。

## ⚠️ 警告

- **本内核模块无兼容保障**，仅在Redmi K60真机(5.10.260-android12-Wild内核KernelSU-Next 33234-2，SukiSU Ultra管理器40796，ReSukiSU管理器262405/2)上测试成功。
- **Root 权限千万不能乱给**：任何拥有Root权限的应用都可以获得本模块的服务。
- **不要给已获得 root 权限的应用安装 Xposed / 模块化框架**，会造成**权限间接泄露**，模块会通过篡改应用的方式执行任意代码。
- **不要强行在未测试兼容的设备上自动加载模块**：本模块依赖特定 GKI 5.10 内核的符号与位定义，不兼容环境下加载理论上会导致panic。请先手动加载验证，再考虑持久化，否则可能会陷入**循环重启（bootloop）**。**矩阵内未覆盖的内核（厂商定制 / 自编译 / 非标准分支）必须按开发者指南自行构建内核专属的产物**，不要直接使用 CI 打包的模块包。
- **不要加载任何不信任的内核模块**，包括本模块，它和Root权限泄露的后果没有多大区别。确保你要加载的模块值得信任，不要从其他不可信渠道下载本模块，否则可能包含恶意程序。
- **这个内核模块并不安全**，它肯定千疮百孔，所以你即使什么都做好了，也可能会有恶意程序轻松黑掉你的手机
- **作者不对此项目造成的任何损失负责**，你知道它很危险，这整个章节都在强调，你已经得到警告了。

## 核心能力

加载后 SukiSU 系 manager 可以正常使用(管理器需要获得root权限)：

- **进入主界面**：`becomeManager` 提权、版本/信息伪装，工作状态显示Built-in；
- **超级用户页面**：app profile 列表可读（GET 查询内核 + 缓存），授权 / 撤销
  **真实写入 KSU-Next 内核并持久化到 `.allowlist`**（写穿透，重启后仍在）；
- **su 提权**：`prctl(0xDEADBEEF, GRANT_ROOT)` 通道 + SELinux domain 切换
  （`u:r:ksu:s0`），`su` / `getRootShell().isRoot` 通过；
- **模块查看 / feature**：提权进程可读 `/data/adb/modules`；feature 开关
  （SU Log / ADB Root / SELinux Hide 等）状态可读可切换，UI 不灰显；
  **GET 返回内核真实状态**（进程上下文直读 `ksu_get_feature`），本地表仅作
  原子路径兜底并在 init 时用内核真实状态 seed，避免 manager 误读"全 0"。

## 安全要点

- **统一授权门**：仅服务 `is_target_app()`（root + escalated-cred / 被加冕
  manager）或内核实时授权 `__ksu_is_allow_uid(uid)` 的进程；硬依赖解析失败时
  **拒绝加载**；
- **SET 写穿透 + 保护**：`SET_APP_PROFILE` 真实写入 KSU-Next（授权/撤销生效并
  持久化），授权进程即可写穿透（已授权 app 本身能 su，写 allow_list 不新增
  权限）；对原生加冕 manager uid 的**撤销永不写入**——`com.rifsxd.ksunext`
  不可能被 SukiSU 撤销；
- **su_compat 自愈**：加载时若检测到内核 su_compat 被误关（此前 manager 的
  startup sync 曾把它写 0），主动恢复为 ON——su(1)/LSPosed 依赖它；
  **这不是提权**：su_compat 只决定"已在 allowlist 的 app 能否 su"，内核
  `ksu_handle_execve_sucompat` 仍强制 `ksu_is_allow_uid_for_current()` 校验；
- **握手 / close 均带身份门**：未授权进程拿不到 fd，`close` 保护只作用于握手所有者。

详见 `PRINCIPLE.md` §14（安全模型与加固）。

## 兼容性

### 目标兼容范围

本模块面向 **SukiSU 系 manager + KSU 系内核** 的桥接场景，兼容方向自顶向下：

| 层 | 目标范围 | 说明 |
|---|---|---|
| manager 层 | SukiSU-Ultra `com.sukisu.ultra`、ReSukiSU、mmrl 等 | 各分支/版本 manager uid 各不相同，模块**不锁定 uid**，以"root + escalated-cred / 内核实时授权"判定服务对象 |
| 协议层 | SukiSU uapi | ioctl 命令号、776B `app_profile`、ver 4（模块负责与 KSU-Next 784B 布局互译） |
| 内核层 | **KernelSU-Next（验证目标）** → 兼容 SukiSU 内核 fork → 兼容 KernelSU | 三者 API 同源（`anon_ksu_ioctl` / `ksu_*_profile` / `__ksu_is_allow_uid` / `ksu_set_feature`），符号名与签名略有差异，见下 |

### 版本差异的适配手段

模块大部分内核接口通过 kallsyms 运行时解析，并暴露模块参数覆盖符号名：

| 模块参数 | 作用 | 换内核/分支时要改 |
|---|---|---|
| `target` | KSU 内核 supercall 分发器（`anon_ksu_ioctl$<md5>`） | **必须**（kCFI 哈希名随构建变化） |
| `svc_symbol` | syscall 分发器符号（`el0_svc_common` / `invoke_syscall` / `el0_svc_handler` / `do_el0_svc`） | 视内核而定 |
| `prctl_symbol` / `reboot_symbol` | prctl / reboot syscall 符号 | 视内核而定 |
| `manager_uid` | 伪装用 uid（默认 `com.rifsxd.ksunext`） | 换原生管理器时 |

硬依赖（解析失败**拒绝加载**）：`__ksu_is_allow_uid`、`anon_ksu_ioctl`、`task_work_add`、cred 辅助函数。

### 容易被忽视的兼容问题

1. **KernelSU API 签名**（最常踩）：`ksu_get_app_profile` 在不同 KSU / KSU-Next 版本的签名不同——
   本模块按 `struct app_profile *(*)(uid_t)` + 配套 `ksu_put_app_profile()` 的模式调用（历史曾修正）；
   若目标内核是其他签名（如调用方自行 `kfree`、无 put 函数、或输出参数形式），GET 会读到错数据甚至崩溃，
   需同步调整调用方式。同理 `ksu_set_app_profile` 有多个候选符号名
   （`ksu_set_app_profile` / `ksu_profile_set` / `set_app_profile`），`ksu_set_feature` 按 `(u32, u64)` 签名解析。
2. **`anon_ksu_ioctl` 是 kCFI 静态函数**：磁盘符号名是 `anon_ksu_ioctl$<md5>`，**裸名永远匹配不上**，
   且每个构建的哈希不同——必须用 `target=` 传完整的哈希名，否则 `insmod` 直接 `-ENOENT`。
3. **SukiSU uapi 命令号会随分支翻转**：历史踩坑——fork 版是 `SET=11/GET=12`、正式版**正好相反**
   （`GET=11/SET=12`）。更换 SukiSU 分支/版本后必须重新核对 ioctl nr 11/12 的语义。
4. **syscall 分发器符号带 LLVM 哈希后缀**：GKI 构建的符号可能是 `el0_svc_common.llvm.<hash>`，
   候选符号表兜底 + `svc_symbol` 参数可覆盖；若分发器符号完全缺失，prctl 拦截退化（授权由内核 KSU
   原生处理，行为变化而非崩溃）。
5. **握手魔数硬编码**：`KSU_INSTALL_MAGIC1=0xDEADBEEF` / `MAGIC2=0xCAFEBABE`（备用 `0xFAFAFAFA`）。
   KSU 系内核（含 KSU-Next、SukiSU fork）沿用这套魔数；若目标内核魔数不同，reboot 握手失效、fd 无法安装。
6. **提权识别用 escalated-cred 指针注册表**（不再用 task flag + `for_each_thread`，
   后者在 manager 启动动画期间与 KSU-Next 的任务遍历并发会 NULL deref panic）。
   注册表按 `current_cred()` 指针识别，不依赖内核 task_struct 布局。
7. **`setup_selinux` 是 static 符号**：缺失不致命（提权仍工作），但进程留在原 SELinux 域，
   root 态读 `/data/adb/modules` 等会被 avc 拒绝——表现为"模块列表/feature 全空"。
8. **`ioctl(-1, ...)` 返回值因内核而异**：本设备实测返回 0 但缓冲为空（NPE 根源）；部分内核返回
   `-EBADF`。双通道逻辑同时兼容两种情况，但真机行为不同时排查方向也不同。
9. **GET_FEATURE 必须反映内核真实状态**：只读本地 `g_features` 表（初始全 0）会让 manager
   把 su_compat 等误读为关闭，其 startup sync 会把"关"写回内核，导致 su(1)/LSPosed 失效。
   模块在进程上下文直读 `ksu_get_feature`，init 时 seed 本地表；fd<0 原子路径（kretprobe
   ret handler 不能调 mutex）才用本地表兜底。改动 GET 逻辑时务必保持"真实优先、本地兜底"。

## 已知边界

- SukiSU manager **必须先被授权**（进入 `.allowlist`），模块才会
  服务它；
- SET **写穿透**：manager 里的授权/撤销真实写入 KSU-Next 内核并持久化
  `.allowlist`（重启后仍在）；授权进程均可写穿透（已授权 app 能 su 即可改
  文件，不新增权限）；原生 `com.rifsxd.ksunext` 的授权**不可能被 SukiSU
  撤销**；
- manager 单个 app 授权后列表需手动下拉刷新（前端不回写列表缓存，属 manager 自身
  行为，非本模块问题）。

## 性能

- 分发器 kretprobe 每 syscall 触发，但非目标 syscall 的 entry handler **返回非 0**
  跳过 return probe 安装，只付一次轻量入口陷入，返回路径零开销；
- 整机 CPU 增量约 1% 量级，常驻内存约 800KB（两个 kretprobe 实例池
  2048 × ~200B × 2）。

## 开发者指南

### 环境准备

| 依赖 | 说明 |
|---|---|
| GKI 内核树 | 设备内核对应的内核源码树（GKI 5.10 / Android 12），通过环境变量 `KDIR` 指定 |
| NDK 工具链 | **必须与目标内核同代 clang**（如 5.10 → r23b），见下方"工具链版本" |
| `make` | 构建宿主自带（Linux/macOS 自带；Windows 用 MSYS2） |
| uapi 头 | `include/uapi/`，`Makefile` 通过 `ccflags-y := -I$(src)/include` 引用，无需额外安装 |

> **工具链版本（关键！）**：设备内核启用 kCFI（`CONFIG_CFI_CLANG=y`），模块必须用
> **与目标内核同代 clang** 编译，否则 kCFI 类型哈希与内核不一致——insmod 阶段可能
> PAN，rmmod 阶段必报 `CFI failure (target: cleanup_module)` 并 panic。NDK 版本按
> 内核分支映射（与 CI 矩阵一致）：5.4→r21e（clang 11）、5.10→r23b（clang 12.0.8，
> 设备验证目标）、5.15→r25b（clang 14）、6.1→r27（clang 17）、6.6→r28（clang 18）。
> 用错版本（例如 r23b 编 6.1）insmod 阶段就可能 PAN。

### 构建

脚本通过环境变量指定路径（未设置时使用脚本内默认值，可在任意位置运行）：

```bash
# 指定内核树与 NDK（路径替换为你自己的）
export KDIR=/path/to/kernel-tree
export NDK=/path/to/android-ndk-r23b
bash build_mod.sh
```

> **产物是内核专属的**：CI 自动构建只覆盖标准 GKI 分支矩阵（见"发布与安装"），
> 每个 `.ko` 只对**对应内核**有效——kCFI 类型哈希（同代 clang）、`task_struct`
> 布局、KSU 符号哈希都是内核专属的。**厂商定制 / 自编译 / 非矩阵内的内核必须用
> 本小节的方式自行构建专属产物**：NDK 按矩阵映射选同代版本（5.4→r21e、
> 5.10→r23b、5.15→r25b、6.1→r27、6.6→r28），并按目标内核实际的
> `anon_ksu_ioctl$<md5>` 传 `target=`，不能直接使用其他内核的 CI 产物。

- 脚本自动适配宿主平台：Linux → `linux-x86_64`、macOS → `darwin-x86_64`、
  Windows（MSYS2）→ `windows-x86_64` 的 NDK prebuilt 子目录；
- 产物：`sukisu_bridge.ko`；
- 本地构建日志写入 `build_mod.log`（脚本内部自动重定向）；
  设了 `GITHUB_ACTIONS` 时（CI）直接输出到 stdout；
- 构建成功以 `BUILD DONE` 为准；失败时看 `build_mod.log` / action log 的报错。

### 安装与验证

```bash
adb push sukisu_bridge.ko /data/local/tmp/
adb shell su -c "insmod /data/local/tmp/sukisu_bridge.ko"
```

加载后逐项验证：

1. manager 进入主界面**不崩溃**（历史 NPE 回归点）；
2. 关于页显示 **工作状态：built-in**；
3. 超级用户页面能读到列表、能授权/撤销；
4. `su` 提权成功（root shell 可执行）；
5. 模块列表 / feature 可读，feature 开关可切换**且不 panic**（历史 panic 回归点）；
6. `su -c dmesg | grep 'seed feature fid=0'` 应为 `val=1`（su_compat 真实开启，
   防 manager 误读全 0 把 su(1)/LSPosed 弄挂）；
7. `rmmod sukisu_bridge` 后原生 KSU-Next manager 完全正常。

### 调试

- 关注关键字：`sukisu_bridge`（功能日志）、`panic` / `CFI failure`（稳定性）、
  `avc: denied`（SELinux 域问题）、`access_ok` 相关 Data Abort（PAN 问题）；

### 代码入口速览（开发者导航）

主源码只有一个文件：`sukisu_bridge.c`（约 3600 行）。主要功能区：

| 区域 | 符号 / 位置 | 作用 |
|---|---|---|
| 拦截通道 | `svc_entry_handler` / `prctl_entry_handler` / `ioctl_entry_handler` | 各入口 handler，负责过滤目标 syscall |
| 命令模拟 | `emulate_sukisu_prctl` / `emulate_sukisu_ioctl` | SukiSU 控制面命令处理与回填 |
| 提权 | `bridge_escape_to_root` / `bridge_queue_become_root` | root 提权 + SELinux 域切换 |
| 授权门 | `sukisu_bridge_authorized` / `is_target_app` | 统一授权判定 |
| 符号解析 | init 中的 `kallsyms_lookup` 系列 | 运行时解析 KSU-Next 内核符号 |
| fd 保护 | `reboot_kp` / `close_kp` | 握手 fd 安装与 close 保护 |

**扩展新命令**：在 `emulate_sukisu_prctl` / `emulate_sukisu_ioctl` 按既有模式加 case，
并确认已加入身份命令白名单（`is_sukisu_identity_nr` / prctl 白名单）。**写穿透
原则**：凡调用 KSU-Next 写接口（`ksu_set_app_profile` / `ksu_set_feature`）必须
经 task_work（进程上下文）排队，且必须通过 CFI-exempt wrapper（`ksu_*_call`），
禁止在 kretprobe ret handler（原子上下文）直接调用。

### 常见问题（FAQ）

| 现象 | 原因与排查 |
|---|---|
| 构建失败 | 检查 `KDIR` / `NDK` 路径；MSYS2 环境问题看 `build_mod.log` |
| `insmod` 返回 `-ENOENT` | 硬依赖符号（如 `__ksu_is_allow_uid`）解析失败，模块安全拒绝加载 |
| manager 进主界面崩溃 / NPE | 双通道拦截失效；检查 `el0_svc_common` 等符号是否存在、dmesg 有无异常 |
| 授权不生效 | manager 未被原生 KSU-Next 授权；或走的是原生 fd 通道未被模块服务 |
| 模块列表为空 | SELinux 域切换失败（`avc: denied`）；检查 `setup_selinux` 符号解析 |
| 原生管理器异常 | 正常情况不可能（对原生 manager 的 deny 已被模块吞掉）；若出现需立即 `rmmod` 并在 dmesg 中检查 `SET protect native manager` 是否出现 |

## 模块参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `svc_symbol` | `el0_svc_common` | syscall 分发器符号（KSU-Next prctl inline hook 之上） |
| `prctl_symbol` | `__arm64_sys_prctl` | prctl syscall 符号（兜底通道） |
| `manager_uid` | `10310` | 伪装用 uid（默认 `com.rifsxd.ksunext` 的 uid） |

## 发布与安装（KSU 模块）

每次 push / PR，GitHub Actions 会自动为多个 GKI 内核分支各编译一个
`KSU_bridge2_SukiSU-<分支>.zip`（KernelSU 模块格式），
见 `.github/workflows/build.yml`。

模块包结构：

```
KSU_bridge2_SukiSU-android12-5.10.zip
├── module.prop     # id=ksu_bridge2_sukiSU_5_10 / author=fnyoat / 内核标识
├── service.sh      # 开机时自动检查内核兼容，匹配才 insmod（不匹配跳过，绝不 panic）
└── sukisu_bridge.ko
```

**安装**（在 KernelSU / KSU-Next 管理器里刷入 zip，或解压到
`/data/adb/modules/`）：开机后 `service.sh` 读取 `uname -r`，必须包含模块包的
内核分支标识才执行 insmod，否则静默跳过——**不同内核的模块包不会互伤，装错
最多是模块不生效，不会 panic**。

**支持的矩阵**（在 `.github/workflows/build.yml` 的 `matrix` 中维护）：

| 分支 | 模块 zip |
|---|---|
| `android11-5.4` | `KSU_bridge2_SukiSU-android11-5.4.zip` |
| `android12-5.10`（设备验证） | `KSU_bridge2_SukiSU-android12-5.10.zip` |
| `android13-5.10` | `KSU_bridge2_SukiSU-android13-5.10.zip` |
| `android13-5.15` | `KSU_bridge2_SukiSU-android13-5.15.zip` |
| `android14-5.15` | `KSU_bridge2_SukiSU-android14-5.15.zip` |
| `android14-6.1` | `KSU_bridge2_SukiSU-android14-6.1.zip` |
| `android15-6.6` | `KSU_bridge2_SukiSU-android15-6.6.zip` |

新增内核：在 `matrix.kernel` 加一项即可；模块内的内核兼容检查由 `build_module.sh`
自动写入分支标识。

> 上述产物只对标准 GKI 分支有效，**矩阵外 / 厂商定制 / 自编译内核请按开发者指南
> 自行构建专属产物**（见"开发者指南 → 构建"）。

## 目录结构

```
KSU_bridge2_SukiSU/
├── sukisu_bridge.c      # 主源码（约 3600 行）
├── Makefile             # 内核模块构建（引用 include/uapi 头）
├── build_mod.sh         # 交叉编译 .ko（KDIR/NDK 环境变量可覆盖）
├── build_module.sh      # 把 .ko 打包成 KSU 模块 zip（自动生成 module.prop / service.sh）
├── .github/workflows/build.yml  # CI：多内核矩阵构建 + 打包 + 上传 artifact
├── device.config        # 设备内核 .config 参考快照
├── PRINCIPLE.md         # 工作原理 / 修复历史 / 安全模型（原理文档）
└── include/uapi/        # SukiSU uapi 协议头
```

## 注意事项

- 设备内核需存在 `el0_svc_common` / `invoke_syscall` 等符号（kretprobe 依赖），
  否则 prctl 拦截不生效，授权将直接由内核 KSU 处理；
- 加载后用 `su -c dmesg` 检查日志，应无 panic / CFI failure；

## 版本历史

- **1.0**：项目完成

## 后记
- 这个项目的代码完全是AI完成的，作者只负责指点和调试，所以我基本什么都不懂。
- 我立项的原因是我的主力机原本是SukiSu LKM，后来刷了某个融合的GKI，我喜欢SukiSu管理器但是又不想失去这个GKI的独有功能(上游仓库是私密的)，所以我就想让SukiSu可以继续管理。
- 开发过程很曲折，实现很困难导致方案摇摆不定，方案从KO到KPM再到Zygisk+Xposed，又到KPM又到KO。我没法花时间在我完全无涉足的领域上，所以我让AI去做，原本以为只需要3天，结果居然浪费了我11天(我一般10点起床熬夜到2点调试这个)，设备panic要等时间重启，开发者设置里的错误报告要等时间导出，中途AI还把构建用资料全删了(构建无法正常工作的期间又导致它乱改代码把原来的逻辑炸了)，我知道我的工作流纯粹是咎由自取，我对时间的估计是完全错误的(我本来以为这虽然傻逼但持续不了多久)，所以确实是自讨苦吃。
- 总的来说，这个项目够诡异了，我不会刻意花时间继续维护它。
- ~~KernelSU强兼SukiSU~~