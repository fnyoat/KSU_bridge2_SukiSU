# KSU_bridge2_SukiSU 工作原理详解

> 给人类读者的一段话：可以把这个模块想象成一名**翻译官兼替身**。内核系统说
> "KSU-Next 方言"，SukiSU 管理器说"SukiSU 方言"，两者同源但词汇和语法不同。
> 模块站在系统调用这一层，把管理器发来的"话"逐条接住、翻译成 KSU-Next 能执行的
> 形式，再替 KSU-Next 用管理器期望的 SukiSU 口吻回答，同时绝不改写 KSU-Next 自己
> 的账本（`.allowlist`）。下面所有小节都是这套机制的精确定义。

> 版本 1.0 · 纯内核模块（LKM `.ko`）方案 · 不改动 SukiSU-Ultra manager 前端

---

## 0. 阅读约定与术语表

本文档描述 `sukisu_bridge.c` 的完整工作原理。文档中的每个函数名、全局变量、
常量、寄存器编号均与源码一一对应，可直接在源码中搜索验证。

### 0.1 术语定义

| 术语 | 定义 |
|---|---|
| manager | SukiSU 系管理器应用（`com.sukisu.ultra`、ReSukiSU、mmrl 等），运行在用户态，与内核通过本文 §2 的两条通道通信 |
| KSU-Next | 内核内置的 KernelSU-Next 实现。提供 `anon_ksu_ioctl` 匿名 fd 接口，但**不实现** SukiSU 的握手与控制面语义 |
| bridge / 本模块 | `sukisu_bridge.ko`，加载进内核的 LKM。以下称"模块" |
| pt_regs | ARM64 的 `struct pt_regs`，保存用户态寄存器现场。ARM64 系统调用进入内核时，内核把用户寄存器保存在当前任务栈上的 pt_regs 中。`regs[0]`~`regs[4]` 对应 x0~x4，`regs[8]` 对应 x8（ARM64 系统调用号） |
| kprobe | 内核动态插桩。在目标函数入口地址替换指令为断点，命中时执行 `pre_handler` |
| kretprobe | kprobe 的返回探针变体。entry 处命中执行 `entry_handler`；若 entry_handler 返回 0，框架把函数返回地址替换为 trampoline，函数返回时再执行 `handler`（ret handler）。若 entry_handler 返回非 0，**不安装**返回探针 |
| task_work | 内核把一段延迟工作挂到 `current` 任务上，该任务从内核态返回用户态之前执行（进程上下文，可睡眠） |
| CFI / kCFI | 内核控制流完整性检查。间接调用前校验目标地址的类型哈希（`.cfi_jt` 跳表） |
| cred | `struct cred`：进程凭据，含 uid/gid/caps/SELinux SID 等 |
| supercall | SukiSU 定义的超级调用，即 `prctl(0xDEADBEEF, cmd, ...)` |

### 0.2 贯穿全文的关键不变量

1. **写穿透但保护原生加冕管理器**：`SET_APP_PROFILE` 经 task_work 真实写入
   KSU-Next `allow_list`（并持久化 `.allowlist`），SukiSU manager 的授权/撤销
   真实生效；**唯一例外**：对原生加冕 manager uid（`com.rifsxd.ksunext`）的
   deny 永不写入内核——原生 manager 不可能被 SukiSU 撤销。
2. **所有提权路径都必须通过授权门** `sukisu_bridge_authorized()`。
3. **未知命令绝不伪装**：模块只拦截自己能识别的 SukiSU 命令，其余原样放行。
4. **原子上下文禁止睡眠**：kretprobe ret handler 内禁止调用可能睡眠的函数。

---

## 1. 背景与目标

### 1.1 参与者

- **SukiSU-Ultra manager**（用户态应用）：期望与"真正的 SukiSU 内核"对话。
- **KSU-Next 内核**（系统态）：设备实际运行的内核，实现 KernelSU-Next 的接口。
- **本模块**（内核态 LKM）：补丁层，位于两者之间。

### 1.2 不兼容的根因

manager 与内核通过一套双方约定好的协议通信。这套协议包含三部分：

1. **魔法握手**：`reboot(0xDEADBEEF, 0xCAFEBABE, 0, &out_fd)` 安装匿名 fd；
2. **fd-ioctl**：`ioctl(fd, cmd, arg)` 执行具体操作；
3. **prctl 控制面**：`prctl(0xDEADBEEF, cmd, arg1, arg2, &result)` 执行超级调用。

KSU-Next 实现了第 2 部分（`anon_ksu_ioctl`），但**没有实现第 1 和第 3 部分**的
SukiSU 语义。结果：

- manager 调用 `reboot(...)` 后拿不到 fd → 报告"未安装（not installed）"；
- 即使拿到 fd，部分 SukiSU 专属命令（KPM、hook-type、feature 等）KSU-Next 也不
  实现，直接返回错误 → manager 崩溃或显示错误状态。

### 1.3 本模块的目标

在不修改 manager 前端、不修改内核的前提下，用单个 `.ko` 补齐 manager 期望的
语义：

1. 用 kprobe 拦截 `reboot` 实现握手，让 manager 拿到 fd；
2. 用 kretprobe 在系统调用层拦截 prctl/ioctl，翻译协议、伪装身份；
3. 对 KSU-Next 实现的功能原样转发，对其未实现的功能伪造 SukiSU 身份的成功响应。

---

## 2. SukiSU manager 的两条通信通道

本节定义 manager 与内核通信的两个通道。模块的所有机制都挂在这两条通道上。

### 2.1 通道 A：fd-ioctl（主通道）

调用序列：

```
reboot(0xDEADBEEF, 0xCAFEBABE, 0, &out_fd)   # 第 1 步：魔法握手
ioctl(fd, cmd, arg)                          # 第 2 步及以后：具体操作
```

- 第 1 步若成功，内核安装一个**匿名 fd**（没有 `/dev/ksu` 节点），该 fd 的
  `file_operations.unlocked_ioctl` 指向 `anon_ksu_ioctl`，并把 fd 号
  `copy_to_user` 写回 `out_fd`。
- 第 2 步中，`cmd` 是 `_IOC('K', nr)` 格式的命令号，`arg` 是指向用户态参数结构
  的指针。

### 2.2 通道 B：prctl 控制面（超级调用）

调用形式：

```
prctl(0xDEADBEEF, cmd, arg1, arg2, &result)
```

参数在 pt_regs 中的位置（ARM64）：

| 语义 | 寄存器 | 值 |
|---|---|---|
| syscall 号 | x8 | 167（`__NR_prctl`） |
| option | x0 | `0xDEADBEEF`（`KSU_INSTALL_MAGIC1`） |
| cmd | x1 | 控制面命令号 |
| arg1 | x2 | 第 1 个参数 |
| arg2 | x3 | 第 2 个参数 |
| &result | x4 | 指向 4 字节结果缓冲的**用户态指针** |

成功约定：**`prctl` 返回值为 -1，且 `*result == 0xDEADBEEF`**。两者缺一，
manager 认为调用失败。

> 注意：正式版 manager 的 app profile 操作实际走**通道 A**（fd-ioctl `'K'`
> nr=11/12），而不是通道 B 的 prctl。这一事实是 §6 若干历史 bug 的根因。

---

## 3. 机制一：reboot 魔法握手 → 安装匿名 fd

### 3.1 问题

KSU-Next 没有实现 SukiSU 的握手，manager 调用 `reboot(0xDEADBEEF, 0xCAFEBABE,
...)` 后拿不到 fd，通道 A 直接断掉。

### 3.2 方案

模块用 **kprobe**（`reboot_kp`，`pre_handler = reboot_handler_pre`）挂在
`__arm64_sys_reboot` 上（符号名可用模块参数 `reboot_symbol` 覆盖）。

执行流程：

1. **触发**：任何进程调用 `reboot(...)`，进入 `__arm64_sys_reboot` 时 kprobe
   命中。
2. **参数提取**：`__arm64_sys_reboot(const struct pt_regs *regs)` 的 x0 是
   **用户 pt_regs 的指针**（不是参数本身）。因此必须先从 kprobe 现场的
   `regs->regs[0]` 解引用得到 `uregs`，再从 `uregs->regs[0]`（magic1）、
   `uregs->regs[1]`（magic2）、`uregs->regs[3]`（out_fd）读取实参。
3. **命中判定**：`uregs->regs[0] == 0xDEADBEEF` 且
   `uregs->regs[1] ∈ {0xCAFEBABE, 0xFAFAFAFA}`。
   - `0xCAFEBABE` 是 KSU 标准 magic2；
   - `0xFAFAFAFA` 是 SukiSU 额外使用的探测值。只认 `0xCAFEBABE` 时 manager 会
     判为"未安装"，两个值都必须接受。
4. **授权门**：调用 `sukisu_bridge_authorized()`，未授权进程直接拒绝握手
   （见 §14.7）。
5. **安装 fd（延迟）**：通过 `task_work` 挂 `ksu_install_fd_tw_func`，在进程
   从内核返回用户态之前执行 `ksu_install_fd(outp)`。该函数：
   - 调用 `anon_inode_getfd` 之类机制分配匿名 fd，其
     `file_operations.unlocked_ioctl = bridge_ioctl`（模块自己的 fops，
     `sukisu_fops`）；
   - 把 fd 号 `copy_to_user` 写回 manager 栈上的 `out_fd`；
   - 把 fd 号存入 `g_ksu_fds[]`，把当前 pid 记录到 `g_ksu_fd_owner_pid`
     （供 §10 的 close 保护使用）。
6. **为什么用 task_work**：reboot kprobe 在系统调用入口触发，此时不能安全地
   分配 fd（需要完整进程上下文、确保当前任务有效）。task_work 保证回调在进程
   上下文、返回用户态前执行。

### 3.3 结果

manager 拿到一个"看起来是 SukiSU 内核给的"fd。此后 manager 的所有 ioctl 都
打到 `bridge_ioctl`（§4）。

---

## 4. 机制二：bridge_ioctl —— 身份伪装 + 转发

### 4.1 函数签名与 CFI

```c
static long bridge_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
```

这是一个**标准 3 参数**的 `unlocked_ioctl`，kCFI 类型哈希与内核
`struct file_operations.unlocked_ioctl` 一致，因此 VFS 的间接调用能通过 CFI
检查。函数整体标记 `no_sanitize("cfi")`，使其内部的转发调用不受 CFI 约束
（见 §8）。

### 4.2 入口授权门

函数第一件事调用 `sukisu_bridge_authorized()`，未授权返回 `-EPERM`。原因是：
握手 fd 被安装到**任意**调用 `reboot(0xDEADBEEF,...)` 的进程，而 reboot 在
权限检查之前就会被 kprobe 看到，所以拿到 fd 不等于可信（见 §14.7）。

### 4.3 分支处理

按 `cmd` 分类，命中顺序如下（与源码 switch 一致）：

#### 4.3.1 身份伪装类（模块自己伪造响应）

| cmd | 动作 |
|---|---|
| `_IOC('K', 2)` GET_INFO | 回填 `info.version = 0x00040105`；`info.flags \|= (1U<<1)`（MANAGER 位）；`info.uapi_version = 2`。**故意不置 LKM 位（bit0）**：SukiSU 是 GKI 内置，`is_lkm_mode()` 必须为 false，否则 manager 显示错误的"LKM"状态。按 `_IOC_SIZE(cmd)` 判断结构化 16B / legacy 12B，只回写声明的大小，避免越界 |
| `KSU_IOCTL_HOOK_TYPE`（nr=101） | 回填 `hook_type = "sukisu"` |
| `KSU_IOCTL_ENABLE_KPM`（nr=102） | 回填 `enabled = 1` |
| `_IOC('K', 200)` KPM | 读取 `kcmd.control_code`：`VERSION`→写 `"1.0.0-sukisu"`；`NUM`/`LIST`→`res=0`；`0`（探测用）→`res=-1`；其他→`res=0`。结果写回 `kcmd.result_code` 指向的用户缓冲 |
| `_IOC('K', 1)`（becomeManager / GRANT_ROOT / GET_VERSION） | 调用 `bridge_queue_become_root()` 排队提权（幂等），把 `0x00040105` 写回 `uarg` |
| `_IOC('K', 100)` GET_FULL_VERSION | 把 `"v4.1.5-sukisu"` 写入 255 字节缓冲 |
| `_IOC('K', 13)` GET_FEATURE | **先读内核真实状态**：`ksu_get_feature_call(fid, &fval, &fsup)`（仅进程上下文，内核 helper 用 mutex），成功后把真实值回填本地 `g_features`；内核接口不可用或 fid 越界才读本地表并 force `supported=1`。**不能只读本地表**：本地表初始全 0，manager 会把 su_compat 误读为关，其 startup sync 再写 `SET_FEATURE(0,0)` 回内核 → su(1)/LSPosed 失效（§13 #22）。fd<0 原子路径（kretprobe ret handler）不能调 mutex，仍只读本地表，但该表已在 init/GET 时与内核同步（`sukisu_seed_features()`） |
| `_IOC('K', 14)` SET_FEATURE | 更新本地 `g_features` 表 + 排队 task_work 调 `ksu_set_feature()`（写真实内核，进程上下文）。`bridge_ioctl` 分支用**栈上局部 `pt_regs`** 调 emulate（VFS ioctl 路径不能碰 `current_pt_regs()`，§13 #21） |
| `_IOC('K', 11)` / `_IOC('K', 12)` | **app profile GET/SET**，转交 `emulate_sukisu_ioctl()` 做结构翻译（§6）。翻译前后各执行 `spoof_begin`/`spoof_end`（§7.2）；`bridge_ioctl` 分支同样用局部 `pt_regs`（§13 #21） |

#### 4.3.2 转发类（其他所有命令）

其余命令（root 授权、sepolicy、真实 profile 等）**原样转发**给 KSU-Next 的
`anon_ksu_ioctl`：

```c
rc = ksu_next_ioctl(filp, cmd, (unsigned long)uarg);
```

- `ksu_next_ioctl` 是 init 时用 kallsyms 解析的 `anon_ksu_ioctl` 地址；
- 转发期间同样临时 `spoof_begin`（伪装成被加冕 uid），使 KSU-Next 的
  `is_manager()` 检查通过；
- 转发调用在 `no_sanitize("cfi")` 函数体内完成，避免 CFI panic（§8）。

### 4.4 写回约定

身份命令的结果通过 `copy_to_user` 写到 `arg` 指向的用户缓冲，函数返回值作为
ioctl 的返回值。所有 `copy_to_user` 前都有 `access_ok` 校验。

---

## 5. 机制三：prctl(0xDEADBEEF) 控制面模拟

### 5.1 为什么需要挂在系统调用分发器层

KSU-Next 在 `__arm64_sys_prctl` 上安装了**内联 hook**：它把该函数的入口直接
改写到自己的处理函数，并立即返回，**原函数体被绕过**。因此：

- 挂在 `__arm64_sys_prctl` 上的 kretprobe **根本不会触发**（函数体不执行）；
- 模块必须挂在**更上层**的系统调用分发器 `el0_svc_common` 上。

系统调用分发器候选符号（按注册顺序尝试）：

```
"el0_svc_common", "invoke_syscall", "el0_svc_handler", "do_el0_svc"
```

分发器在内联 hook **之前**运行（entry），在其**之后**返回（ret）。模块在
`svc_ret_handler` 里改写用户 pt_regs 和输出缓冲，从而覆盖 KSU-Next 的处理结果，
让 manager 看到 SukiSU 身份的响应。

### 5.2 双通道保活（避免冷启动 NPE）

#### 5.2.1 问题

`el0_svc_common` 被**每一个进程的每一个系统调用**命中。冷启动瞬间并发调用
风暴会耗尽 kretprobe 实例池（`maxactive` 个并发实例），导致 manager 关键的
身份 ioctl（尤其 `GET_FULL_VERSION` nr=100）漏过拦截 → 返回 `-ENOTTY` →
`getFullVersion()` 为 null → manager 的 `Natives.b()` NPE 崩溃回桌面。

#### 5.2.2 方案

模块同时挂三条 kretprobe，构成主备通道：

| 探针 | 挂载点 | 作用 |
|---|---|---|
| `svc_krp`（主） | syscall 分发器 | 覆盖 KSU-Next inline hook，主通道 |
| `prctl_krp`（备） | `__arm64_sys_prctl` | 仅对**未被 KSU-Next 重定向**的 prctl 生效，兜底 |
| `ioctl_krp`（备） | `__arm64_sys_ioctl`（候选 `ksys_ioctl`/`do_sys_ioctl`） | 只对 ioctl syscall 触发，实例池几乎不会耗尽，`GET_FULL_VERSION` 等由它兜底 |

`svc_krp` / `ioctl_krp` 的 `maxactive` 取 **2048**（曾为 8192，缩池省内存）。

#### 5.2.3 性能优化：非目标 syscall 跳过 return probe（2026-08）

`el0_svc_common` 被每个 syscall 命中是**结构性开销**：挂载点必须在内联 hook
之上（§5.1），且 kprobe 是**全局**的，不支持按进程 / SELinux 域选择触发，
所以无法做到"只看某个进程"。

减少开销的手段是 kretprobe 的返回语义：**entry handler 返回非 0 时，框架跳过
return probe 安装**。`pre_handler_kretprobe` 在 entry 返回非 0 时会把该实例
归还 freelist（已核对 GKI 5.10 `kernel/kprobes.c`，无泄漏）。因此：

- **非目标 syscall**：只付一次**入口陷入**（地址范围检查 + `regs[8]` syscall
  号比较），返回路径**零额外开销**；
- **目标 syscall**（`prctl(0xDEADBEEF,...)` / 无效 fd 的身份 ioctl）：返回 0
  安装 return probe，ret handler 执行 emulate + `spoof_end`。

三个 entry handler（`svc_entry_handler` / `prctl_entry_handler` /
`ioctl_entry_handler`）统一改为"目标返回 0，其余返回 1"。整机 CPU 增量从
~1-2% 显著下降。

### 5.3 控制面命令处理（`emulate_sukisu_prctl`）

`svc_ret_handler` 对拦截到的目标 prctl 调用 `emulate_sukisu_prctl(uregs, cmd,
arg1, arg2, arg5)`。命令号白名单：

```
cmd = 0, 1, 2, 9, 10, 11, 15, 30, 100, 101, 102
```

各命令处理（`uregs->regs[0] = -1` 是所有成功的统一返回值约定）：

| cmd | 命令 | 处理 |
|---|---|---|
| 0 | GRANT_ROOT | **su 的唯一提权通道**。SukiSU 的 `userspace/su/jni/su.c` 调 `prctl(0xDEADBEEF, 0, 0, 0, &result)` 请求提权，要求 `*result == 0xDEADBEEF`，否则打印 `"Access Denied: sucompat not permitted"` 并退出 1。模块：授权门检查 → `bridge_queue_become_root()` 提权 → `copy_to_user(rp, &result, 4)` 回填 → `uregs->regs[0] = -1`。未授权时回填 `0` 使 su 打印 Access Denied |
| 1 | BECOME_MANAGER | 通过 task_work 把 manager 进程提权到 root（`bridge_escape_to_root`，§7.3）。其 fork/exec 的 `ksud su` helper 继承 root cred，`getRootShell().isRoot` 通过 |
| 2 | GET_VERSION | 回填 `version = 0x00040105`、`flags = (1U<<1)`（仅 MANAGER 位，不带 LKM 位） |
| 9 | CHECK_SAFEMODE | 仅回填 result，返回 -1 |
| 10 / 11 | GET/SET_APP_PROFILE | 见 §6（这是 prctl 通道的 profile 处理，但正式版 manager 实际走 fd-ioctl nr=11/12） |
| 15 | ENABLE_SU | `su --disable-sucompat` 触发。经 task_work 调 `ksu_set_feature(0, 0)`（`KSU_FEATURE_SU_COMPAT`）真正禁用 su 兼容 |
| 30 | GET_VERSION_FULL | 回填 `"v4.1.5-sukisu"` |
| 100 | ENABLE_KPM | 回填 `enabled = 1` |
| 101 | HOOK_TYPE | 回填 `"sukisu"` |
| 102 | SUSFS_STATUS | 回填全零 `struct susfs_status` |

**未授权进程的处理**：GRANT_ROOT / BECOME_MANAGER 分支先查
`sukisu_bridge_authorized()`，未授权回填 `denied = 0`（使 `*result !=
0xDEADBEEF`）并返回 -1，绝不提权。

**未知命令**：`switch` 默认分支不做任何伪装，原样放行回 KSU-Next，避免破坏
其他进程。

---

## 6. app profile GET/SET —— 核心数据面

### 6.1 命令号语义

正式版 manager 走 fd-ioctl 通道：

```
KSU_IOCTL_GET_APP_PROFILE = _IOC('K', 11)   // GET
KSU_IOCTL_SET_APP_PROFILE = _IOC('K', 12)   // SET
```

早期模块把 `nr==11` 当 SET、`nr==12` 当 GET，**完全颠倒**，后果：

- GET（nr=11）被当"写入" → 从用户态读空 buffer 存入缓存且不回写 → 列表读不到
  状态；
- SET（nr=12）被当"读取" → 返回旧值、没写内核 → 授权全无效。

修复：**GET==11、SET==12**。

> 注意：不同 SukiSU 分支的 uapi 可能再次翻转命令号（历史 fork 版是
> SET=11/GET=12）。更换分支后必须核对。

### 6.2 结构体翻译（776B ↔ 784B）

- manager 发出的是 **SukiSU compact profile**（`struct sukisu_app_profile`，
  自然对齐）；
- KSU-Next 内核期望的是 **784 字节**的 `struct app_profile`（`selinux_domain`
  在 offset 704，已用真机 `.allowlist` 验证一致），`version` 接受 **4**。

翻译函数 `sukisu_to_ksu` / `ksu_to_sukisu` 处理：

- `struct sukisu_root_profile` 补 `u64 flags;` → 模块内部 `sukisu_app_profile`
  由 768B 变 **776B**，与官方 SukiSU 布局对齐；
- `SUKISU_PROFILE_VER` **3 → 4**，匹配官方 `KSU_APP_PROFILE_VER`；
- manager 发来的 `version=3` 在写入内核前改写成 `4`，否则 `profile_valid()`
  拒绝（`"Selinux domain empty"`）。

### 6.3 SET 路径（授权/撤销）—— 写穿透，保护原生加冕管理器

#### 6.3.1 历史事故（为什么一度只读化）

早期实现把 SET 镜像进 KSU-Next 内核 `allow_list` 和磁盘 `.allowlist`。而
SukiSU manager 启动时会对每个已装 app 发一条 `allow=0` 的 startup-sync deny。
模块的 `was_granted` 逻辑又把 seed（加载时从 `.allowlist` 读入）的原生 grant
误判为"SukiSU 自己的授权"，于是 deny 被**真实写入** → `com.rifsxd.ksunext`
（原生加冕管理器）的授权被永久撤销。现象是"模块卸载后原生才恢复正常"。

之后模块曾长期**只读化**（SET 永不写内核）。用户决定恢复写穿透：SukiSU 的
授权必须真实生效（"以前的版本都能用"），并接受"不保护整个 allowlist"的代价；
但"原生加冕管理器绝不能被撤销"保留为硬性保护。

#### 6.3.2 现状（2026-08 恢复写穿透）

SET 同时做两件事：

1. **更新内存缓存**（manager UI 的即时视图）：
   - 授权（`allow_su==1`）：`allowlist_map_store` + `mirrored=1`；
   - 撤销：`mirrored==1` 时从缓存移除；否则仅更新缓存；
   - 默认拒绝：仅更新缓存。
2. **写穿透进 KSU-Next**（`sukisu_profile_write_kernel`）：把 SukiSU compact
   profile 翻译成 784B `struct ksu_app_profile`（`sukisu_to_ksu`：version 改写
   为 4、`groups_count` 收敛到 32、空/超长 `selinux_domain` 兜底
   `"u:r:su:s0"`），经 task_work（`profile_set_tw_func`，进程上下文）调用真实
   `ksu_set_app_profile()`，成功后调 `ksu_persistent_allow_list()` 持久化。
   授权/撤销/拒绝**全部真实生效**。

**写穿透门（2026-08 修订）**：`sukisu_profile_write_kernel()` 开头要求
`sukisu_bridge_authorized()`（统一授权门，原子上下文安全）。**注意**：写穿透门
**不是** escalated-cred——manager 通过 bridge fd 做 profile 操作时以普通 uid
运行（非提权态），若限 escalated-cred 则撤销被静默丢到本地缓存，内核 allow_list
不动（"SukiSU 撤销了、原生还显示已授权"）。安全论证：已授权 app 本身能 su
（root），本就能直接改 `/data/adb/ksu/.allowlist` 文件，允许其写穿透**不新增
权限**——这是最小权限原则（authorized 即可更新其成员表），非安全边界。

**硬保护点（保留）**：对原生加冕 manager uid（`*g_ksu_manager_uid`，解析失败
回退 `g_spoof_uid`=10310）的 **deny** → **吞掉不写内核**，缓存照常更新。
SukiSU manager 的 startup-sync deny 因此永远撤销不了 `com.rifsxd.ksunext`；
其余 app 的原生授权可被 SukiSU 覆盖（用户接受）。

**签名注意**：内核真实签名是 `int ksu_set_app_profile(struct app_profile *)`
（单参数，mutex + hash replace/insert）。模块早期 typedef 是
`bool (*)(struct ksu_app_profile *, bool)`（双参）——未验证的猜测，因 SET 只读
化期间从未被调用而未暴露。恢复写路径时已修正为 `int (*)(struct ksu_app_profile *)`。

### 6.4 GET 路径（读取授权状态）

缓存权威优先级：

1. **显式授权** 或 **显式自定义拒绝**（`use_default==0`）：缓存即权威，直接
   返回；
2. **默认拒绝**（`use_default==1`）：**不算权威**，必须向内核查询确认
   （`kernel_checked` 标志）——否则会掩盖"仅存在于 KSU-Next `allow_list`、
   从未进模块缓存"的原生授权，导致 manager 只看到自己的设置；
3. 缓存未命中：先查内存 `.allowlist` 镜像（加载时 seed 的
   `g_allowlist_map`），再查 `ksu_get_app_profile(uid)`（本 fork 拒绝伪装 uid，
   主要靠磁盘镜像），都没有才回默认拒绝。

---

## 7. 身份判定（不锁定 uid）+ 伪装

### 7.1 服务对象判定：`is_target_app()`

不同 SukiSU 分支/版本的 manager uid 各不相同（取决于包安装顺序），**锁定任何
一个 uid 都会破坏对其他分支的兼容**。因此模块不锁定 uid。

判定规则（`is_target_app()`）：

1. **`current_uid().val == 0` 且 `sukisu_cred_escalated()`**：即 root 进程**必须
   是模块提权的**（§14.1/§14.6）。
   - 用户在原生 manager 中给 SukiSU manager 授权后，manager 以 root 运行；
   - 模块从授权进程提权而来，`commit_creds` 换整个线程组共享 cred，并注册进
     `g_escalated_creds[]`，按 `current_cred()` 指针身份识别（fork 继承）；
   - **其他方式得到的 root**（adb root、第三方 su、内核漏洞）**cred 不在注册表
     → 不服务**。这是安全收紧（早期 `uid==0` 直接放行已删除）。
2. 非 root 进程：仅当 uid 等于 KSU-Next 加冕的 manager uid
   （`*g_ksu_manager_uid`，解析不到时回退 `g_spoof_uid` 即 10310）才服务——
   保留对原生 KSU-Next manager 的兼容。

**不依赖 comm 匹配**（`current->comm` 可用 `prctl(PR_SET_NAME)` 伪造），杜绝
改名攻击。线程组 leader 的 comm 可作诊断参考，但不参与判定。

### 7.2 伪装：`spoof_begin` / `spoof_end`

KSU-Next 的 `is_manager()` 用 `current_uid()` 与它加冕的 uid（如 10310）比对。
SukiSU manager 的 APK 签名不匹配 KSU-Next 内置哈希，**永远不会被加冕**，所有
manager-only 路径都会拒绝它。

模块在目标进程自己的内核上下文里**临时**把 cred 的
`uid/euid/suid/fsuid` 改成 `g_spoof_uid`（默认 10310，参数 `manager_uid` 可
覆盖），使 KSU-Next 的 `is_manager()` 在调用期间通过。这**只是伪装目标，不是
身份锁**。

`spoof_end()` 的还原条件：**当前 uid 是否仍等于 `g_spoof_uid`**。

- 相等 → 还在 manager 自身 syscall 内，还原 cred；
- 不等 → 进程已 exec 进 `su`（helper 是独立进程，uid 已变），**保留提权**，
  让 sucompat 把 helper 提升到 root。

刻意不复用 `is_target_app()`：它按 root+标记判定，在提权后对任何 root 进程都
返回 true，会把 su helper 的 root 误还原。

### 7.3 提权：`bridge_escape_to_root`

在 manager 进程内执行（经 task_work，进程上下文）：

1. `uid/gid` 设为 0；
2. 清空 `securebits`；
3. 置满 `cap_*`；
4. **保留原有 supplementary group**（避免 `groups_alloc` 解析不稳导致
   `in_group_p` panic）；
5. 调 `setup_selinux("u:r:ksu:s0", cred)` 切换 SELinux domain。

> **SELinux domain 切换是"能力"的关键**：只提 uid/gid/caps 而 domain 仍在
> `untrusted_app` 时，进程访问 `/data/adb/modules`、feature ioctl 等 root
> 资源会被 SELinux avc 拒绝（`avc: denied { dac_read_search } ...`），即使
> uid==0 也读不到任何东西。`setup_selinux` 是 static 符号，用 kallsyms 解析
> （解析失败不致命，但能力受限）。

---

## 8. CFI / kCFI 处理（稳定性核心）

### 8.1 问题

GKI 内核开启 kCFI（+ Shadow-Call-Stack）。KSU-Next 的 `anon_ksu_ioctl`、
`ksu_set_app_profile`、`ksu_get_app_profile` 都是 **static 函数**，其
build-specific kCFI 类型哈希与标准调用签名不一致：

- 把 `anon_ksu_ioctl` 地址直接塞进 `.unlocked_ioctl` → VFS 的 CFI 间接调用
  panic；
- 直接间接调用 `ksu_set/get_app_profile` → 内核 CFI panic
  （`"CFI failure (target: ...XX)"`）。

### 8.2 解决策略

1. **自身暴露标准签名**：`bridge_ioctl` 是标准 3 参数 `unlocked_ioctl`，过
   VFS 的 CFI；内部只在 `no_sanitize("cfi")` 上下文转发给 `anon_ksu_ioctl`。
   `no_sanitize("cfi")` 让编译器**不生成 CFI 检查**，间接调用直接抵达
   `.cfi_jt` 跳表入口。
2. **所有 kallsyms 解析来的未知符号**（`filp_open` / `commit_creds` /
   `task_work_add` / `make_kuid` 等）的间接调用，全部包一层
   `no_sanitize("cfi")` wrapper。它们实际落在 `.cfi_jt` 跳表分支指令上，CFI
   检查会把分支 opcode 误读成类型哈希而 panic。
3. **不用 workqueue 做 SET**：模块不带 CFI 影子，workqueue 的 `work->func`
   无 CFI 影子，内核 `process_one_work()` 内 CFI 检查会 panic。改用
   `task_work`（CFI-exempt 路径）。
4. `task_work_add` 自身参数原型（`enum` vs `int`）类型哈希不匹配，同样走
   `no_sanitize("cfi")` wrapper。

---

## 9. allowlist 种子与授权隔离

### 9.1 种子（加载时）

`bridge_init` 解析磁盘 `/data/adb/ksu/.allowlist`（magic `0x7f4b5355`），把
现有 GRANT 通过 `ksu_to_sukisu()` 镜像进内存表 `g_allowlist_map`。

原因：本 SukiSU-Ultra fork 的 `ksu_get_app_profile()` 调用时强制
`is_manager()` 并拒绝伪装 uid（SET 在 seed 阶段也失败），所以**加载时直接解析
磁盘**，让原生 KSU-Next manager 管理的授权在本模块里可见。

### 9.2 授权隔离（根治：KSU-Next 严格只读）

**症状**：用户看到"随机全部重置"→ 原生 manager 的授权被 SukiSU manager 抹掉，
且**模块卸载后原生才恢复正常**。

**根因**：KSU-Next 的 `allow_list` 与原生 manager **共享**。SukiSU manager
启动会发一次"同步"，把每个已装 app 写成 `allow=0`，且可能随时重新同步。早期
实现把 profile 盲目镜像进 KSU-Next 内核 `allow_list` 和磁盘 `.allowlist`，
`was_granted` 又把 seed 进来的原生 grant 误判为"SukiSU 自己的授权"，于是
sync deny 被真实写入，原生授权（含 `com.rifsxd.ksunext` 自身）被永久撤销。

**中间态（已废弃）**：模块一度**严格只读**——`SET_APP_PROFILE` 永不调
`ksu_set_app_profile`，只更新内存缓存。代价是 SukiSU manager 的授权不落内核
（无实权），仅剩"兼容壳 + 视图"作用。

**现状（2026-08，写穿透）**：恢复真实写入，保留唯一的硬保护：

- `SET_APP_PROFILE`（prctl cmd=11 / ioctl nr=12）：更新内存缓存后，经
  `sukisu_profile_write_kernel()` 排队 task_work 调 `ksu_set_app_profile()` +
  `ksu_persistent_allow_list()`，SukiSU 的授权/撤销**真实生效**；
- **唯一例外**：对原生加冕 manager uid 的 deny 被吞掉（`sukisu_profile_write_kernel`
  开头判断 `!allow_su && current_uid == 原生 manager uid`），SukiSU 的
  startup-sync deny 永远撤销不了 `com.rifsxd.ksunext`；
- `SET_FEATURE`（ioctl nr=14）写本地 `g_features` 内存表 + task_work 调
  `ksu_set_feature`（进程上下文，ret handler 原子上下文不能调 mutex）；
- GET 路径：`ksu_get_app_profile_call`（profile GET）；**GET_FEATURE 读内核真实
  状态**（`ksu_get_feature_call`，进程上下文）+ 回填本地表；原子路径只读本地表
  （由 seed/GET 保持同步，见 §14.2）。**不能只回本地表**（§13 #22）。

**代价**：SukiSU manager 启动的 sync deny 会覆盖（撤销）其余 app 的原生授权——
用户明确接受（"不需要保护 allowlist"）。要保留某 app 的授权，在 SukiSU manager
里重新授权即可（写穿透会持久化）。

---

## 10. close(2) 保护

### 10.1 问题

manager 在获得握手 fd 后可能立即 `close(2)` 它。`libkernelsu` 的 `init()` 之后
扫描 `/proc/self/fd` 找 `[ksu_driver]` 并 `dup()`；若 fd 已被关闭，
`init()` 失败 → `getFullVersion()` 返回 NULL → `Natives.b()` NPE。

### 10.2 方案

模块在 `__arm64_sys_close` 上挂 kprobe（`close_kp`）。对受保护的 fd 集合
`g_ksu_fds`，把系统调用的 fd 参数改写为 `-1`（即 `close(-1)` 返回 `-EBADF`，
真实 fd 存活）。

两个必须遵守的实现细节（都踩过坑）：

1. **寄存器来源**：`__arm64_sys_close(const struct pt_regs *regs)` 的 x0 是
   **用户 pt_regs 指针**，fd 号必须从 `x0` 解引用的 `pt_regs->regs[0]` 读取
   （与 `__arm64_sys_ioctl` / `__arm64_sys_prctl` / `__arm64_sys_reboot` 同理）。
   早期直接读 kprobe 现场的 `regs->regs[0]`，得到内核 vmalloc 地址低 32 位，
   永不匹配 `g_ksu_fds` → 保护从不命中 → 握手 fd 被正常关闭（dmesg 可见
   `fd released`）→ 兜底失效。
2. **进程身份门**：fd 号是进程私有的。必须加
   `current->pid == g_ksu_fd_owner_pid`（握手完成时记录的进程）门控，否则全局
   close kprobe 会把**所有进程**的 `close(同号fd)` 改写成 `close(-1)`，系统级
   泄漏 fd。

### 10.3 无 panic 保证

该 handler 只做**整数比较**：不调用 `fcheck()`、不走 RCU、不追逐任何由 fd
派生的指针。因此无论传入什么 fd 值，结构上不可能 NULL panic。

---

## 11. 符号解析策略

### 11.1 为什么需要 kallsyms

运行内核（Wild kernel / GKI）不导出部分符号，且部分导出符号的 modversion CRC
与模块不匹配。直接引用会加载失败或产生 undefined symbol。

### 11.2 方法

- 用 **kallsyms + kprobe** 方式（`resolve_symbol`）解析 static / 未导出符号。
  `resolve_symbol` 的实现要点：不能直接 kprobe
  `module_kallsyms_lookup_name` / `kallsyms_lookup_name`——在本 GKI 构建上，
  注册这类 kprobe 会在 `init_module` 期间**硬重启设备**（比直接探测目标符号更
  糟），因此改为直接探测目标符号本身。
- 解析目标（候选符号名）：
  - `anon_ksu_ioctl`（转发目标，必须 `target=` 传完整 kCFI 哈希名
    `anon_ksu_ioctl$<md5>`，见 §12）
  - `ksu_set_app_profile` / `ksu_profile_set` / `set_app_profile`
  - `ksu_get_app_profile` / `ksu_profile_get` / `get_app_profile`
  - `ksu_put_app_profile`
  - `__ksu_is_allow_uid`（**硬依赖**，解析失败拒绝加载，见 §14.1）
  - `ksu_manager_uid`
  - `task_work_add`
  - `commit_creds` / `prepare_creds` / `abort_creds` / `groups_alloc` /
    `groups_free` / `make_kuid` / `make_kgid`
  - `setup_selinux`（static，非致命）
  - `ksu_set_feature` / `ksu_get_feature`
  - `filp_open` / `filp_close` / `kernel_read` / `__kmalloc` /
    `__get_task_comm`
- CRC 不匹配但仍导出的符号（如 `make_kuid`、`__kmalloc`）同样走 kallsyms，使
  模块仅有 CRC 匹配的依赖。
- `MODULE_IMPORT_NS(vmlinux)` 满足加载期命名空间检查。
- 内置 `__stack_chk_guard` 弱符号作为链接垫片（仅解决 modpost 链接期
  undefined，运行期仍是内核提供的 `__stack_chk_fail`）。

---

## 12. 构建与安装

### 12.1 构建

`build_mod.sh` 通过环境变量 `KDIR` / `NDK` 指定路径（未设置时用脚本内默认值），
自动适配宿主平台（Linux / macOS / Windows+MSYS2）选择 NDK prebuilt 子目录：

```bash
export KDIR=/path/to/kernel-tree
export NDK=/path/to/android-ndk-r23b
bash build_mod.sh          # 或 Windows 下用 bash.exe 绝对路径调用
```

- 产物：`sukisu_bridge.ko`；本地日志写 `build_mod.log`，CI（`GITHUB_ACTIONS`）
  直接输出到 stdout；成功标志 `BUILD DONE`。
- **工具链版本是硬性约束**：设备内核启用 kCFI，模块必须用**与目标内核同代 clang**
  编译，否则 kCFI 类型哈希不匹配 → insmod 可能 PAN、rmmod 必报 `CFI failure` 并
  panic。NDK 按内核分支映射（与 CI 矩阵一致）：5.4→r21e（clang 11）、5.10→r23b
  （clang 12，设备验证目标）、5.15→r25b（clang 14）、6.1→r27（clang 17）、
  6.6→r28（clang 18）。**产物是内核专属的**：矩阵外 / 厂商定制 / 自编译内核必须
  用对应内核树自行编译，不能直接使用其他内核的 CI 产物。
- 其他关键编译 flag（SCS/PAC+BTI/禁栈保护）由脚本按设备内核配置自动设置，见
  `build_mod.sh` 注释。

### 12.2 安装

```bash
# 通过 ksud 加载（KSU-Next 自带 insmod 通道）
ksud insmod sukisu_bridge.ko
# 或 adb push + insmod
adb push sukisu_bridge.ko /data/local/tmp/
adb shell su -c 'insmod /data/local/tmp/sukisu_bridge.ko'
```

### 12.3 可覆盖模块参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `target` | `anon_ksu_ioctl` | 转发目标。磁盘符号是 kCFI 哈希名 `anon_ksu_ioctl$<md5>`，裸名不匹配，必须传完整名 |
| `reboot_symbol` | `__arm64_sys_reboot` | 握手挂钩的 reboot 系统调用符号 |
| `prctl_symbol` | `__arm64_sys_prctl` | prctl 控制面 kretprobe 符号 |
| `svc_symbol` | `el0_svc_common` | syscall 分发器符号（在 KSU-Next inline hook 之上） |
| `manager_uid` | `10310` | 要伪装的被加冕 manager uid |

> 验证要点：加载后 `su -c dmesg | grep sukisu_bridge` 应无 panic / CFI
> failure；manager 显示 built-in（GKI）。SET 为**写穿透**：SukiSU manager 里的
> 授权/撤销会真实写入内核并持久化 `.allowlist`，**可用 `.allowlist` 条目变化
> 验证**；但 `com.rifsxd.ksunext` 的 deny 永不落盘（保护）。验证"能力"
> 应看 su 提权（`prctl cmd=0` 日志）与 SELinux domain 切换
> （`escape_to_root ... selinux=u:r:ksu:s0`）。

---

## 13. 修复历史（踩坑记录，按时间）

| # | 症状 | 根因 | 修复 |
|---|------|------|------|
| 1 | manager NPE 崩溃回桌面（`Natives.b()`） | `ksuctl` 的 `static int fd` 只在首次 scan 缓存；握手 fd 在首次 scan 之后装上 → fd 恒 -1 → `ioctl(-1)` 返回 0 但 buffer 空 → `getFullVersion()` null | do_el0_svc 主通道 + `__arm64_sys_ioctl` 兜底，`fd<0` + 身份命令白名单才 emulate |
| 2 | 兜底从不触发 | `ioctl_entry_handler` 把 kretprobe 现场 `regs->regs[0]`（=用户 pt_regs 指针，vmalloc 地址低位）当 fd → 恒 ≥0 | 先解引用 x0 得用户 pt_regs，再从 `uregs->regs[0..2]` 读 fd/cmd/arg（`__arm64_sys_ioctl/prctl/close/reboot` 同坑） |
| 3 | 获取 root 失败（所有管理器） | `bridge_queue_become_root` / `profile_set_tw_func` 有 uid 校验，拒绝非 root 非加冕的 SukiSU manager | 移除 uid 校验，改为统一授权门提权（§5.3） |
| 4 | 原生授权被永久撤销（模块卸载才恢复） | SET 镜像进 KSU-Next + `was_granted` 误判 seed 原生 grant → startup sync deny 真写入 `.allowlist`，`com.rifsxd.ksunext` 被撤销 | 一度改 SET **严格只读**（§6.3.1）；2026-08 按用户要求恢复**写穿透**，但保留硬保护：对原生加冕 manager uid 的 deny 永不写内核（§6.3.2/§9.2） |
| 5 | 所有管理器失去一切能力（模块列表空、feature/setenforce 失效） | su helper 的 `prctl(0xDEADBEEF, cmd=0 GRANT_ROOT)` 不在白名单 → KSU-Next 不实现 prctl 控制面 → `result!=0xDEADBEEF` → su 退出 | svc 白名单加 cmd=0/15；`emulate_sukisu_prctl` 新增 GRANT_ROOT（提权+回填）/ ENABLE_SU（写 su_compat feature） |
| 6 | uid==0 仍读不到 `/data/adb/modules`（avc denied） | `bridge_escape_to_root` 只提 uid/gid/caps，没切 SELinux domain，进程仍在 `untrusted_app` 域 | 提权时调 `setup_selinux("u:r:ksu:s0")`（§7.3） |
| 7 | 全系统 fd 泄漏（系统级破坏） | close 保护只在全局 `__arm64_sys_close` 上按整数 fd 匹配，无进程身份门 → 所有进程的 `close(同号)` 被改写成 `close(-1)` | `close_entry_handler` 加 `current->pid == g_ksu_fd_owner_pid` 门控（§10） |
| 8 | close 保护从不命中（fd 被正常关闭） | `close_entry_handler` 直接读 `regs->regs[0]` 当 fd（vmalloc 地址低位），永不匹配 | 从 x0 解引用的用户 pt_regs 读 fd（§10） |
| 9 | SET_FEATURE 空转（SELinux 模式开关无效） | `SET_FEATURE`(nr=14) 不在白名单，且不写真实内核 | 白名单加 nr=14；emulate 的 GET 只读本地表（ret handler 原子上下文不能调 mutex 的 `ksu_get_feature`），SET 走 task_work 调 `ksu_set_feature`（进程上下文） |
| 10 | manager 无法修改授权（fd-ioctl 通道全失效） | 正式版 uapi 的 `GET_APP_PROFILE=_IOC('K',11)` / `SET=_IOC('K',12)`，早期模块把 11 当 SET、12 当 GET，完全反了 | 对调判断：GET==11、SET==12（§6.1） |
| 11 | manager 显示工作状态为 LKM | GET_INFO / GET_VERSION 主动置了 `KSU_GET_INFO_FLAG_LKM` 位，`is_lkm_mode()` 误判 | 三处去掉 LKM 位，仅保留 MANAGER 位与 version，显示 built-in（GKI） |
| 12 | 任意 App 一条 syscall 即拿 root（高危 LPE） | GRANT_ROOT/BECOME_MANAGER/nr=1 无条件提权，且可从 svc prctl / ioctl(fd<0) / reboot 握手三处无认证入口到达 | 统一授权门 `sukisu_bridge_authorized()` 应用于全入口（§14.1） |
| 13 | 授权撤销不生效 | 授权判定用加载时快照，撤销后仍继续服务 | 改实时查询内核 `__ksu_is_allow_uid()`；硬依赖解析失败拒绝加载（§14.1） |
| 14 | root 被误拒（提权线程其他兄弟线程 uid=0 无标记） | 提权经 task_work 挂发起线程，`commit_creds` 换整个线程组 cred → 其他线程 uid=0 但无 `PF_SUKISU_ESCALATED` | `bridge_escape_to_root` 用 `for_each_thread` + `rcu_read_lock` 给整个线程组打标记；fork 继承（§14.6） |
| 15 | 未授权进程可拿握手 fd（fd 泄漏向量） | reboot kprobe 先于 `CAP_SYS_BOOT` 检查，任意进程能到 fd 安装点 | fd 安装前查 `sukisu_bridge_authorized()`（§14.7） |
| 16 | 每 syscall 两次 kprobe 陷入（性能） | entry handler 恒返回 0 → 每个 syscall 都装 return probe | 非目标 syscall 返回非 0，跳过 return probe 安装（§5.2.3） |
| 17 | 管理器 feature 开关全部灰色禁用（SU Log / ADB Root / SELinux Hide），但状态可见 | 模块用紧凑 16B 布局处理 GET/SET_FEATURE（value@4/supported@12），而 SukiSU fork uapi（`supercall.h`）是 C 默认对齐：GET `feature_id@0,value@8,supported@16`（24B）、SET `feature_id@0,value@8`（16B）。真正的 supported@16 从未被写 → ksud 读到 `supported=0` → UI 判"unsupported"置灰；SET 也从错误偏移 @4 读 value → 写入脏值 | GET/SET_FEATURE 改用官方 `struct ksu_get_feature_cmd` / `struct ksu_set_feature_cmd`（C 对齐）；bridge_ioctl 补 nr=14 拦截（本地表 + task_work 写内核），与 fd<0 兜底路径一致（§6 数据面） |
| 18 | 点 SukiSU 图标即 panic（`bridge_escape_to_root+0x15c` NULL deref，`task_work_run` 上下文，logcat 三次同址） | 提权路径用 `for_each_thread()` 遍历线程组打 PF 标记；SET 写穿透使 `ksu_set_app_profile()`→`ksu_mark_running_process()` 全系统 `for_each_process_thread()` 遍历，与 bridge 的并发遍历在 manager 启动动画（线程组剧烈 fork/exit）时撞上半个 `list_del` 的节点（LIST_POISON）→ 解引用崩溃 | 彻底删除 for_each_thread 遍历，改用 escalated-cred 指针注册表：`commit_creds` 换整个线程组共享 cred → `sukisu_cred_escalated()` 按 `current_cred()` 指针身份识别（无链表遍历、不可竞态、fork 继承）（§14.6） |
| 19 | 写穿透越权：普通已授权 app 可篡改内核 allow_list | 写穿透仅受 `sukisu_bridge_authorized()`（allowlisted 也通过）门控 → 任意能 su 的 app 可 `ioctl(-1,'K',12)` 真实改写授权表 | 一度限 `sukisu_cred_escalated()`（manager-only）；后按真机验证回退（见 #20） |
| 20 | 撤销授权不落盘（SukiSU 撤销了、原生仍显示已授权） | 写穿透限 escalated-cred 后，manager 以**普通 uid** 走 bridge fd 撤销时 `sukisu_cred_escalated()` 为 false → 撤销被静默丢到本地缓存，内核 allow_list 不动 | 写穿透门改回 `sukisu_bridge_authorized()`（授权即可写穿透，原子上下文安全）；已授权 app 本身能 su 本就能改 `.allowlist`，不新增权限；原生 manager deny 吞掉保护不变（§6.3.2/§14.5） |
| 21 | 点 feature 开关 panic（`emulate_sukisu_ioctl ← bridge_ioctl ← __arm64_sys_ioctl`，Unable to handle kernel paging request） | `bridge_ioctl` 的 SET_FEATURE(nr=14)/APP_PROFILE(nr=11/12) 分支把 `current_pt_regs()` 传给 emulate，且在 emulate 返回后**二次解引用** `current_pt_regs()->regs[0]`——VFS unlocked_ioctl 路径该帧不可用 → 非法写/读 | 分支改为传**栈上局部 `struct pt_regs local_regs`**，emulate 结果写进局部帧，`return (int)local_regs.regs[0]`；不再触碰 `current_pt_regs()`（§4.3/§6） |
| 22 | su_compat 被禁、su(1)/LSPosed 失效（原生 manager 蹦出一堆 feature） | `bridge_ioctl` 的 GET_FEATURE 只读本地 `g_features` 表（初始全 0），未读内核真实状态 → manager `is_su_enabled()` 读到 0 → 启动 sync 发 `SET_FEATURE(fid=0,val=0)` 写穿透进内核 → `ksu_su_compat_enabled=false` → su 提权通道断 | GET_FEATURE（进程上下文）先调 `ksu_get_feature_call()` 读**内核真实状态**并回填本地表；`sukisu_seed_features()` 在 init 时用真实状态填充 `g_features[0..4]`（fd<0 原子路径也正确）；若检测到 su_compat 被误关则主动恢复为 ON（§6 数据面） |

---

## 14. 安全模型与加固（2026-08 代码审查后）

本模块是一个**内核级提权点**（可把调用进程抬到 uid 0 + 全 caps +
`u:r:ksu:s0`）。本节逐条记录审查发现的问题与修复。

### 14.1 提权必须经过授权门（高危修复）

**漏洞**：`emulate_sukisu_prctl` 的 `GRANT_ROOT(cmd=0)` /
`BECOME_MANAGER(cmd=1)` 和 `emulate_sukisu_ioctl` 的 `nr=1` **无条件**调用
`bridge_queue_become_root()`。这些 emulate 可从三个**无身份认证**的入口到达：

- svc 层 prctl 拦截（任意进程调 `prctl(0xDEADBEEF, 0)` 即进入白名单分支）；
- svc/ioctl_krp 的 `ioctl(fd<0, 'K', nr=1)` 兜底；
- reboot 握手 fd（kprobe 在 reboot **入口**触发，不看权限，任意进程调
  `reboot(0xDEADBEEF,...)` 就发 fd）。

→ **任意未授权 App 一条 syscall 即拿 root**。

**修复**：新增统一授权门 `sukisu_bridge_authorized()`，判定顺序：

1. `is_target_app()`（**root + escalated-cred 注册** / 加冕 manager uid）；
2. **内核实时授权 `__ksu_is_allow_uid(uid)`**（**唯一**非 root 路径）——反映
   原生 manager 的授权**和撤销**，无需 reload。快照兜底已删除。

**root 身份不再默认放行**：早期 `is_target_app()` 里 `current_uid()==0` 直接
返回 true，任何 root 进程（adb root、第三方 su、其它途径提权）都被无条件服务。
现在要求 `current_uid()==0 && sukisu_cred_escalated()`：只有**被 bridge 从授权
进程提权而来**的 root 才被服务（cred 指针注册表识别，见 §14.6）。非 bridge 提权
的 root 进程授权记录也为空（`.allowlist` 不含 uid 0）→ 被拒。

**检查点（授权门必须覆盖的入口）**：

- svc 层 prctl/ioctl 拦截条件；
- `ioctl_ret_handler`（ioctl_krp 兜底）；
- `bridge_ioctl` 入口（拿到握手 fd 的进程也必须已授权）；
- emulate 内 GRANT_ROOT/BECOME_MANAGER/nr=1 分支（纵深防御）。

**实时性（加强）**：早期只用加载时快照判定，导致授权撤销不生效——用户发现
授权错了去原生管理器撤销，模块还继续服务。现改为实时查询内核
`__ksu_is_allow_uid()`：授权/撤销**立即生效**。

**硬性要求（用户指定）**：`__ksu_is_allow_uid` 是**硬依赖**——init 解析失败
**拒绝加载**（`insmod` 失败，等价于立刻 rmmod），绝不回退到加载时快照。

### 14.2 原子上下文禁止睡眠（健壮性修复）

- kretprobe ret handler 是**原子上下文**（preempt disabled）。`allowlist_map_store`
  此前在持 `g_allowlist_lock` 时用 `GFP_KERNEL` 分配 → 改 `GFP_ATOMIC`；
- `emulate_sukisu_ioctl` 的 GET_FEATURE **只读内存表**（`ksu_get_feature` 用
  mutex 会睡眠）；SET_FEATURE 走 task_work（进程上下文）；
  **原子路径只读本地表的前提是本地表与内核同步**：`sukisu_seed_features()` 在
  init 时（进程上下文）直读 `ksu_get_feature` 填充 `g_features[0..4]`，且
  `bridge_ioctl` 的 GET_FEATURE（进程上下文）每次命中都回填——否则本地表全 0，
  manager 会把 su_compat 误读为关并 sync 关掉（§13 #22）；
- `sukisu_get_from_ksunext` 用 `rcu_read_lock`（非睡眠）+ 正确调用
  `ksu_get_app_profile(uid)` + `ksu_put_app_profile`。

### 14.3 卸载竞态（use-after-free 修复）

pending 的 task_work 回调（become-root / feature-set / fd-install）在模块卸载后
执行会跳到已释放代码 → panic。修复：每个 task_work 排队时 `try_module_get()`，
回调末尾 `module_put()`。卸载时若有 pending task_work，`rmmod` 返回 `EBUSY`
而非崩溃。

### 14.4 `ksu_get_app_profile` 签名修正（功能修复）

内核实际签名是 `struct app_profile *ksu_get_app_profile(uid_t)`（RCU + kref），
此前模块按 `bool (*)(struct ksu_app_profile*)` 调用：struct 指针被当作 uid 哈希
键、返回的 profile 被丢弃、翻译未初始化结构 → KSU-Next 的授权永远读不到。
已改为正确调用并 `ksu_put_app_profile`。

### 14.5 已评估/已知边界（未修复，可接受）

- `spoof_begin` 直接改 `current_cred()`（未 commit_creds）。`cred->usage==1`
  检查降低并发风险；单线程 syscall 窗口内安全，属内核 hack 的固有成本。
- close 保护用「fd 号 + 握手 pid」整数匹配：受保护 fd 永不释放，进程内不会
  撞号复用；其他进程 pid 不匹配不拦截。无需 fcheck。
- 双通道（svc + ioctl kretprobe）可能对同一 ioctl 重复 emulate：各身份命令
  幂等（写同一 buffer / 重复排队 task_work），无害。
- **写穿透门 = 统一授权门**（`sukisu_bridge_authorized()`，非 escalated-cred）：
  早期把写穿透限 escalated-cred，导致 manager 以普通 uid 用 bridge fd 撤销时
  被静默丢弃（撤销不落盘 bug）。已改为 authorized 门；已授权 app 本身能 su
  （root），本就能直接改 `.allowlist` 文件，写穿透不新增权限——最小权限原则
  而非关键防线（§6.3.2）。
- **escalated-cred 悬垂指针**：cred 释放后地址留在 `g_escalated_creds[]`，若被
  新 root 进程复用会误识别——但该进程已 root，不新增权限；且只比较指针不 deref，
  无 UAF。
- `bridge_escape_to_root` 未设 `cap_inheritable`：su helper exec 后靠
  uid0+permitted 工作，实测可用。

### 14.6 提权身份的线程组范围（2026-08 重写：cred 指针注册表）

**问题演进**：提权发生在 task_work（挂在发起 ioctl/prctl 的线程上），但
`commit_creds()` 换的是**整个线程组共享**的 cred → 其他线程也变 uid 0。必须让
"桥接提权的 root"可被整个线程组识别。

**初版修复（已废弃）**：`for_each_thread` + `rcu_read_lock` 给整个线程组打
`PF_SUKISU_ESCALATED`（0x20000000u）标记，fork 继承。

**致命缺陷（2026-08 真机 panic）**：SET 写穿透使 SukiSU manager 启动时
`ksu_set_app_profile()`→`ksu_mark_running_process()` 触发**全系统**
`for_each_process_thread()` 遍历；同时 `bridge_escape_to_root` 自己也在
`for_each_thread()` 遍历 current 的线程组。manager 启动动画期间线程组剧烈
fork/exit，两个并发 RCU 链表遍历撞上半个 `list_del` 的节点（LIST_POISON 地址）
→ `bridge_escape_to_root+0x15c` NULL deref panic（用户 logcat 三次同址崩溃）。

**最终方案（cred 指针注册表）**：
- `commit_creds(cred)` 后，该 cred 成为**整个线程组共享**的指针（每个线程
  `current_cred()` 相同）；
- `sukisu_cred_escalated_add(cred)` 把它注册进 8 槽环形数组
  `g_escalated_creds[]`（spinlock 保护）；
- 识别 `sukisu_cred_escalated()`：`current_cred() == 数组里的指针`。

**为什么安全**：
- **无链表遍历** → 不可能与任何 task-list 遍历竞态；
- **只比较指针、不 deref** → cred 释放后仍可安全比较（悬垂指针仅比较不触碰）；
- `spoof_begin()` 只改 cred 的 uid **字段**（`usage==1` 时），`current_cred()`
  指针不变 → spoof 期间仍匹配；
- fork 继承共享 cred → su helper 被识别；exec 后新 cred 不匹配（接受：helper
  exec 后不再需要 bridge 服务）。

**残留边界**：已释放的 cred 地址若被新 root 进程复用会误识别——但该进程本身已
root，不新增权限；且数组仅存指针不做 deref，无 UAF。

### 14.7 握手授权门（最终审查修复）

reboot kprobe 在 **syscall 入口**触发，先于内核 `CAP_SYS_BOOT` 权限检查——
任意 App 调 `reboot(0xDEADBEEF, 0xCAFEBABE)` 都会到达 fd 安装点。此前虽然
ioctl 有授权门兜底，但未授权进程仍能：① 获得 bridge fd；② 被记为
`g_ksu_fd_owner_pid`；③ 其 `close(该fd号)` 被改写为 `close(-1)` → **fd 泄漏
向量**。

修复：fd 安装前检查 `sukisu_bridge_authorized()`，未授权直接拒绝握手。正常
manager（在 allow_list 有授权）不受影响。

**代价/使用说明**：SukiSU 系管理器（含 su helper）必须先被用户在**原生
KSU-Next manager** 中授权（出现在内核 allow_list），模块才为其服务。

---

## 15. 目录结构

```
KSU_bridge2_SukiSU/
├── sukisu_bridge.c      # 全部逻辑（约 2900 行）
├── sukisu_bridge.ko     # 构建产物
├── Makefile             # obj-m := sukisu_bridge.o
├── build_mod.sh         # 交叉编译脚本（KDIR/NDK 环境变量可覆盖）
├── include/uapi/        # SukiSU uapi 头文件（编译依赖，ccflags -I$(src)/include）
├── device.config        # 设备相关配置
└── PRINCIPLE.md         # 本文件
```
