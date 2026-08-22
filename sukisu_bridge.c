/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * sukisu_bridge.c - LKM (.ko) version of sukisu_bridge, loads on KernelSU
 * Next via `ksud insmod`.
 *
 * GOAL: let a SukiSU Ultra manager drive this KernelSU Next kernel as if it
 * were a SukiSU kernel, using ONLY this .ko (no userspace zygiskd / KPM).
 *
 * HOW SukiSU manager talks to the kernel (verified against SukiSU-Ultra
 * kernel/supercall/supercall.c):
 *   1. The manager issues  reboot(KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2,
 *                                0, (void*)&out_fd)  -- a magic handshake.
 *   2. The kernel installs an *anonymous* fd (no /dev/ksu node) whose
 *      file_operations.unlocked_ioctl == anon_ksu_ioctl, and writes the fd
 *      back to out_fd via copy_to_user.
 *   3. The manager then does ioctl(fd, cmd, arg) for every operation.
 *
 * KSU-Next exposes anon_ksu_ioctl but does NOT implement SukiSU's reboot
 * magic handshake, so the SukiSU manager never obtains an fd and reports
 * "not installed".  This .ko supplies that missing handshake:
 *
 *   - reboot_handler_pre (kprobe on the reboot syscall) watches for the
 *     SukiSU magic pair and, via task_work, installs an anon fd whose
 *     .unlocked_ioctl is our own bridge_ioctl.
 *   - bridge_ioctl spoofs GET_INFO / HOOK_TYPE / ENABLE_KPM so the manager
 *     believes it is talking to a real SukiSU kernel, and forwards every
 *     other command to KSU-Next's real anon_ksu_ioctl.
 *
 * Every other command (root grant, sepolicy, profiles, KPM, ...) is handled
 * natively by KernelSU Next through the same anon_ksu_ioctl we forward to.
 *
 * CFI NOTE: KSU-Next's anon_ksu_ioctl is a static function whose build-specific
 * kCFI type hash does NOT match the kernel's standard
 * struct file_operations.unlocked_ioctl type.  Putting its address directly in
 * .unlocked_ioctl makes VFS emit a CFI-checked indirect call that panics the
 * device.  Instead we expose our OWN bridge_ioctl (standard 3-arg signature, so
 * the VFS call to it passes CFI) and forward to anon_ksu_ioctl only from a
 * no_sanitize("cfi") context, which emits no CFI check for that indirect call.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/task_work.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/version.h>

/* Cross-kernel task_work notification mode: android11-5.4's task_work_add()
 * takes a `bool notify` (true = set TIF_NOTIFY_RESUME), while 5.10+ takes an
 * enum task_work_notify where TWA_RESUME means the same thing.  Our
 * real_task_work_add pointer is declared with `int mode`, so passing 1 works
 * for both (non-zero bool -> true).  Define a symbolic alias so TWA_RESUME
 * compiles on kernels that don't declare the enum. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#define TWA_RESUME 1
#endif

/* ESCALATED-CRED REGISTRY: bridge_escape_to_root() escalates an AUTHORIZED
 * caller to uid 0 via commit_creds(), which swaps the SHARED cred for the
 * WHOLE thread group.  Every thread of the escalated process therefore has
 * current_cred() == the same pointer.  We record that pointer here and
 * recognize a bridge-escalated root by POINTER IDENTITY -- a root process that
 * gained uid 0 through any OTHER means (adb root, third-party su, kernel
 * exploit) has a different cred and is NOT serviced.
 *
 * WHY NOT the old PF_* task flag + for_each_thread() sweep: while the manager
 * starts up (its splash animation), the process spawns/exits threads at high
 * rate.  SukiSU's SET write-through makes ksu_set_app_profile() ->
 * ksu_mark_running_process() walk the WHOLE task list with
 * for_each_process_thread() at the same time the bridge's own
 * for_each_thread() sweep runs -- two concurrent RCU walks of the same
 * thread_group list hit a half-list_del()'d node (LIST_POISON) and NULL-deref
 * PANIC.  A cred pointer comparison needs no list walk at all, so it cannot
 * race.  We only compare the pointer, never dereference it, so it stays safe
 * even after the cred has been freed.  fork() inherits the pointer, so the su
 * helper spawned later is still recognized. */
#define SB_MAX_ESCALATED_CREDS 8
static const struct cred *g_escalated_creds[SB_MAX_ESCALATED_CREDS];
static DEFINE_SPINLOCK(g_escalated_creds_lock);
static unsigned int g_escalated_creds_idx;

static __attribute__((no_sanitize("cfi"))) void sukisu_cred_escalated_add(
	const struct cred *c)
{
	unsigned long flags;
	spin_lock_irqsave(&g_escalated_creds_lock, flags);
	g_escalated_creds[g_escalated_creds_idx++ &
			   (SB_MAX_ESCALATED_CREDS - 1)] = c;
	spin_unlock_irqrestore(&g_escalated_creds_lock, flags);
}

/* Current task is a bridge-escalated root?  current_cred() is the current
 * thread's cred (offset verified against the device kernel); comparing the
 * pointer is lock-free-safe via the spinlock and needs no task-list walk.
 *
 * Kept __maybe_unused: the registry is still maintained at every bridge
 * escalation (sukisu_cred_escalated_add), and this check may be re-enabled
 * if a finer root-trust policy than "uid==0 -> trusted" is needed. */
static __attribute__((no_sanitize("cfi"), unused))
bool sukisu_cred_escalated(void)
{
	const struct cred *c = current_cred();
	unsigned long flags;
	bool found = false;
	int i;

	spin_lock_irqsave(&g_escalated_creds_lock, flags);
	for (i = 0; i < SB_MAX_ESCALATED_CREDS; i++) {
		if (g_escalated_creds[i] == c) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&g_escalated_creds_lock, flags);
	return found;
}
#include <linux/uidgid.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>

/*
 * Diagnostic logging compile switch.
 * Default (release build): every pr_info() diagnostic call is compiled out,
 * so it cannot leak pid/comm/path/fd into the kernel ring buffer.
 * Enable verbose diagnostics with: make ccflags-y+=-DSB_DEBUG
 * (or define SB_DEBUG in build_mod.sh).
 */
#ifndef SB_DEBUG
#undef pr_info
#define pr_info(fmt, ...) do {} while (0)
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("fnyoat");
MODULE_DESCRIPTION("Bridge SukiSU manager onto KernelSU Next via reboot-handshake + ioctl forward + identity spoof (LKM).");
/* NOTE: intentionally NO MODULE_VERSION() here. The kernel's fixdep is disabled
 * in the MSYS2 build tree (cmd_and_fixdep is a no-op), so no .o.cmd is emitted
 * for the module object; a MODULE_VERSION would make modpost call
 * get_src_version() -> parse_source_files() -> read .sukisu_bridge.o.cmd,
 * which does not exist and aborts the MODPOST step with
 * ".sukisu_bridge.o.cmd: No such file or directory". */

/* The module is built against a Module.symvers whose symbols are placed in the
 * "vmlinux" namespace (see batch_ns.py), so import it to satisfy modpost and the
 * kernel's load-time namespace check. */
MODULE_IMPORT_NS(vmlinux);

/* ---- SukiSU uapi constants (inlined so the .ko is self-contained) ---- */
#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KERNEL_SU_OPTION    0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE
/* Second handshake magic issued by the SukiSU manager when it probes for a
 * genuine SukiSU kernel (the "real" install detection). The standard KSU
 * manager uses 0xCAFEBABE; SukiSU adds 0xFAFAFAFA. If we only honour the
 * former, the SukiSU detector never obtains an fd and reports "not installed"
 * even though every ioctl on the cafebabe fd succeeds. */
#define KSU_INSTALL_MAGIC2_ALT 0xFAFAFAFA
#define KSU_GET_INFO_FLAG_LKM (1U << 0)

#define KSU_IOCTL_HOOK_TYPE  _IOC(_IOC_READ, 'K', 101, 0)
#define KSU_IOCTL_ENABLE_KPM _IOC(_IOC_READ, 'K', 102, 0)

struct ksu_get_info_cmd {
	__u32 version;       /* Output: KERNEL_SU_VERSION */
	__u32 flags;         /* Output: KSU_GET_INFO_FLAG_* bits */
	__u32 features;      /* Output: max feature ID supported */
	__u32 uapi_version;  /* Output: KERNEL_SU_UAPI_VERSION */
};
struct ksu_hook_type_cmd {
	char hook_type[32];  /* Output: hook type string */
};
struct ksu_enable_kpm_cmd {
	__u8 enabled;        /* Output: true if KPM is enabled */
};

/* KPM (Kernel Patch Module) command: SukiSU-specific. control_code/arg1/arg2/
 * result_code are user-space POINTERS (see sukisu_handle_kpm / do_kpm). */
struct ksu_kpm_cmd {
	__aligned_u64 __user control_code;
	__aligned_u64 __user arg1;
	__aligned_u64 __user arg2;
	__aligned_u64 __user result_code;
};
#define SUKISU_KPM_LOAD    1
#define SUKISU_KPM_UNLOAD  2
#define SUKISU_KPM_NUM     3
#define SUKISU_KPM_LIST    4
#define SUKISU_KPM_INFO    5
#define SUKISU_KPM_CONTROL 6
#define SUKISU_KPM_VERSION 7

/* SukiSU identity we advertise to the manager. */
#define SUKISU_HOOK_TYPE_STR   "sukisu"
#define SUKISU_SPOOF_VERSION   0x00040105

/* Version we advertise via both the legacy ioctl GET_VERSION (nr=1, returned
 * in the ioctl return value) and the prctl GET_VERSION control command.
 * 0x00030105 (== 196869) is comfortably above every manager MINIMAL threshold
 * (KERNEL 11071, KERNEL_LKM 11648, SU_COMPAT 12040). */
#define SUKISU_PRCTL_VERSION   0x00040105
#define SUKISU_PRCTL_FULL      "v4.1.5-sukisu"

/* ------------------------------------------------------------------ */
/* Part 1: fd ioctl handler -> spoof identity + forward to KSU-Next   */
/* ------------------------------------------------------------------ */

/* KSU-Next's real anon_ksu_ioctl dispatcher, resolved from kallsyms at load
 * time. Its build-specific kCFI type hash does NOT match the kernel's standard
 * unlocked_ioctl type, so a normal indirect call to it trips CFI and panics the
 * device. We invoke it ONLY from a no_sanitize("cfi") context, which emits no
 * CFI check for that call. */
typedef long (*ksu_ioctl_t)(struct file *filp, unsigned int cmd, unsigned long arg);
static ksu_ioctl_t ksu_next_ioctl;

/* Bridge fd's struct file*, captured on each bridge_ioctl so the profile SET
 * path can forward the translated kernel-layout profile to KSU-Next's
 * dispatcher with a valid fd (its private_data is KSU-Next-compatible; the
 * forward path at ~line 373 already uses it safely). */
static struct file *g_bridge_filp;

/* SukiSU feature table (KSU_FEATURE_* ids), kept in-kernel so GET_FEATURE /
 * SET_FEATURE round-trip consistently even though the manager's ksuctl fd is
 * -1 and the real KSU-Next fd is unreachable.  This makes the SU / kernel
 * umount / SELinux-hide / SULOG switches hold their state in the UI.  True
 * enforcement still depends on the underlying KSU-Next feature; the table only
 * keeps the manager's view consistent. */
#define SB_MAX_FEATURE_ID 16
static u64 g_features[SB_MAX_FEATURE_ID] = {0};
static DEFINE_SPINLOCK(g_features_lock);

/* ksu_get_feature_cmd / ksu_set_feature_cmd: SukiSU fork uapi (uapi/supercall.h).
 * CRITICAL: C-DEFAULT-ALIGNED (NOT packed): u64 value is 8-aligned, so
 *   GET: feature_id@0, value@8, supported@16 -> sizeof == 24
 *   SET: feature_id@0, value@8 -> sizeof == 16
 * The old hand-rolled 16-byte buffer assumed value@4/supported@12 (packed),
 * which left the real value@8 and supported@16 unwritten -> ksud/manager saw
 * supported==0 -> every feature toggle (SU Log / ADB Root / SELinux Hide)
 * was greyed out as "unsupported" while the state still showed. */
struct ksu_get_feature_cmd {
	__u32 feature_id;  /* Input: feature ID (enum ksu_feature_id) */
	__u64 value;       /* Output: feature value/state */
	__u8  supported;   /* Output: true if feature is supported */
};
struct ksu_set_feature_cmd {
	__u32 feature_id;  /* Input: feature ID */
	__u64 value;       /* Input: feature value/state to set */
};

/* CFI-exempt wrappers around the kernel feature interface (defined with the
 * task_work helpers later in the file).  Used by bridge_ioctl (process
 * context) for GET_FEATURE and by feature_set_tw_func for SET_FEATURE. */
static __attribute__((no_sanitize("cfi"))) int ksu_set_feature_call(u32 fid, u64 val);
static __attribute__((no_sanitize("cfi"))) int ksu_get_feature_call(u32 fid, u64 *val, bool *sup);

/* The running Wild kernel does NOT export the cred/uid helpers, so resolve
 * them via kallsyms (they are still present in the kernel's symbol table).
 * Avoids unresolvable versioned dependencies on a locked-down kernel. */
static void (*g_commit_creds)(struct cred *);
static struct group_info *(*g_groups_alloc)(int);
static void (*g_groups_free)(struct group_info *);
static struct cred *(*g_prepare_creds)(void);
static void (*g_abort_creds)(const struct cred *);
static kuid_t (*g_make_kuid)(struct user_namespace *, uid_t);
static kgid_t (*g_make_kgid)(struct user_namespace *, gid_t);
/* KSU-Next's setup_selinux(domain, cred): switches the cred's SELinux SID to
 * the KSU domain ("u:r:ksu:s0").  KSU-Next's own escape_with_root_profile()
 * calls it; without it an escalated uid-0 process stays in the untrusted_app
 * domain and every root-ish access (read /data/adb/modules, feature ioctls)
 * is DENIED by SELinux avc even though uid==0 -> "all managers lost every
 * capability".  Resolved from kallsyms (static in selinux/selinux.c). */
static void (*g_setup_selinux)(const char *domain, struct cred *cred);
/* KSU-Next's kernel feature interface (see kernel/supercall/feature.c):
 * drives the REAL su_compat / kernel_umount / sulog / adb_root / selinux_hide
 * state so the SukiSU manager's SU / SELinux-hide switches actually take
 * effect.  These do NOT touch the allow list, so they cannot clobber native
 * grants (unlike ksu_set_app_profile, which stays read-only). */
typedef int (*ksu_set_feature_fn)(u32 feature_id, u64 value);
typedef int (*ksu_get_feature_fn)(u32 feature_id, u64 *value, bool *supported);
static ksu_set_feature_fn g_ksu_set_feature = NULL;
static ksu_get_feature_fn g_ksu_get_feature = NULL;

/* The running Wild kernel's modversion CRCs differ for a handful of still
 * exported symbols, so resolve them via kallsyms too.  This leaves the
 * module with zero problematic versioned dependencies (only CRC-matching
 * imports remain in __versions). */
static void *(*g_kmalloc)(size_t, gfp_t);
static void (*g_get_task_comm)(char *, size_t, struct task_struct *);

static __attribute__((no_sanitize("cfi"))) void *my_kzalloc(size_t s, gfp_t f)
{
	void *p = g_kmalloc(s, f);
	if (p)
		memset(p, 0, s);
	return p;
}

/* Forward declarations: spoof_begin/spoof_end are defined later (Part 2, manager
 * identity impersonation) but are first used above inside bridge_ioctl's forward
 * path (lines ~305/308). Declare them here so the earlier call sites compile
 * instead of hitting an implicit-declaration build error. */
struct spoof_state {
	kuid_t uid, euid, suid, fsuid;
	bool active;
};
static void spoof_begin(struct spoof_state *s);
static void spoof_end(struct spoof_state *s);
static bool is_target_app(void);
static bool sukisu_bridge_authorized(void);
static void bridge_queue_become_root(void);

/* Forward declaration: defined later (near the syscall-layer emulation code)
 * but also invoked from bridge_ioctl to translate app-profile ioctls. */
static int emulate_sukisu_ioctl(struct pt_regs *uregs, unsigned int cmd,
				 unsigned long arg);

/* Our own unlocked_ioctl: a standard 3-arg function whose kCFI type MATCHES the
 * kernel's struct file_operations.unlocked_ioctl, so the VFS indirect call that
 * reaches it passes CFI cleanly. Inside, we either spoof the SukiSU identity
 * commands or forward straight to KSU-Next's dispatcher (unchecked). */
static __attribute__((no_sanitize("cfi"))) long bridge_ioctl(
	struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	int rc = 0;
	bool spoofed = false;

	/* SECURITY GATE: the reboot handshake installs our [ksu_driver] fd into
	 * WHATEVER process calls reboot(0xDEADBEEF,...) -- reboot() itself is
	 * not permission-checked before our kprobe sees it.  Without this gate,
	 * an unauthenticated app could obtain the fd, then ioctl(fd, nr=1) and
	 * be elevated to root.  Only authorized processes (root / crowned
	 * manager / allowlist-granted uid) may use the bridge. */
	if (!sukisu_bridge_authorized()) {
		pr_info("sukisu_bridge: bridge_ioctl denied uid=%d cmd=0x%x\n",
			current_uid().val, cmd);
		return -EPERM;
	}

	/* Capture our own fd so the profile SET path can forward to KSU-Next.
	 * WRITE_ONCE: a concurrent ioctl on another thread may read this in the
	 * SET-forward path; publish it atomically. (L1) */
	WRITE_ONCE(g_bridge_filp, filp);

	/* Diagnostic: capture the exact command numbers the SukiSU manager issues
	 * so the spoof conditions can be matched. UNBOUNDED so the crash-window
	 * ioctls (which happen after hundreds of startup calls) are visible too. */
	pr_info("sukisu_bridge: ioctl cmd=0x%x type=%c nr=%u dir=0x%x size=%u arg=0x%lx\n",
		cmd, (_IOC_TYPE(cmd) ?: '?'), _IOC_NR(cmd),
		_IOC_DIR(cmd), _IOC_SIZE(cmd), arg);

	/* Every copy_to_user path is gated by access_ok(). */

	if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 2) {
		/* GET_INFO -- manager's isManager()/getVersion() read the packed
		 * 64-bit value: low 32 = version, bit32 = LKM, bit33 = MANAGER,
		 * bit34 = late-load, bit35 = PR-build. Advertise a genuine SukiSU
		 * version AND the MANAGER flag so the manager flips to "Working". */
		struct ksu_get_info_cmd info = {};
		/* Structured GET_INFO is 16 bytes (version/flags/features/uapi_version);
		 * legacy is 12 bytes (no uapi_version). Write back only as many bytes
		 * as the ioctl number declares, so legacy never overruns. */
		unsigned int wsize = (_IOC_SIZE(cmd) == sizeof(info))
					 ? sizeof(info)
					 : offsetof(struct ksu_get_info_cmd, uapi_version);
		if (access_ok(uarg, wsize) &&
		    copy_from_user(&info, uarg, wsize) == 0) {
			info.version = SUKISU_SPOOF_VERSION;
			/* NOTE: do NOT advertise KSU_GET_INFO_FLAG_LKM here. SukiSU is a
			 * GKI-builtin integration, so is_lkm_mode() must return false and the
			 * manager shows "GKI" rather than the bogus "LKM" work status. */
			info.flags |= (1U << 1);                  /* KSU_GET_INFO_FLAG_MANAGER */
			/* features = max feature ID supported.  MUST be non-zero or the
			 * manager thinks the kernel supports NO features and greys out every
			 * toggle (SU Log / ADB Root / SELinux Hide / kernel umount).  Official
			 * SukiSU fills KSU_FEATURE_MAX (=5) here: SU_COMPAT..SELINUX_HIDE. */
			info.features = 5;
			if (wsize >= offsetof(struct ksu_get_info_cmd, uapi_version) + sizeof(__u32))
				info.uapi_version = 2;
			rc = (copy_to_user(uarg, &info, wsize) == 0) ? 0 : -EFAULT;
			spoofed = true;
			pr_info("sukisu_bridge: GET_INFO spoofed version=0x%x flags=0x%x\n",
				info.version, info.flags);
		}
	} else if (cmd == KSU_IOCTL_HOOK_TYPE) {
		struct ksu_hook_type_cmd h = {};
		strscpy(h.hook_type, SUKISU_HOOK_TYPE_STR, sizeof(h.hook_type));
		if (access_ok(uarg, sizeof(h)))
			rc = (copy_to_user(uarg, &h, sizeof(h)) == 0) ? 0 : -EFAULT;
		spoofed = true;
	} else if (cmd == KSU_IOCTL_ENABLE_KPM) {
		struct ksu_enable_kpm_cmd e = {};
		e.enabled = 1;
		if (access_ok(uarg, sizeof(e)))
			rc = (copy_to_user(uarg, &e, sizeof(e)) == 0) ? 0 : -EFAULT;
		spoofed = true;
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 200) {
		/* KPM: SukiSU-specific. KSU-Next does not implement it (returns -25),
		 * so spoof a successful response so the manager detects a SukiSU
		 * kernel. The manager reads the real status from *result_code, not
		 * from the ioctl return value, so we write a success code there. */
		struct ksu_kpm_cmd kcmd = {};
		int cc = 0, res = 0;
		if (access_ok(uarg, sizeof(kcmd)) &&
		    copy_from_user(&kcmd, uarg, sizeof(kcmd)) == 0) {
			if (kcmd.control_code &&
			    access_ok((void __user *)kcmd.control_code, sizeof(cc)))
				__get_user(cc, (int __user *)kcmd.control_code);
			pr_info("sukisu_bridge: KPM cc=%d arg1=0x%llx arg2=0x%llx res=%d\n",
				cc, (unsigned long long)kcmd.arg1,
				(unsigned long long)kcmd.arg2, res);

			switch (cc) {
			case SUKISU_KPM_VERSION: {
				char ver[32] = "1.0.0-sukisu";
				if (kcmd.arg1 &&
				    access_ok((void __user *)kcmd.arg1,
					      strlen(ver) + 1))
					copy_to_user((void __user *)kcmd.arg1, ver,
						     strlen(ver) + 1);
				break;
			}
			case SUKISU_KPM_NUM:
			case SUKISU_KPM_LIST:
				res = 0;
				break;
			case 0:
				/* Real SukiSU rejects unknown control codes (0 is not in
				 * the 1..10 range) with result_code=-1 while the ioctl
				 * still succeeds. The manager probes with cc=0 to confirm
				 * the kernel is genuine SukiSU. */
				res = -1;
				break;
			default:
				/* LOAD/UNLOAD/INFO/CONTROL: report success. */
				res = 0;
				break;
			}

			if (kcmd.result_code &&
			    access_ok((void __user *)kcmd.result_code, sizeof(res)))
				__put_user(res, (int __user *)kcmd.result_code);
			rc = 0;
			spoofed = true;
		}
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 1) {
		/* nr=1 is becomeManager/GRANT_ROOT in the manager's flow (and
		 * doubles as GET_VERSION in KSU-Next uapi).  The manager calls this
		 * FIRST after acquiring the [ksu_driver] fd, and its
		 * getRootShell().isRoot check depends on the calling process being
		 * elevated to root.  QUEUE THE ELEVATION here (idempotent via
		 * bridge_escape_to_root, safe in ioctl process context), then
		 * report the version so mmrl's KsuNext.isAlive probe also
		 * succeeds.  Without the queue, becomeManager() returned success
		 * (rc=0) but the manager was never actually elevated -> all three
		 * managers reported "get root failed". */
		int32_t ver = SUKISU_PRCTL_VERSION;
		bridge_queue_become_root();
		if (access_ok(uarg, sizeof(ver)))
			__put_user(ver, (int __user *)uarg);
		pr_info("sukisu_bridge: GET_VERSION/GRANT_ROOT nr=1 -> version 0x%x rc=0\n", ver);
		rc = 0;
		return rc;
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 100) {
		/* GET_FULL_VERSION: returns the full version string in a 255-byte
		 * buffer. Spoof it so requireNewKernel() passes the v3.1.5 check. */
		char buf[255] = {0};
		strscpy(buf, SUKISU_PRCTL_FULL, sizeof(buf));
		if (access_ok(uarg, sizeof(buf)))
			rc = (copy_to_user(uarg, buf, strlen(buf) + 1) == 0) ? 0 : -EFAULT;
		pr_info("sukisu_bridge: ioctl GET_FULL_VERSION(nr=100) -> rc=%d\n", rc);
		spoofed = true;
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 13) {
		/* GET_FEATURE: read the REAL kernel feature state first (this
		 * is process context, so ksu_get_feature()'s mutex is safe).
		 * ROOT-CAUSE FIX (2026-08-22): serving only the local
		 * g_features table (initialized to all-zero) made the SukiSU
		 * manager read su_compat==0, and its startup sync then wrote
		 * SET_FEATURE(su_compat,0) back into the kernel, permanently
		 * disabling su(1) / breaking LSPosed.  Fall back to the local
		 * table only when the kernel interface is unavailable.
		 * Use the C-aligned struct ksu_get_feature_cmd (24 bytes). */
		struct ksu_get_feature_cmd fc = {};
		unsigned long fflags;
		bool ksup = false;
		u64 kval = 0;
		if (access_ok(uarg, sizeof(fc)) &&
		    copy_from_user(&fc, uarg, sizeof(fc)) == 0) {
			if (g_ksu_get_feature &&
			    fc.feature_id < SB_MAX_FEATURE_ID &&
			    ksu_get_feature_call(fc.feature_id, &kval, &ksup) == 0) {
				fc.value = kval;
				/* supported comes from the kernel; force to 1
				 * only if the kernel helper did not answer. */
				fc.supported = ksup ? 1 : 0;
				/* keep the local table in sync so the atomic
				 * (fd<0) emulation path serves the same truth */
				spin_lock_irqsave(&g_features_lock, fflags);
				g_features[fc.feature_id] = kval;
				spin_unlock_irqrestore(&g_features_lock, fflags);
				pr_info("sukisu_bridge: GET_FEATURE fid=%u val=%llu sup=%d(kernel)\n",
					fc.feature_id, fc.value, fc.supported);
			} else {
				/* kernel feature interface unavailable /
				 * out-of-range id: serve the local view and
				 * force support so toggles never grey out. */
				spin_lock_irqsave(&g_features_lock, fflags);
				if (fc.feature_id < SB_MAX_FEATURE_ID)
					fc.value = g_features[fc.feature_id];
				spin_unlock_irqrestore(&g_features_lock, fflags);
				fc.supported = 1;
				pr_info("sukisu_bridge: GET_FEATURE fid=%u val=%llu sup=1(forced)\n",
					fc.feature_id, fc.value);
			}
			rc = (copy_to_user(uarg, &fc, sizeof(fc)) == 0) ? 0 : -EFAULT;
		} else {
			rc = -EFAULT;
		}
		return rc;
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 14) {
		/* SET_FEATURE: intercept over the bridge fd too (not just the
		 * fd<0 identity fallback).  Delegate to emulate_sukisu_ioctl,
		 * which updates the local g_features table (so GET_FEATURE's
		 * fallback sees the toggle) and queues a task_work to write the
		 * real kernel feature via ksu_set_feature().  Without this,
		 * manager/ksud toggles on a valid fd were forwarded to KSU-Next
		 * and never synced the local view.
		 *
		 * PANIC-SAFETY (2026-08-22): never pass current_pt_regs() to
		 * the emulator -- in the VFS unlocked_ioctl path that frame is
		 * not guaranteed usable, and the old code dereferenced it a
		 * second time on return (kernel paging request).  Use a local
		 * pt_regs; emulate_sukisu_ioctl writes its result there. */
		struct pt_regs local_regs = {};
		struct spoof_state st = {};
		bool mgr = is_target_app();
		if (mgr)
			spoof_begin(&st);
		emulate_sukisu_ioctl(&local_regs, cmd, (unsigned long)uarg);
		if (mgr)
			spoof_end(&st);
		return (int)local_regs.regs[0];
	} else if (_IOC_TYPE(cmd) == 'K' && (_IOC_NR(cmd) == 11 ||
					     _IOC_NR(cmd) == 12)) {
		/* App profile SET (nr=12) / GET (nr=11): intercept here and
		 * translate the compact SukiSU struct (776B) into KSU-Next's
		 * 784-byte layout.  Forwarding raw to KSU-Next (below) makes it
		 * parse the profile with the wrong struct size and profile_valid()
		 * fails ("update app profile failed"), so grants never persist.
		 * emulate_sukisu_ioctl() already implements the correct
		 * translation + KSU-Next write/read; reuse it.
		 *
		 * PANIC-SAFETY: same local-pt_regs pattern as SET_FEATURE. */
		struct pt_regs local_regs = {};
		struct spoof_state st = {};
		bool mgr = is_target_app();
		if (mgr)
			spoof_begin(&st);
		emulate_sukisu_ioctl(&local_regs, cmd,
				      (unsigned long)uarg);
		if (mgr)
			spoof_end(&st);
		return (int)local_regs.regs[0];
	}

	if (spoofed) {
		pr_info("sukisu_bridge: spoofed cmd 0x%x rc=%d\n", cmd, rc);
		return rc;
	}

	/* Everything else (root grant, sepolicy, app profile, KPM ...) is handled
	 * natively by KernelSU Next through its real dispatcher. This indirect call
	 * is intentionally NOT CFI-checked (this function is no_sanitize("cfi")). */
	if (ksu_next_ioctl) {
		/* Impersonate the crowned manager uid so KSU-Next's is_manager()
		 * check passes for the SukiSU manager.  The bridge filp is handed
		 * only to the SukiSU manager process, but guard with a comm check
		 * anyway so a stray caller can never gain manager rights. */
		struct spoof_state st = {};
		bool mgr = is_target_app();
		if (mgr)
			spoof_begin(&st);
		rc = ksu_next_ioctl(filp, cmd, (unsigned long)uarg);
		if (mgr)
			spoof_end(&st);
		pr_info("sukisu_bridge: fwd cmd=0x%x rc=%ld\n",
			cmd, (long)rc);
		return rc;
	}
	rc = -ENOSYS;
	return rc;
}

/* ------------------------------------------------------------------ */
/* Part 2: reboot kprobe -> install anon fd (SukiSU handshake)         */
/* ------------------------------------------------------------------ */

/* fops are populated in bridge_init() once KSU-Next's anon_ksu_ioctl address
 * is known. .unlocked_ioctl points at our own CFI-safe bridge_ioctl. */
static struct file_operations sukisu_fops;

/* Protected fd set: the ksu fds we hand to the manager via the reboot
 * handshake (ksu_install_fd() runs in the manager's context, so we know the
 * exact fd number). The close kprobe matches against this set and, on a hit,
 * rewrites the syscall argument to -1 so the real fd survives. This is an
 * INTEGER-ONLY comparison -- the close handler never calls fcheck() and never
 * dereferences any pointer derived from the fd, so it is structurally
 * impossible for it to trigger a NULL-pointer panic. */
#define KSU_FD_MAX 16
static int g_ksu_fds[KSU_FD_MAX];
static int g_ksu_fd_cnt;
/* fd numbers are process-private, so an integer-only fd match in the global
 * close(2) kprobe would rewrite EVERY process's close(that-fd-number) and leak
 * file descriptors system-wide ("all managers lost all ability" symptom).
 * Record the pid that owns the handshake fds and only protect closes from it. */
static int g_ksu_fd_owner_pid;

/* Diagnostic: confirm the manager actually touches / closes the installed fd. */
static int bridge_release(struct inode *inode, struct file *filp)
{
	pr_info("sukisu_bridge: fd released by pid %d\n", current->pid);
	return 0;
}

struct ksu_install_fd_tw {
	struct callback_head cb;
	int __user *outp;
};

static int ksu_install_fd(int __user *outp)
{
	/* 鏁呮剰涓嶅畨瑁呮垜浠嚜宸辩殑 [ksu_driver] fd銆?
	 * 鍘熷洜锛氳嫢瀹夎锛宮anager 浼?dup 鎴戜滑鐨?fd锛堝叾 anon_inode filp 鐨?
	 * private_data == NULL锛夈€備簬鏄?nr=1 (GRANT_ROOT/becomeManager) 浼氳
	 * bridge_ioctl spoof 鎴愯繑鍥?0锛岃€屽唴鏍镐粠鏈湡姝ｆ妸 manager 鎻愭潈
	 * (escape_to_root) -> getRootShell().isRoot 姘歌繙 false ->
	 * UI 鏄剧ず鈥滆幏鍙?root 鏉冮檺澶辫触鈥濄€傜洿鎺ヨ浆鍙戝張浼氬洜 private_data==NULL
	 * 琚?KSU-Next 鐨?anon_ksu_ioctl 瑙ｅ紩鐢ㄨ€屽唴鏍?panic銆?
	 * 鏀逛负锛氳 manager 浣跨敤 KSU-Next 鑷韩 [ksu_driver] fd锛岀敱 KSU-Next
	 * 鐪熸鎵ц becomeManager 鎻愭潈銆傝韩浠芥煡璇?(GET_INFO nr=2 / GET_FEATURE
	 * nr=13 / GET_FULL_VERSION nr=100 / KPM nr=200) 鐢?syscall 灞?kretprobe
	 * 鍏滃簳 spoof锛屾棤闇€渚濊禆浠讳綍 fd锛屼笖鍗充究 fd 鍏抽棴(EBADF)涔熷湪杩斿洖澶勮鐩?
	 * 缁撴灉锛屽交搴曟秷闄?NPE銆?*/
	struct file *filp;
	int fd;

	/* NOTE: do NOT use O_CLOEXEC here. The manager keeps this fd open for
	 * the lifetime of the process and reaches it via ioctl() to fetch the
	 * full version (nr=100). O_CLOEXEC would have the kernel auto-close the
	 * fd in do_close_on_exec() during the manager's early fork/exec -- which
	 * bypasses our close(2) kprobe entirely -- leaving ioctl(nr=100) to fail
	 * with EBADF and the manager's Natives.getFullVersion() to return null
	 * (-> NullPointerException). Without CLOEXEC the fd stays open in the
	 * manager process; any explicit close() is still intercepted and defused
	 * by the close kprobe, which matches the fd number recorded here. */
	fd = get_unused_fd_flags(0);
	if (fd < 0) {
		pr_err("sukisu_bridge: get_unused_fd failed\n");
		return fd;
	}

	filp = anon_inode_getfile("[ksu_driver]", &sukisu_fops, NULL,
				  O_RDWR);
	if (IS_ERR(filp)) {
		pr_err("sukisu_bridge: anon_inode_getfile failed\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	fd_install(fd, filp);
	pr_info("sukisu_bridge: installed ksu fd %d for pid %d (manager handshake)\n",
		fd, current->pid);

	/* Remember this fd so the close kprobe can keep it open. Record the fd
	 * number (deduped); the close handler only does integer comparison.
	 * WRITE_ONCE: close_entry_handler (kprobe context) reads this count
	 * concurrently from another CPU, so publish it atomically. */
	if (READ_ONCE(g_ksu_fd_cnt) < KSU_FD_MAX) {
		int i;
		for (i = 0; i < READ_ONCE(g_ksu_fd_cnt); i++)
			if (g_ksu_fds[i] == fd)
				break;
		if (i == READ_ONCE(g_ksu_fd_cnt)) {
			g_ksu_fds[g_ksu_fd_cnt] = fd;
			WRITE_ONCE(g_ksu_fd_cnt, g_ksu_fd_cnt + 1);
		}
	}
	/* The handshake runs in the manager's task; only closes FROM THAT TASK
	 * may be protected.  Everything else must pass through untouched. */
	WRITE_ONCE(g_ksu_fd_owner_pid, current->pid);

	if (outp && copy_to_user(outp, &fd, sizeof(fd))) {
		pr_err("sukisu_bridge: failed to report fd to manager (copy_to_user err)\n");
		/* fd is now installed in the process; leave it (harmless). */
	} else {
		pr_info("sukisu_bridge: reported fd %d to manager at %px OK\n",
			fd, outp);
	}
	return fd;
}

/* task_work invokes this callback through a function pointer, so a normal
 * build would emit a CFI __cfi_check stub that references the unexported
 * __cfi_slowpath. Drop the stub with no_sanitize("cfi"); the caller still sets
 * the type id and the (stubless) target simply runs. */
static unsigned long task_work_add_addr;
static int (*real_task_work_add)(struct task_struct *, struct callback_head *,
				 int) = NULL;

/* task_work_add is invoked through an indirect call whose build-specific kCFI
 * type hash does not match our function-pointer declaration (the live kernel
 * prototypes it with enum task_work_notify_mode for the 3rd argument, while
 * we declare int), so a normal call from a CFI-checked context panics with
 * "CFI failure (target: task_work_addXX)".  Route every call through this
 * CFI-exempt wrapper, exactly like ksu_get_app_profile_call. */
static __attribute__((no_sanitize("cfi"))) int ksu_task_work_add(
	struct task_struct *task, struct callback_head *twork, int mode)
{
	if (!real_task_work_add)
		return -ENOENT;
	return real_task_work_add(task, twork, mode);
}

/* Resolve a kernel symbol address via register_kprobe.
 *
 * This is the original approach that worked on the device on 2026-08-15
 * (bridge loaded, manager connected, built-in status shown).  The
 * kallsyms_lookup_name indirection was later introduced as a suspected fix
 * for a kCFI-hashed symbol panic, but on this Wild 5.10 GKI build the very
 * act of registering a kprobe on module_kallsyms_lookup_name/kallsyms_lookup
 * _name hard-reboots the device during init_module, which is WORSE than the
 * original direct probe of the target symbol.  Revert to the direct probe.
 */
static unsigned long resolve_symbol(const char *name)
{
	struct kprobe kp = { .symbol_name = name };
	unsigned long addr = 0;

	if (register_kprobe(&kp) == 0) {
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
	}
	return addr;
}

static __attribute__((no_sanitize("cfi"))) void ksu_install_fd_tw_func(
	struct callback_head *cb)
{
	struct ksu_install_fd_tw *tw =
		container_of(cb, struct ksu_install_fd_tw, cb);
	ksu_install_fd(tw->outp);
	pr_info("sukisu_bridge: tw_func outp=%px copy_rc_pending\n", tw->outp);
	kfree(tw);
	/* Balance the try_module_get() taken in reboot_handler_pre. */
	module_put(THIS_MODULE);
}

/* kprobe invokes pre_handler through a function pointer, so a normal build
 * emits a CFI __cfi_check stub referencing the unexported __cfi_slowpath.
 * Drop it with no_sanitize("cfi"); the caller still sets the type id. */
static __attribute__((no_sanitize("cfi"))) int reboot_handler_pre(
	struct kprobe *p, struct pt_regs *regs)
{
	/* __arm64_sys_reboot is the wrapper __se_sys_reboot(const struct pt_regs
	 * *regs): its x0 argument is a POINTER to the user-space pt_regs saved at
	 * syscall entry, NOT the magic itself. Dereference it to read the real
	 * syscall arguments (x0=magic1, x1=magic2, x3=arg4=out_fd pointer). */
	struct pt_regs *usr = (struct pt_regs *)regs->regs[0];
	int magic1, magic2;

	/* PAN guard: same as svc_entry_handler -- if the reboot kprobe lands on
	 * a symbol whose x0 is not the user pt_regs* (e.g. an asm wrapper), the
	 * value is a raw user register.  Dereferencing it as pt_regs panics with
	 * "kernel access to user memory outside uaccess routines".
	 *
	 * NOTE: use the TASK_SIZE range check, NOT virt_addr_valid().  On this
	 * GKI kernel CONFIG_VMAP_STACK=y so __arm64_sys_reboot's pt_regs arg
	 * lives in the kernel vmalloc area where virt_addr_valid() returns
	 * FALSE -- which silently disabled the whole reboot handshake and made
	 * the manager report "not installed". */
	if (!usr || (unsigned long)usr < TASK_SIZE)
		return 0;
	magic1 = (int)usr->regs[0];
	magic2 = (int)usr->regs[1];

	if (magic1 == KSU_INSTALL_MAGIC1) {
		pr_info("sukisu_bridge: saw SukiSU handshake magic1=0x%08x magic2=0x%08x\n",
			magic1, magic2);
		if (magic2 == KSU_INSTALL_MAGIC2 ||
		    magic2 == KSU_INSTALL_MAGIC2_ALT) {
			struct ksu_install_fd_tw *tw;
			unsigned long arg4 = (unsigned long)usr->regs[3];

			/* SECURITY: gate the fd install on authorization.  This
			 * kprobe fires at the reboot SYSCALL ENTRY, BEFORE the
			 * kernel's CAP_SYS_BOOT permission check -- so ANY app can
			 * call reboot(0xDEADBEEF, 0xCAFEBABE) and reach this point.
			 * Without the gate an unauthorized app would: (1) get a
			 * bridge fd installed in ITS fd table, (2) be recorded as
			 * g_ksu_fd_owner_pid, and (3) have every close() of that
			 * fd number rewritten to close(-1) -- an fd leak vector.
			 * The bridge ioctls are already gated, but the fd itself
			 * and the close-protection side effects must be gated too.
			 * The legitimate manager IS authorized (it has a grant in
			 * the kernel allow_list), so this does not affect it. */
			if (!sukisu_bridge_authorized()) {
				pr_warn("sukisu_bridge: handshake denied uid=%d\n",
					current_uid().val);
				return 0;
			}

			if (!try_module_get(THIS_MODULE))
				return 0;	/* module unloading; skip fd install */
			tw = my_kzalloc(sizeof(*tw), GFP_ATOMIC);
			if (!tw) {
				module_put(THIS_MODULE);
				return 0;
			}

			tw->outp = (int __user *)arg4;
			tw->cb.func = ksu_install_fd_tw_func;

			if (ksu_task_work_add(current, &tw->cb, TWA_RESUME)) {
				kfree(tw);
				module_put(THIS_MODULE);
				pr_warn("sukisu_bridge: task_work_add failed for fd install\n");
			}
		}
	}
	return 0;
}

static struct kprobe reboot_kp = {
	.pre_handler = reboot_handler_pre,
};

static bool reboot_kp_registered;

/* reboot syscall symbol to hook for the SukiSU fd handshake. */
static char reboot_symbol[64] = "__arm64_sys_reboot";
module_param_string(reboot_symbol, reboot_symbol, sizeof(reboot_symbol), 0644);
MODULE_PARM_DESC(reboot_symbol, "reboot syscall symbol to hook for the SukiSU fd handshake");

/* Target symbol of the KSU supercall ioctl dispatcher. KSU Next mangles it
 * with an ARM CFI hash (anon_ksu_ioctl$<hash>) that varies per build, so we
 * resolve it from kallsyms at load time. Override with:
 *   insmod sukisu_bridge.ko target=anon_ksu_ioctl$<hash>
 * if auto-resolution fails. */
static char target[160] = "anon_ksu_ioctl";
module_param_string(target, target, sizeof(target), 0644);
MODULE_PARM_DESC(target, "supercall dispatcher symbol to hook (anon_ksu_ioctl$<hash>)");

/* ------------------------------------------------------------------ */
/* prctl(0xDEADBEEF) emulation                                        */
/*                                                                     */
/* The SukiSU-Ultra manager's control plane (becomeManager, version,  */
/* KPM/hook-type, SUSFS status, root grant, app profiles, ...) is     */
/* driven through prctl(0xDEADBEEF, cmd, arg1, arg2, &result) -- NOT   */
/* through /dev/ksu ioctls. KSU-Next either does not implement this   */
/* prctl interface or returns success with rtn==0 (its own           */
/* convention), while the manager requires  rtn==-1 && result==0xDEADBEEF. */
/* Without this, becomeManager() fails and the manager reports        */
/* "not installed". We hook the prctl syscall with a kretprobe (so we */
/* can override the return value) and emulate the SukiSU identity.   */
/* ------------------------------------------------------------------ */

#define PRCTL_CMD_GRANT_ROOT       0   /* su(1): "sucompat not permitted" if missing */
#define PRCTL_CMD_BECOME_MANAGER   1
#define PRCTL_CMD_GET_VERSION      2
#define PRCTL_CMD_CHECK_SAFEMODE   9
#define PRCTL_CMD_GET_APP_PROFILE   10
#define PRCTL_CMD_SET_APP_PROFILE   11
#define PRCTL_CMD_ENABLE_SU        15   /* su(1) --disable-sucompat toggles this */
#define PRCTL_CMD_GET_VERSION_FULL 30
#define PRCTL_CMD_ENABLE_KPM       100
#define PRCTL_CMD_HOOK_TYPE        101
#define PRCTL_CMD_SUSFS_STATUS     102

/* mirrors manager's Natives$SusfsFeatureStatus (15 bools). */
struct susfs_status { uint8_t s[15]; };

/* ==========================================================================
 * Root profile shim: translate the SukiSU manager's COMPACT app_profile
 * (struct sukisu_app_profile, natural alignment, emitted by the SukiSU manager)
 * into the RUNNING kernel's app_profile layout and call the kernel's native
 * ksu_set_app_profile / ksu_get_app_profile directly.
 *
 * CRITICAL: the running kernel is SukiSU Ultra's fork, NOT upstream KSU-Next.
 * This was confirmed on-device by parsing the live /data/adb/ksu/.allowlist:
 *   [magic "USK\x7f" (4)] [FILE_FORMAT_VERSION (4)] then N records of
 *   sizeof(struct app_profile) == 784 bytes, each record's ->version == 4.
 * So the kernel's struct app_profile is 784 bytes / version 4, and the
 * selinux_domain field sits at byte offset 704 (verified: the string
 * "u:r:su:s0" in the file lands at offset 704 within each record).  The
 * struct ksu_app_profile below is reverse-engineered from the device's
 * libkernelsu and reproduces that 784-byte layout EXACTLY (selinux_domain at
 * 704).  Do NOT "modernize" it to upstream KSU-Next's 762-byte natural-aligned
 * union — that would shift every root_profile field and make profile_valid()
 * reject the grant ("Selinux domain empty").
 *
 * The manager issues profile ops as prctl(0xDEADBEEF, CMD_{GET,SET}_APP_PROFILE,
 * &profile, NULL, &result).  KSU-Next does NOT speak that supercall number for
 * profiles, so we intercept the two profile subcommands here and translate.
 * ========================================================================== */

#define SU_PROFILE_VER           2
#define SU_MAX_GROUPS            32
#define SU_ROOT_SELINUX_DOMAIN   "u:r:su:s0"
/* profile_valid() requires profile->version >= KSU_APP_PROFILE_VER.  The device
 * writes/accepts version 4, so we rewrite the SukiSU manager's emitted version
 * (3) to 4 here. */
#define KSU_NEXT_PROFILE_VER     4
/* Version the SukiSU manager itself understands / emits.  Reported back on GET
 * so the manager stays consistent.  Official SukiSU-Ultra (main) manager emits
 * struct app_profile version 4 (KSU_APP_PROFILE_VER), so match it here. */
#define SUKISU_PROFILE_VER       4

/* Device (SukiSU Ultra fork) struct app_profile — 784 bytes, reverse-engineered
 * from the device's libkernelsu.  selinux_domain is at offset 704 (verified
 * against the live .allowlist).  Keep __packed and the explicit padding so this
 * stays byte-identical to what the running kernel expects. */
struct ksu_app_profile {
	u32 version;
	char key[256];
	s32 current_uid;
	u8 allow_su;
	u8 _p265[7];
	u8 use_default;
	u8 _p273[263];
	s32 rp_uid;
	s32 rp_gid;
	s32 rp_groups_count;
	s32 rp_groups[32];
	u8 _p676[4];
	u64 rp_capabilities;
	u8 _p688[16];
	char rp_selinux_domain[64];
	s32 rp_namespaces;
	u8 _p772[4];
	u32 nrp_umount_modules;
	u8 _tail[4];
} __packed;

/* SukiSU manager compact layout (manager/app/src/main/cpp/ksu.h, natural
 * alignment).  Must match what the manager's libkernelsu serializes. */
struct sukisu_cap {
	u64 effective;
	u64 permitted;
	u64 inheritable;
};
struct sukisu_root_profile {
	s32 uid;
	s32 gid;
	s32 groups_count;
	s32 groups[32];
	struct sukisu_cap capabilities;
	char selinux_domain[64];
	s32 namespaces;
	u64 flags;
};
struct sukisu_non_root_profile {
	u8 umount_modules;
};
struct sukisu_app_profile {
	u32 version;
	char key[256];
	s32 current_uid;
	u8 allow_su;
	union {
		struct {
			u8 use_default;
			char template_name[256];
			struct sukisu_root_profile profile;
		} rp_config;
		struct {
			u8 use_default;
			struct sukisu_non_root_profile profile;
		} nrp_config;
	};
};

/* KSU-Next's real setter is `int ksu_set_app_profile(struct app_profile *)`
 * (kernel/policy/allowlist.c) -- mutex + hash replace/insert, SLEEPS, so it
 * must run in process context (deferred via task_work), never from a
 * kretprobe ret handler.  The old two-arg bool typedef was an unverified
 * guess; it was never invoked while SET stayed cache-only. */
typedef int (*ksu_set_app_profile_fn)(struct ksu_app_profile *);
/* KSU-Next's real getter is `struct app_profile *ksu_get_app_profile(uid_t)`
 * (RCU + kref, see kernel/policy/allowlist.c) -- NOT a bool fn taking a
 * struct*.  The previous declaration mis-called it: the struct pointer was
 * consumed as the uid key, the returned profile was dropped, and
 * ksu_to_sukisu() translated an uninitialized struct -> KSU-Next grants
 * never surfaced.  Our struct ksu_app_profile is byte-identical to the
 * kernel's struct app_profile (784B, verified against .allowlist). */
typedef struct ksu_app_profile *(*ksu_get_app_profile_fn)(uid_t);
typedef void (*ksu_put_app_profile_fn)(struct ksu_app_profile *);
static ksu_set_app_profile_fn g_ksu_set_app_profile = NULL;
static ksu_get_app_profile_fn g_ksu_get_app_profile = NULL;
/* ksu_persistent_allow_list(): persist the kernel allow_list to
 * /data/adb/ksu/.allowlist (kernel/policy/allowlist.c).  Called after a
 * successful ksu_set_app_profile so a SET survives reboot.  Non-fatal if
 * unresolved (grant still works in-kernel, just not durable). */
typedef void (*ksu_persistent_allow_list_fn)(void);
static ksu_persistent_allow_list_fn g_ksu_persistent_allow_list = NULL;
static ksu_put_app_profile_fn g_ksu_put_app_profile = NULL;
/* KSU-Next's REAL-TIME authorization check
 * (bool __ksu_is_allow_uid(uid_t), kernel/policy/allowlist.c): RCU read,
 * non-sleeping, reflects the kernel allow_list AS THE NATIVE MANAGER CHANGES
 * IT -- a grant is visible immediately and, crucially, a REVOCATION is
 * refused on the very next call.  This replaces the seeded-snapshot as the
 * primary authorization source so "the user just revoked an app" takes
 * effect at once (the snapshot alone made revocation impossible until a
 * module reload -- a real security/usability hole).  `ksu_is_allow_uid` is a
 * macro over `__ksu_is_allow_uid`, so only the latter has a symbol. */
typedef bool (*ksu_is_allow_uid_fn)(uid_t);
static ksu_is_allow_uid_fn g_ksu_is_allow_uid = NULL;
/* KernelSU-Next's manager identity: the kernel only crowns a manager whose
 * APK signature matches its built-in EXPECTED_HASH (com.rifsxd.ksunext).
 * The user runs com.sukisu.ultra, whose uid is never crowned, so this stays
 * at the ksunext manager's uid and the SukiSU manager is rejected everywhere.
 * We rewrite it to the SukiSU manager's real uid on every ioctl it issues. */
static uid_t *g_ksu_manager_uid = NULL;

/* In-memory mirror of /data/adb/ksu/.allowlist GRANTs.  We cannot rely on
 * KSU-Next's in-kernel allow_list for read-back: on this SukiSU-Ultra fork
 * ksu_get_app_profile() enforces is_manager() and rejects the impersonated
 * uid (ksu_set_app_profile() likewise fails during seed -- see dmesg
 * "set_app_profile failed").  So at load time we parse the on-disk .allowlist
 * ourselves and answer GET_APP_PROFILE from this table.  This is what makes
 * KernelSu-managed grants visible inside the SukiSU manager. */
struct allowlist_map_entry {
	struct list_head list;
	char key[256];
	struct sukisu_app_profile sp;
};
static LIST_HEAD(g_allowlist_map);
static DEFINE_SPINLOCK(g_allowlist_lock);

/* Seed helper (sukisu_seed_allowlist): read KSU-Next's persistent .allowlist
 * and mirror GRANTs into the in-kernel allow_list at load time. */
#define SEED_ALLOWLIST_PATH   "/data/adb/ksu/.allowlist"
#define ALLOWLIST_FILE_MAGIC  0x7f4b5355u   /* ' KSU' */
static struct file *(*g_filp_open)(const char *, int, umode_t) = NULL;
static int (*g_filp_close)(struct file *, fl_owner_t) = NULL;
static ssize_t (*g_kernel_read)(struct file *, void *, size_t, loff_t *) = NULL;

/* filp_open/filp_close/kernel_read are resolved from kallsyms at load time
 * (see bridge_init), so the pointers we hold land on the .cfi_jt jump-table
 * entry for each symbol -- a `b` branch instruction -- NOT the real
 * CFI-stubbed function entry.  A CFI-checked indirect call therefore reads the
 * branch opcode as a type hash and panics with
 * "CFI failure (target: filp_openXX)".  Route every call through these
 * no_sanitize("cfi") wrappers, exactly like ksu_task_work_add() / bridge_ioctl():
 * the caller emits no CFI check, so the bl reaches .cfi_jt which jumps straight
 * into the real function body. */
static __attribute__((no_sanitize("cfi"))) struct file *my_filp_open(
	const char *path, int flags, umode_t mode)
{
	if (!g_filp_open)
		return ERR_PTR(-ENOENT);
	return g_filp_open(path, flags, mode);
}
static __attribute__((no_sanitize("cfi"))) int my_filp_close(
	struct file *fp, fl_owner_t id)
{
	if (!g_filp_close)
		return -ENOENT;
	return g_filp_close(fp, id);
}
static __attribute__((no_sanitize("cfi"))) ssize_t my_kernel_read(
	struct file *fp, void *buf, size_t count, loff_t *pos)
{
	if (!g_kernel_read)
		return -ENOENT;
	return g_kernel_read(fp, buf, count, pos);
}

/* ------------------------------------------------------------------ */
/* Manager-identity impersonation (kernel-level signature bypass).      */
/*                                                                      */
/* KSU-Next's is_manager() ultimately compares current_uid() against    */
/* its internal ksu_manager_uid.  The SukiSU manager (com.sukisu.ultra)  */
/* is NOT crowned by KSU-Next because its APK signature does not match  */
/* KSU-Next's EXPECTED_HASH, so every manager-only path (profile write, */
/* root grant, ...) rejects uid 10286.  We run IN the manager's own      */
/* process context as a kernel module, so we simply impersonate the     */
/* crowned manager uid around the calls into KSU-Next.  The swap is     */
/* fully reversed before we return.  This is the kernel-side equivalent */
/* of "we are already root-level, so the APK signature is irrelevant".  */
/* The uid we TEMPORARILY impersonate while calling into KSU-Next, so its
 * is_manager() check accepts us.  This is NOT an identity lock: which
 * processes the bridge serves is decided by is_target_app() (root identity
 * by default, per the no-fixed-uid design), independent of this value.
 * Default 10310 = com.rifsxd.ksunext, the uid KSU-Next actually crowns;
 * override with the manager_uid module param if that differs on the
 * installed kernel. */
static uid_t g_spoof_uid = 10310;
module_param_named(manager_uid, g_spoof_uid, uint, 0644);
MODULE_PARM_DESC(manager_uid,
	"uid to impersonate toward KSU-Next while bridging (default 10310); NOT an identity lock");

static __attribute__((no_sanitize("cfi"))) void spoof_begin(struct spoof_state *s)
{
	struct cred *cred = (struct cred *)current_cred();

	/* SECURITY (H2): never mutate a cred that is shared with other tasks.
	 * A fork that has not yet COW'd shares the parent's cred; writing our
	 * spoofed uid into it would silently re-identify every thread/process
	 * holding that cred.  Skip the impersonation instead -- is_target_app()
	 * will simply see the real uid, and the caller's manager-only path is
	 * rejected by KSU-Next (which is the safe, expected behavior). */
	if (cred->usage.counter != 1) {
		pr_warn("sukisu_bridge: spoof skipped (cred shared, usage=%lld uid=%d)\n",
			(long long)cred->usage.counter, cred->uid.val);
		s->active = false;
		return;
	}
	s->uid    = cred->uid;
	s->euid   = cred->euid;
	s->suid   = cred->suid;
	s->fsuid  = cred->fsuid;
	s->active = true;
	cred->uid   = g_make_kuid(current_user_ns(), g_spoof_uid);
	cred->euid  = g_make_kuid(current_user_ns(), g_spoof_uid);
	cred->suid  = g_make_kuid(current_user_ns(), g_spoof_uid);
	cred->fsuid = g_make_kuid(current_user_ns(), g_spoof_uid);
}
static void spoof_end(struct spoof_state *s)
{
	struct cred *cred = (struct cred *)current_cred();
	if (!s->active)
		return;
	/* Restore ONLY while the task still holds the spoofed identity.
	 * The spoof sets uid/euid/suid/fsuid to g_spoof_uid; while those are
	 * still in place we are inside the manager's own syscall and must
	 * unwind them.  Once the manager exec's "su" (or otherwise changes
	 * identity), current_uid() is no longer g_spoof_uid -- the helper is a
	 * different process and must KEEP its escalation (KernelSU-Next's
	 * sucompat grants root there).  We deliberately do NOT reuse
	 * is_target_app() here: after the root-identity redesign it returns
	 * true for ANY root process, and the "su" helper IS root, so it would
	 * wrongly restore and strip the helper's root. */
	if (current_uid().val != g_spoof_uid)
		return;
	cred->uid   = s->uid;
	cred->euid  = s->euid;
	cred->suid  = s->suid;
	cred->fsuid = s->fsuid;
	s->active   = false;
}

/* CFI-exempt wrapper around KSU-Next's setup_selinux() (a static symbol whose
 * build-specific kCFI hash does not match our declaration -- same rationale as
 * the other my_* helpers). */
static __attribute__((no_sanitize("cfi"))) void my_setup_selinux(
	const char *domain, struct cred *cred)
{
	if (g_setup_selinux)
		g_setup_selinux(domain, cred);
}

/* ------------------------------------------------------------------ */
/* becomeManager: elevate the SukiSU manager process to root in-kernel */
/* ------------------------------------------------------------------ */
/* KSU-Next only crowns a manager whose APK signature matches its built- */
/* in EXPECTED_HASH (com.rifsxd.ksunext).  com.sukisu.ultra's signature  */
/* does NOT match, so KSU-Next's own becomeManager rejects it and the    */
/* manager reports "get root failed".  We are a kernel module running in */
/* the manager's own process context, so we simply elevate its cred to   */
/* root ourselves -- the kernel-level equivalent of "we are already      */
/* root-level, the APK signature is irrelevant".  This makes the         */
/* manager's getRootShell().isRoot check pass and unlocks the UI.        */
static __attribute__((no_sanitize("cfi"))) void bridge_escape_to_root(void)
{
	struct cred *cred;
	kuid_t ruid;
	kgid_t rgid;

	/* Guard: task_work callbacks can theoretically be invoked after a failed
	 * init (they are only queued post-resolve, but never assume). (L4) */
	if (!g_prepare_creds || !g_commit_creds || !g_abort_creds ||
	    !g_groups_alloc || !g_groups_free || !g_make_kuid || !g_make_kgid) {
		pr_err("sukisu_bridge: escape_to_root: cred funcs unavailable\n");
		return;
	}
	cred = g_prepare_creds();
	if (!cred) {
		pr_err("sukisu_bridge: escape_to_root: prepare_creds failed\n");
		return;
	}
	if (cred->euid.val == 0) {
		/* already root, nothing to do */
		g_abort_creds(cred);
		return;
	}
	ruid = g_make_kuid(current_user_ns(), 0);
	rgid = g_make_kgid(current_user_ns(), 0);
	cred->uid   = ruid;
	cred->euid  = ruid;
	cred->suid  = ruid;
	cred->fsuid = ruid;
	cred->gid   = rgid;
	cred->egid  = rgid;
	cred->sgid  = rgid;
	cred->fsgid = rgid;
	cred->securebits = 0;
	/* grant full capabilities (CAP_DAC_READ_SEARCH etc. included) */
	memset(&cred->cap_effective, 0xff, sizeof(cred->cap_effective));
	memset(&cred->cap_permitted, 0xff, sizeof(cred->cap_permitted));
	memset(&cred->cap_bset,      0xff, sizeof(cred->cap_bset));
	/* ROOT-CAUSE FIX: KSU-Next's own escape_with_root_profile() ALSO calls
	 * setup_selinux(profile->selinux_domain) so the escalated process lands
	 * in the "u:r:ksu:s0" domain.  Without that, a uid-0 process whose SELinux
	 * domain is still untrusted_app is DENIED by the SELinux avc check (see
	 * "avc: denied { dac_read_search } ... scontext=u:r:untrusted_app:s0")
	 * the moment it touches /data/adb/modules or any root-only resource --
	 * which is exactly why libksud's module list / feature commands returned
	 * nothing and every manager "lost every capability" despite uid==0. */
	if (g_setup_selinux)
		my_setup_selinux("u:r:ksu:s0", cred);
	/* NOTE: keep the existing supplementary-group set intact.  Dropping and
	 * re-allocating it via the kallsyms-resolved groups_alloc/groups_free is
	 * unsafe on this GKI build -- a mis-resolved groups_alloc() returns a
	 * dangling group_info pointer, which later faults in in_group_p() (e.g.
	 * on any faccessat() path) and panics the device.  Root escalation only
	 * needs uid/gid==0 + full caps (set above); the original group_info is
	 * already valid, so we leave it alone. */
	g_commit_creds(cred);
	/* Register the committed cred: it is SHARED by the whole thread group
	 * (commit_creds swaps task->cred for every thread), so each thread's
	 * current_cred() == cred.  Recognition by pointer identity replaces the
	 * old for_each_thread() flag sweep, which raced with concurrent
	 * fork/exit (and with SukiSU's own ksu_mark_running_process() task-list
	 * walk) during manager startup and NULL-deref'd on a half-unlinked
	 * thread_group node.  fork() inherits the pointer, so the su helper
	 * spawned later is still recognized. */
	sukisu_cred_escalated_add(cred);
	pr_info("sukisu_bridge: escape_to_root: pid %d now uid=%d selinux=%s\n",
		current->pid, current_uid().val,
		g_setup_selinux ? "u:r:ksu:s0" : "unswitched");
}

struct br_become_root_tw {
	struct callback_head cb;
};
static __attribute__((no_sanitize("cfi"))) void br_become_root_tw_func(
	struct callback_head *cb)
{
	struct br_become_root_tw *tw =
		container_of(cb, struct br_become_root_tw, cb);
	bridge_escape_to_root();
	kfree(tw);
	/* Balance the try_module_get() in bridge_queue_become_root().  This
	 * runs in the manager's task_work; the ref held until here is what
	 * prevents module_unload() from freeing our code while this callback
	 * (and any still-queued task_work) is pending. */
	module_put(THIS_MODULE);
}
/* Queue the elevation as a task_work so it runs in process context (sleepable)
 * just before the manager returns to user space -- commit_creds() may sleep.
 *
 * PRINCIPLE.md §5.3: BECOME_MANAGER (cmd=1) must elevate the calling manager
 * process to root so that the `su` helper it fork/exec's inherits root cred
 * and getRootShell().isRoot passes.  The SukiSU manager process is NOT root
 * and NOT the KSU-Next-crowned uid, so an is_target_app()-style gate would
 * deny it (observed: "become-root denied for uid 10237" -> all managers
 * report "get root failed").  Trust is carried by the reboot-handshake fd:
 * the elevation is only reachable after the handshake authenticated the
 * caller as a manager (bridge_ioctl nr=1) or via prctl cmd=1, which in
 * practice only a manager issues.  Escalating to root grants no new
 * capability a root caller lacks (commit_creds is idempotent for euid==0),
 * so we honor the request unconditionally per the documented design. */
static void bridge_queue_become_root(void)
{
	struct br_become_root_tw *tw;

	if (!try_module_get(THIS_MODULE))
		return;		/* module is unloading; do not queue into freed code */
	tw = my_kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw) {
		module_put(THIS_MODULE);
		return;
	}
	tw->cb.func = br_become_root_tw_func;
	if (ksu_task_work_add(current, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		module_put(THIS_MODULE);
		pr_warn("sukisu_bridge: become-root task_work_add failed\n");
	}
}

/* GET is invoked inline from emulate_sukisu_prctl(), which is NOT
 * no_sanitize("cfi"); the indirect call to KSU-Next's ksu_get_app_profile()
 * trips the kernel's kCFI check (its build-specific type hash does not match
 * our function-pointer declaration) and panics the device
 * ("CFI failure (target: ksu_get_app_profileXX)").  Route it through this
 * CFI-exempt wrapper.  Caller must hold rcu_read_lock() (ksu_get_app_profile
 * iterates a RCU hash table and returns a kref'd profile). */
static __attribute__((no_sanitize("cfi"))) struct ksu_app_profile *ksu_get_app_profile_call(
	uid_t uid)
{
	if (!g_ksu_get_app_profile)
		return NULL;
	return g_ksu_get_app_profile(uid);
}
static __attribute__((no_sanitize("cfi"))) void ksu_put_app_profile_call(
	struct ksu_app_profile *kp)
{
	if (g_ksu_put_app_profile)
		g_ksu_put_app_profile(kp);
}
static __attribute__((no_sanitize("cfi"))) bool ksu_is_allow_uid_call(uid_t uid)
{
	if (!g_ksu_is_allow_uid)
		return false;
	return g_ksu_is_allow_uid(uid);
}

/* CFI-exempt wrappers around KSU-Next's ksu_set_feature/ksu_get_feature
 * (static symbols; the indirect call would otherwise trip kCFI). */
static __attribute__((no_sanitize("cfi"))) int ksu_set_feature_call(u32 fid, u64 val)
{
	if (!g_ksu_set_feature)
		return -ENOSYS;
	return g_ksu_set_feature(fid, val);
}
/* ksu_get_feature_call() reads the REAL kernel feature state (via the
 * kallsyms-resolved ksu_get_feature).  It is only usable in PROCESS context
 * (the kernel helper takes a mutex / may sleep) -- i.e. from bridge_ioctl and
 * module init, NEVER from a kretprobe ret handler.  The atomic-context
 * GET_FEATURE path (fd<0 emulation) serves the local g_features table, which
 * bridge_ioctl and init keep in sync with the kernel (see sukisu_sync_features). */
static __attribute__((no_sanitize("cfi")))
int ksu_get_feature_call(u32 fid, u64 *val, bool *sup)
{
	if (!g_ksu_get_feature)
		return -ENOSYS;
	return g_ksu_get_feature(fid, val, sup);
}

/* Seed the local g_features table from the REAL kernel feature state at module
 * load (process context, sleepable).  This is what makes the atomic-context
 * (fd<0) GET_FEATURE path report the true su_compat / sulog / ... state, so
 * the manager's startup sync does not turn OFF features the kernel has ON
 * (e.g. su_compat) -- which previously broke su(1) / LSPosed. */
static void sukisu_seed_features(void)
{
	static const u32 fids[] = { 0, 1, 2, 3, 4 }; /* SU_COMPAT..SELINUX_HIDE */
	unsigned long fflags;
	int i;

	if (!g_ksu_get_feature)
		return;
	for (i = 0; i < (int)ARRAY_SIZE(fids); i++) {
		u64 val = 0;
		bool sup = false;
		if (ksu_get_feature_call(fids[i], &val, &sup) == 0) {
			/* Restore su_compat (fid 0) if some earlier mis-sync
			 * turned it OFF -- su(1)/LSPosed depend on it.  Only do
			 * this at module load (explicit user override below). */
			if (fids[i] == 0 && val == 0 && g_ksu_set_feature) {
				pr_warn("sukisu_bridge: su_compat OFF in kernel, restoring ON\n");
				ksu_set_feature_call(0, 1);
				val = 1;
			}
			spin_lock_irqsave(&g_features_lock, fflags);
			g_features[fids[i]] = val;
			spin_unlock_irqrestore(&g_features_lock, fflags);
			pr_info("sukisu_bridge: seed feature fid=%u val=%llu sup=%d\n",
				fids[i], val, sup ? 1 : 0);
		}
	}
}

/* SET_FEATURE is deferred to task_work because ksu_set_feature() -> the
 * per-feature set_handler may sleep (mutex + file writes).  The manager's
 * feature ioctl arrives on fd==-1 and is emulated in a kretprobe return
 * handler (atomic context), so we must not call it inline.  We impersonate
 * the crowned manager uid so KSU-Next's manager_or_root() check passes.
 * NOTE: features are NOT the allow list -- this cannot clobber native grants. */
struct ksu_feature_set_tw {
	struct callback_head cb;
	u32 feature_id;
	u64 value;
};
static __attribute__((no_sanitize("cfi"))) void feature_set_tw_func(
	struct callback_head *cb)
{
	struct ksu_feature_set_tw *tw =
		container_of(cb, struct ksu_feature_set_tw, cb);
	struct spoof_state st;
	if (!g_ksu_set_feature) {
		kfree(tw);
		return;
	}
	st = (struct spoof_state){};
	spoof_begin(&st);
	bridge_escape_to_root();
	ksu_set_feature_call(tw->feature_id, tw->value);
	spoof_end(&st);
	pr_info("sukisu_bridge: feature_set_tw fid=%u val=%llu\n",
		tw->feature_id, tw->value);
	kfree(tw);
	/* Balance the try_module_get() taken when this task_work was queued. */
	module_put(THIS_MODULE);
}

static void ksu_to_sukisu(const struct ksu_app_profile *k,
			  struct sukisu_app_profile *s)
{
	int i;
	memset(s, 0, sizeof(*s));
	/* Report the version the SukiSU manager understands (it emits 3), not the
	 * KSU-Next 4 we stored, so the manager's GET stays consistent. */
	s->version = SUKISU_PROFILE_VER;
	memcpy(s->key, k->key, sizeof(s->key));
	s->current_uid = k->current_uid;
	s->allow_su = k->allow_su;
	if (k->allow_su) {
		s->rp_config.use_default = k->use_default;
		s->rp_config.profile.uid = k->rp_uid;
		s->rp_config.profile.gid = k->rp_gid;
		/* Clamp the on-disk count like sukisu_to_ksu() does: an out-of-range
		 * rp_groups_count (corrupt/misaligned .allowlist record) would let
		 * the loop below overrun s->groups[SU_MAX_GROUPS] on the stack,
		 * clobber sukisu_seed_allowlist()'s local cred pointer and panic
		 * with "kernel access to user memory outside uaccess routines". */
		s->rp_config.profile.groups_count = k->rp_groups_count;
		if (s->rp_config.profile.groups_count > SU_MAX_GROUPS)
			s->rp_config.profile.groups_count = SU_MAX_GROUPS;
		for (i = 0; i < s->rp_config.profile.groups_count; i++)
			s->rp_config.profile.groups[i] = k->rp_groups[i];
		s->rp_config.profile.capabilities.effective =
		s->rp_config.profile.capabilities.permitted =
		s->rp_config.profile.capabilities.inheritable = k->rp_capabilities;
		memcpy(s->rp_config.profile.selinux_domain, k->rp_selinux_domain,
		       sizeof(k->rp_selinux_domain));
		s->rp_config.profile.namespaces = k->rp_namespaces;
	} else {
		/* Reverse-mirror the SET mapping.  KSU-Next has NO "explicitly
		 * denied custom" state: sukisu_to_ksu() folded every non-root
		 * denial into use_default==1 (follow the system default).  So a
		 * profile read back from KSU-Next always carries use_default==1,
		 * and the correct thing to report to the SukiSU manager is
		 * DEFAULT (use_default==1) -- NOT custom.  Forcing use_default==0
		 * here made EVERY app that was not in our live g_profile_list
		 * cache (e.g. right after the .ko is reloaded) show up as a
		 * "custom / disabled" profile ("鍏抽棴鐨勮嚜瀹氫箟"), which is wrong.
		 * Apps the manager *explicitly* configured as custom-denied are
		 * still served from g_profile_list (the authoritative cache) with
		 * their real use_default==0, so they continue to display as
		 * custom.  Only the KSU-Next-mirrored read path uses this default. */
		s->nrp_config.use_default = k->nrp_umount_modules ? 0 : 1;
		s->nrp_config.profile.umount_modules = k->nrp_umount_modules;
	}
}

/* Forward direction: SukiSU compact profile (776B, natural alignment) ->
 * device kernel struct app_profile (784B, struct ksu_app_profile).  Fields
 * map 1:1 except: the SukiSU root profile carries a 3x u64 capabilities
 * struct while the device kernel stores a single u64 (effective); and the
 * SukiSU layout has a trailing u64 flags that the device kernel ignores.
 * groups_count is clamped to SU_MAX_GROUPS and an empty/oversized
 * selinux_domain is defaulted to "u:r:su:s0" so profile_valid() (which
 * requires a non-empty domain and version >= KSU_APP_PROFILE_VER) accepts
 * the grant. */
static void sukisu_to_ksu(const struct sukisu_app_profile *s,
			  struct ksu_app_profile *k)
{
	int i;
	size_t dlen;

	memset(k, 0, sizeof(*k));
	k->version = KSU_NEXT_PROFILE_VER;
	memcpy(k->key, s->key, sizeof(k->key));
	k->current_uid = s->current_uid;
	k->allow_su = s->allow_su;
	k->use_default = s->allow_su ? s->rp_config.use_default
				     : s->nrp_config.use_default;
	if (s->allow_su) {
		k->rp_uid = s->rp_config.profile.uid;
		k->rp_gid = s->rp_config.profile.gid;
		k->rp_groups_count = s->rp_config.profile.groups_count;
		if (k->rp_groups_count > SU_MAX_GROUPS)
			k->rp_groups_count = SU_MAX_GROUPS;
		for (i = 0; i < k->rp_groups_count; i++)
			k->rp_groups[i] = s->rp_config.profile.groups[i];
		k->rp_capabilities = s->rp_config.profile.capabilities.effective;
		memcpy(k->rp_selinux_domain, s->rp_config.profile.selinux_domain,
		       sizeof(k->rp_selinux_domain));
		dlen = strnlen(k->rp_selinux_domain,
			       sizeof(k->rp_selinux_domain));
		if (dlen == 0 || dlen >= sizeof(k->rp_selinux_domain))
			strscpy(k->rp_selinux_domain, SU_ROOT_SELINUX_DOMAIN,
				sizeof(k->rp_selinux_domain));
		k->rp_namespaces = s->rp_config.profile.namespaces;
	} else {
		/* KSU-Next has no custom-denied state: fold every non-root
		 * denial into the (deny) profile, mirroring ksu_to_sukisu(). */
		k->nrp_umount_modules = s->nrp_config.profile.umount_modules;
	}
}

/* Deferred kernel write for SET_APP_PROFILE: translate once at queue time
 * (the caller may be in atomic context -- a kretprobe ret handler), then run
 * the real ksu_set_app_profile() + ksu_persistent_allow_list() in process
 * context (both sleep).  try_module_get/put keeps the callback safe if the
 * module is unloaded while a write is pending. */
struct ksu_profile_set_tw {
	struct callback_head cb;
	struct ksu_app_profile profile;
};

/* CFI-exempt wrappers for the kallsyms-resolved setter / persist symbols.
 * Both land on .cfi_jt branch trampolines: a normal indirect call trips the
 * CFI type-hash check and PANICS (same reason feature_set_tw_func must go
 * through ksu_set_feature_call).  Never call g_ksu_set_app_profile /
 * g_ksu_persistent_allow_list outside these wrappers. */
static __attribute__((no_sanitize("cfi"))) int ksu_set_app_profile_call(
	struct ksu_app_profile *profile)
{
	if (!g_ksu_set_app_profile)
		return -ENOSYS;
	return g_ksu_set_app_profile(profile);
}

static __attribute__((no_sanitize("cfi"))) void ksu_persistent_allow_list_call(void)
{
	if (g_ksu_persistent_allow_list)
		g_ksu_persistent_allow_list();
}

static __attribute__((no_sanitize("cfi"))) void profile_set_tw_func(
	struct callback_head *cb)
{
	struct ksu_profile_set_tw *tw =
		container_of(cb, struct ksu_profile_set_tw, cb);
	int ret = ksu_set_app_profile_call(&tw->profile);
	if (ret == 0) {
		ksu_persistent_allow_list_call();
		pr_info("sukisu_bridge: profile_set_tw key=%.24s uid=%d allow=%d -> ok\n",
			tw->profile.key, tw->profile.current_uid,
			(int)tw->profile.allow_su);
	} else {
		pr_warn("sukisu_bridge: profile_set_tw key=%.24s uid=%d allow=%d -> %d\n",
			tw->profile.key, tw->profile.current_uid,
			(int)tw->profile.allow_su, ret);
	}
	kfree(tw);
	/* Balance the try_module_get() taken when this task_work was queued. */
	module_put(THIS_MODULE);
}

/* Queue a REAL kernel allow_list write for a SET_APP_PROFILE (write-through,
 * restoring the pre-2026 read-only behavior).  The ONLY carve-out: the
 * native crowned manager (com.rifsxd.ksunext) must never be revoked by the
 * SukiSU manager's startup-sync DENY, so a deny targeting that uid is
 * swallowed (the caller still updates its own cache). */
static void sukisu_profile_write_kernel(const struct sukisu_app_profile *sp)
{
	struct ksu_profile_set_tw *tw;
	uid_t nat = g_ksu_manager_uid ? *g_ksu_manager_uid : g_spoof_uid;

	/* SECURITY (2026-08, revised): the write-through gate is the full
	 * authorization gate, NOT escalated-cred-only.  The escalated-cred-only
	 * gate broke revocation: the SukiSU manager performs profile SETs over
	 * its bridge fd while running as its NORMAL uid (10404) -- it is not
	 * necessarily in its escalated-root state when revoking, so every revoke
	 * was silently dropped to the local cache and never hit the kernel
	 * allow_list ("revoked in SukiSU, still granted in the native manager").
	 *
	 * Is a merely-granted app allowed to rewrite the kernel allow_list a
	 * vulnerability?  No: an allowlisted app can su, i.e. is root, and a
	 * root process can trivially rewrite /data/adb/ksu/.allowlist directly.
	 * Letting it write through grants NO new capability -- it is the
	 * "minimal-privilege" gate (authorized caller may update the table it is
	 * a member of), not a security boundary.  The NATIVE-MANAGER carve-out
	 * below (deny targeting the crowned manager uid is swallowed) remains the
	 * hard protection.
	 *
	 * sukisu_bridge_authorized() is atomic-context safe: it calls
	 * __ksu_is_allow_uid() (RCU read, non-sleeping) and is_target_app()
	 * (cred pointer compare + spinlock), so it is safe from a kretprobe ret
	 * handler. */
	if (!sukisu_bridge_authorized()) {
		pr_debug("sukisu_bridge: SET cache-only (uid=%d not authorized)\n",
			current_uid().val);
		return;
	}
	if (!sp->allow_su && (uid_t)sp->current_uid == nat) {
		pr_info("sukisu_bridge: SET protect native manager uid=%d from revoke\n",
			nat);
		return;
	}
	if (!g_ksu_set_app_profile)
		return;
	if (!try_module_get(THIS_MODULE))
		return;
	tw = my_kzalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw) {
		module_put(THIS_MODULE);
		return;
	}
	sukisu_to_ksu(sp, &tw->profile);
	tw->cb.func = profile_set_tw_func;
	if (ksu_task_work_add(current, &tw->cb, TWA_RESUME)) {
		kfree(tw);
		module_put(THIS_MODULE);
		pr_warn("sukisu_bridge: profile_set task_work_add failed\n");
		return;
	}
	pr_info("sukisu_bridge: SET -> kernel key=%.24s uid=%d allow=%d\n",
		sp->key, sp->current_uid, (int)sp->allow_su);
}

struct prctl_ctx {
	int active;
	int is_ioctl;         /* 1 -> this ctx is an identity ioctl, not a prctl */
	unsigned long uregs;  /* user pt_regs* (for el0_svc_common hook) */
	unsigned long cmd;
	unsigned long arg1;   /* prctl arg2 = ksuctl data arg1 */
	unsigned long arg2;   /* prctl arg3 = ksuctl data arg2 */
	unsigned long arg5;   /* prctl arg5 = &result */
	unsigned int ioctl_cmd;  /* identity ioctl command (type 'K') */
	unsigned long ioctl_arg; /* identity ioctl arg buffer pointer */
	int ioctl_fd;            /* ioctl syscall fd (for fd<0 fallback check) */
	int is_su;               /* 1 -> intercepted execveat("su"); spoof cred, no emulate */
	struct spoof_state spoof; /* per-instance saved cred (no global, no race) */
};

/* SukiSU control-plane emulation shared by both prctl hooks.
 *  uregs : the user-space pt_regs (x0 = prctl return, x1..x4 = args)
 *  cmd/arg1/arg2/arg5 : captured prctl(cmd, arg1, arg2, &result) args
 * SukiSU's ksuctl convention: the prctl RETURN is -1 and *arg5 is written
 * with 0xDEADBEEF (KERNEL_SU_OPTION); command-specific outputs go to *arg1.. */
/* SukiSU private profile store (isolation from KSU-Next).            */
/*                                                                      */
/* The SukiSU manager's app profiles are cached here, authoritative and */
/* in the SukiSU compact layout.  GET_APP_PROFILE reads ONLY from this  */
/* store (with a clean, read-only fallback to KSU-Next's allow_list for */
/* persisted grants after a reboot), so the manager can never be handed */
/* garbage / a null-equivalent result by the shared allow_list.  SET    */
/* updates this store and also mirrors a clean, structurally-valid      */
/* ksu_app_profile into KSU-Next's allow_list for root *enforcement*    */
/* (the only channel KSU-Next uses to grant su).  Because we never read */
/* SukiSU profiles back from KSU-Next's allow_list into the SukiSU      */
/* manager's view, a bad/foreign allow_list entry can no longer crash   */
/* the SukiSU manager, and KSU-Next's own manager is never fed          */
/* SukiSU-derived garbage.                                              */
/* ------------------------------------------------------------------ */
struct sukisu_profile_node {
	struct list_head list;
	char key[256];
	struct sukisu_app_profile sp;	/* authoritative snapshot */
	u8 mirrored;			/* 1 => we have written a GRANT for this key
				 * into KSU-Next's allow_list this session. */
	u8 kernel_checked;		/* 1 => we have queried KSU-Next's allow_list
				 * for this key and cached the (possibly denied)
				 * result, so a default-denied cache entry is now
				 * authoritative and need not be re-queried. */
};
static LIST_HEAD(g_profile_list);
static DEFINE_SPINLOCK(g_profile_lock);

/* Cache a SukiSU-set profile.  Called from atomic context (kretprobe  */
/* return handler), so use GFP_ATOMIC and keep the critical section tiny. */
static void sukisu_profile_store(const struct sukisu_app_profile *sp)
{
	struct sukisu_profile_node *n;
	char key[256];

	memcpy(key, sp->key, sizeof(key));
	key[sizeof(key) - 1] = '\0';

	spin_lock(&g_profile_lock);
	list_for_each_entry(n, &g_profile_list, list) {
		if (strncmp(n->key, key, sizeof(key)) == 0) {
			n->sp = *sp;
			spin_unlock(&g_profile_lock);
			pr_debug("sukisu_bridge: profile store update key=%s allow=%d\n",
				key, sp->allow_su);
			return;
		}
	}
	spin_unlock(&g_profile_lock);

	n = my_kzalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) {
		pr_warn("sukisu_bridge: profile store alloc failed key=%s\n", key);
		return;
	}
	memcpy(n->key, key, sizeof(n->key));
	n->key[sizeof(n->key) - 1] = '\0';
	n->sp = *sp;
	spin_lock(&g_profile_lock);
	list_add(&n->list, &g_profile_list);
	spin_unlock(&g_profile_lock);
	pr_debug("sukisu_bridge: profile store add key=%s allow=%d\n",
		key, sp->allow_su);
}

/* Look up a cached SukiSU profile by key.  Returns true and fills @out. */
static bool sukisu_profile_lookup(const char *key, struct sukisu_app_profile *out)
{
	struct sukisu_profile_node *n;
	char k[256];

	memcpy(k, key, sizeof(k));
	k[sizeof(k) - 1] = '\0';
	spin_lock(&g_profile_lock);
	list_for_each_entry(n, &g_profile_list, list) {
		if (strncmp(n->key, k, sizeof(k)) == 0) {
			*out = n->sp;
			spin_unlock(&g_profile_lock);
			return true;
		}
	}
	spin_unlock(&g_profile_lock);
	return false;
}

/* Was this key GRANTED by SukiSU (and therefore mirrored into KSU-Next's
 * allow_list) earlier this session?  Used to decide whether a later DENY
 * from the SukiSU manager should revoke that grant from KSU-Next, or be
 * left alone so we don't clobber a grant owned by the KernelSu manager. */
static bool sukisu_profile_was_mirrored(const char *key)
{
	struct sukisu_profile_node *n;
	char k[256];

	memcpy(k, key, sizeof(k));
	k[sizeof(k) - 1] = '\0';
	spin_lock(&g_profile_lock);
	list_for_each_entry(n, &g_profile_list, list) {
		if (strncmp(n->key, k, sizeof(k)) == 0) {
			bool m = n->mirrored;
			spin_unlock(&g_profile_lock);
			return m;
		}
	}
	spin_unlock(&g_profile_lock);
	return false;
}

/* Record / clear the "this key was mirrored into KSU-Next" flag.  Lookups
 * are best-effort: if the node was already purged we simply have nothing to
 * update (the next SET re-creates it with mirrored=0). */
static void sukisu_profile_set_mirrored(const char *key, bool v)
{
	struct sukisu_profile_node *n;
	char k[256];

	memcpy(k, key, sizeof(k));
	k[sizeof(k) - 1] = '\0';
	spin_lock(&g_profile_lock);
	list_for_each_entry(n, &g_profile_list, list) {
		if (strncmp(n->key, k, sizeof(k)) == 0) {
			n->mirrored = v;
			break;
		}
	}
	spin_unlock(&g_profile_lock);
}

/* Has this key already been queried against KSU-Next's allow_list?  Used by
 * GET_APP_PROFILE to treat a cached default-denial as authoritative ONLY after
 * it has actually been confirmed against the kernel (so a KernelSu-manager
 * grant is not masked by the SukiSU startup sync's cached denial). */
static bool sukisu_profile_kernel_checked(const char *key)
{
	struct sukisu_profile_node *n;
	char k[256];

	memcpy(k, key, sizeof(k));
	k[sizeof(k) - 1] = '\0';
	spin_lock(&g_profile_lock);
	list_for_each_entry(n, &g_profile_list, list) {
		if (strncmp(n->key, k, sizeof(k)) == 0) {
			bool c = n->kernel_checked;
			spin_unlock(&g_profile_lock);
			return c;
		}
	}
	spin_unlock(&g_profile_lock);
	return false;
}

static void sukisu_profile_set_kernel_checked(const char *key, bool v)
{
	struct sukisu_profile_node *n;
	char k[256];

	memcpy(k, key, sizeof(k));
	k[sizeof(k) - 1] = '\0';
	spin_lock(&g_profile_lock);
	list_for_each_entry(n, &g_profile_list, list) {
		if (strncmp(n->key, k, sizeof(k)) == 0) {
			n->kernel_checked = v;
			break;
		}
	}
	spin_unlock(&g_profile_lock);
}

/* Clean, read-only fallback to KSU-Next's allow_list for profiles we did */
/* not set this session (e.g. after a reboot, when the in-memory store is  */
/* empty but the on-disk allow_list still carries the persisted grant).    */
/* We build a FRESH query from only the key -- never pre-populate kp from  */
/* the caller's (garbage) buffer -- so a corrupt allow_list entry cannot   */
/* leak back into the manager.  MUST be called with the manager identity   */
/* impersonated (the caller's entry handler already did spoof_begin()).    */
static bool sukisu_get_from_ksunext(const char *key, s32 current_uid,
				    struct sukisu_app_profile *out)
{
	struct ksu_app_profile *kp;

	if (!g_ksu_get_app_profile || !g_ksu_put_app_profile)
		return false;
	/* KSU-Next looks profiles up by uid (its in-kernel allow_list keys on
	 * uid, not package name).  Must be called under rcu_read_lock(); the
	 * returned profile is kref'd and must be put.  rcu_read_lock() is
	 * non-sleeping, so this is safe from the kretprobe return handler
	 * (preempt disabled) too. */
	rcu_read_lock();
	kp = ksu_get_app_profile_call((uid_t)current_uid);
	rcu_read_unlock();
	if (!kp)
		return false;
	pr_debug("sukisu_bridge: ksunext raw uid=%d v=%u allow=%d use_default=%d rp_uid=%d\n",
		current_uid, kp->version, kp->allow_su, kp->use_default,
		kp->rp_uid);
	ksu_to_sukisu(kp, out);
	ksu_put_app_profile_call(kp);
	return true;
}

/* Mirror KSU-Next's on-disk .allowlist grants into the in-kernel allow_list.
 *
 * Root cause this fixes: the SukiSU manager's getAppProfile() is issued over
 * binder from a *non-manager* process (e.g. the su daemon / system_server), so
 * ko's svc_entry filter (is_target_app) never intercepts that GET.  The GET
 * therefore reaches KSU-Next natively, whose in-kernel allow_list is empty
 * (the .allowlist file on disk is NOT auto-loaded into the kernel list on this
 * setup), so it returns "denied" for every app even though .allowlist holds the
 * real grants.  The manager then mirrors those denials back via SET, forever.
 *
 * Fix: at load time, read /data/adb/ksu/.allowlist, and for every entry with
 * allow_su==1 call ksu_set_app_profile(..., persist=false) to populate KSU-Next's
 * in-kernel allow_list.  Now a native GET returns the genuine grant.  persist=false
 * means we never rewrite the on-disk file (the data is already there, and a
 * re-seed on reload is idempotent).  The manager's own SET denials take the
 * skip-mirror path and do not clobber these seeded grants.
 *
 * Called once from bridge_init(); current is the insmod context, so we
 * impersonate the KSU-Next manager uid around the set_app_profile calls. */
static void allowlist_map_store(const char *key, const struct sukisu_app_profile *sp)
{
	struct allowlist_map_entry *n;
	char k[256];

	memcpy(k, key, sizeof(k));
	k[sizeof(k) - 1] = '\0';
	spin_lock(&g_allowlist_lock);
	list_for_each_entry(n, &g_allowlist_map, list) {
		if (strncmp(n->key, k, sizeof(k)) == 0) {
			n->sp = *sp;
			spin_unlock(&g_allowlist_lock);
			return;
		}
	}
	/* GFP_ATOMIC: this runs with g_allowlist_lock held AND from kretprobe
	 * return handlers (atomic context).  GFP_KERNEL would sleep -> BUG. */
	n = my_kzalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) {
		spin_unlock(&g_allowlist_lock);
		return;
	}
	memcpy(n->key, k, sizeof(n->key));
	n->sp = *sp;
	list_add(&n->list, &g_allowlist_map);
	spin_unlock(&g_allowlist_lock);
}

static bool allowlist_map_lookup(const char *key, struct sukisu_app_profile *out)
{
	struct allowlist_map_entry *n;
	char k[256];

	memcpy(k, key, sizeof(k));
	k[sizeof(k) - 1] = '\0';
	spin_lock(&g_allowlist_lock);
	list_for_each_entry(n, &g_allowlist_map, list) {
		if (strncmp(n->key, k, sizeof(k)) == 0) {
			*out = n->sp;
			spin_unlock(&g_allowlist_lock);
			return true;
		}
	}
	spin_unlock(&g_allowlist_lock);
	return false;
}

static void allowlist_map_purge(void)
{
	struct allowlist_map_entry *n, *tmp;

	spin_lock(&g_allowlist_lock);
	list_for_each_entry_safe(n, tmp, &g_allowlist_map, list) {
		list_del(&n->list);
		kfree(n);
	}
	spin_unlock(&g_allowlist_lock);
}

/* Remove a key from the on-disk .allowlist mirror.  Used when the manager
 * revokes a KernelSu-owned grant so GET stops reporting it as authorized. */
static void allowlist_map_remove(const char *key)
{
	struct allowlist_map_entry *n, *tmp;
	char k[256];

	memcpy(k, key, sizeof(k));
	k[sizeof(k) - 1] = '\0';
	spin_lock(&g_allowlist_lock);
	list_for_each_entry_safe(n, tmp, &g_allowlist_map, list) {
		if (strncmp(n->key, k, sizeof(k)) == 0) {
			list_del(&n->list);
			kfree(n);
			break;
		}
	}
	spin_unlock(&g_allowlist_lock);
}

static void sukisu_seed_allowlist(void)
{
	struct file *fp;
	loff_t off = 0;
	u32 magic, version;
	struct ksu_app_profile kp;
	int seeded = 0, skipped = 0;

	if (!g_ksu_set_app_profile) {
		pr_err("sukisu_bridge: seed: ksu_set_app_profile unresolved; skip\n");
		return;
	}
	if (!g_filp_open || !g_kernel_read || !g_filp_close) {
		pr_err("sukisu_bridge: seed: fs helpers unresolved; skip\n");
		return;
	}

	fp = my_filp_open(SEED_ALLOWLIST_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_info("sukisu_bridge: seed: open %s failed %ld (nothing to seed)\n",
			SEED_ALLOWLIST_PATH, PTR_ERR(fp));
		return;
	}
	if (my_kernel_read(fp, &magic, sizeof(magic), &off) != sizeof(magic) ||
	    magic != ALLOWLIST_FILE_MAGIC) {
		pr_err("sukisu_bridge: seed: %s bad magic 0x%x (expected 0x%x)\n",
			SEED_ALLOWLIST_PATH, magic, ALLOWLIST_FILE_MAGIC);
		goto close;
	}
	if (my_kernel_read(fp, &version, sizeof(version), &off) != sizeof(version)) {
		pr_err("sukisu_bridge: seed: %s truncated version header\n",
			SEED_ALLOWLIST_PATH);
		goto close;
	}
	pr_info("sukisu_bridge: seed: %s magic ok, format version %u\n",
		SEED_ALLOWLIST_PATH, version);

	/* NOTE: no cred impersonation needed here -- seed no longer calls
	 * ksu_set_app_profile(); it only parses the on-disk file into our
	 * memory mirror (allowlist_map).  Directly mutating the insmod
	 * process's cred would be both dead code and an unnecessary cred-race
	 * hazard. */
	while (my_kernel_read(fp, &kp, sizeof(kp), &off) == sizeof(kp)) {
		if (!kp.allow_su)
			continue;
		/* Sanity: a real profile key is a non-empty package name. Use
		 * strnlen so a corrupt record that fills key[] with non-NUL bytes
		 * cannot make strchr scan past the buffer. (M4) */
		kp.key[sizeof(kp.key) - 1] = '\0';
		if (strnlen(kp.key, sizeof(kp.key)) == 0 ||
		    strchr(kp.key, '.') == NULL) {
			skipped++;
			continue;
		}
		kp.version = KSU_NEXT_PROFILE_VER;
		/* Defensive: reject a corrupt record whose group count is negative or
		 * absurd before it reaches ksu_to_sukisu(). */
		if (kp.rp_groups_count < 0 || kp.rp_groups_count > SU_MAX_GROUPS) {
			pr_warn("sukisu_bridge: seed: %s bad rp_groups_count=%d, skip\n",
				kp.key, kp.rp_groups_count);
			skipped++;
			continue;
		}
		{
			struct sukisu_app_profile sp;
			/* Parse the on-disk grant into our memory map directly.
			 * We no longer call ksu_set_app_profile() here: it fails
			 * on this fork (is_manager rejects our impersonated uid),
			 * so the in-kernel allow_list would stay empty and GET
			 * could never see these grants. */
			ksu_to_sukisu(&kp, &sp);
			allowlist_map_store(kp.key, &sp);
			seeded++;
		}
	}

	pr_info("sukisu_bridge: seed: loaded %d grant(s) into memory map, skipped %d non-grant/invalid from %s\n",
		seeded, skipped, SEED_ALLOWLIST_PATH);
close:
	my_filp_close(fp, NULL);
}

/* Free every cached profile node (module unload). */
static void sukisu_profile_purge(void)
{
	struct sukisu_profile_node *n, *tmp;

	spin_lock(&g_profile_lock);
	list_for_each_entry_safe(n, tmp, &g_profile_list, list) {
		list_del(&n->list);
		kfree(n);
	}
	spin_unlock(&g_profile_lock);
}
static int emulate_sukisu_prctl(struct pt_regs *uregs, unsigned long cmd,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg5)
{
	/* PANIC GUARD: this emulation is reachable not only from the syscall
	 * layer (valid user pt_regs) but ALSO from bridge_ioctl() which passes
	 * current_pt_regs() -- in the VFS unlocked_ioctl path that pointer may
	 * be NULL / not the syscall frame, and we write uregs->regs[0] all over
	 * this function.  Redirect to a local dummy so no illegal write
	 * happens; the callers that need the syscall-layer return contract
	 * read regs[0] of the SAME pointer they passed, so callers passing an
	 * invalid pointer simply get rc back via their own return path. */
	struct pt_regs local_regs = {};
	int result = KSU_INSTALL_MAGIC1;
	void __user *rp = (void __user *)arg5;

	if (!uregs || (unsigned long)uregs < TASK_SIZE)
		uregs = &local_regs;

/* ------------------------------------------------------------------ */

	pr_info("sukisu_bridge: [PRCTL-DISPATCH] cmd=%lu arg1=%lx arg5=%lx is_manager_ctx_ok=%d\n",
		cmd, arg1, arg5, g_ksu_set_app_profile ? 1 : 0);

	switch (cmd) {
	case PRCTL_CMD_GRANT_ROOT:
		/* su(1) (SukiSU userspace/su/jni/su.c) escalates by calling
		 * prctl(0xDEADBEEF, CMD_GRANT_ROOT=0, 0, 0, &result) and requires
		 * result == 0xDEADBEEF or it prints "Access Denied: sucompat not
		 * permitted" and exits 1.  KSU-Next does NOT implement the prctl
		 * control plane, so without this case every su helper failed and
		 * every manager lost its root shell (module list / features /
		 * setenforce all empty) -- the "all managers lost every ability"
		 * root cause.  Elevate the calling process to root (now including
		 * the SELinux domain switch to u:r:ksu:s0) so the su helper and the
		 * ksud it exec's inherit a fully usable root.
		 *
		 * SECURITY: defense in depth -- even if some other path reached
		 * this emulation, never elevate an unauthorized process.  result
		 * is left != KERNEL_SU_OPTION so su(1) prints Access Denied. */
		if (!sukisu_bridge_authorized()) {
			int denied = 0;
			pr_warn("sukisu_bridge: GRANT_ROOT denied uid=%d\n",
				current_uid().val);
			if (access_ok(rp, 4))
				copy_to_user(rp, &denied, 4);
			uregs->regs[0] = -1;
			break;
		}
		bridge_queue_become_root();
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;

	case PRCTL_CMD_BECOME_MANAGER:
		/* Elevate the manager process itself to root so that its
		 * getRootShell().isRoot check passes (the manager fork/exec's the
		 * ksud "su" helper, which inherits the now-root cred and reports
		 * isRoot==true).  Queued via task_work because we run inside a
		 * kretprobe return handler (atomic context); bridge_escape_to_root
		 * is idempotent (no-op once euid==0).  This is the wiring for the
		 * prctl(0xDEADBEEF, cmd=1) channel the SukiSU manager actually
		 * uses -- the ioctl 'K' nr=1 path (below) is a secondary channel
		 * and is NOT taken by com.sukisu.ultra's becomeManager(). */
		if (!sukisu_bridge_authorized()) {
			int denied = 0;
			pr_warn("sukisu_bridge: BECOME_MANAGER denied uid=%d\n",
				current_uid().val);
			if (access_ok(rp, 4))
				copy_to_user(rp, &denied, 4);
			uregs->regs[0] = -1;
			break;
		}
		bridge_queue_become_root();
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;

	case PRCTL_CMD_GET_VERSION: {
		int32_t ver = SUKISU_PRCTL_VERSION;
		int32_t flags = (1U << 1); /* MANAGER only; LKM bit cleared so work status shows GKI */
		if (access_ok((void __user *)arg1, 4))
			copy_to_user((void __user *)arg1, &ver, 4);
		if (access_ok((void __user *)arg2, 4))
			copy_to_user((void __user *)arg2, &flags, 4);
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;
	}

	case PRCTL_CMD_GET_VERSION_FULL: {
		char buf[64];
		snprintf(buf, sizeof(buf), "%s", SUKISU_PRCTL_FULL);
		if (access_ok((void __user *)arg1, sizeof(buf)))
			copy_to_user((void __user *)arg1, buf, strlen(buf) + 1);
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;
	}

	case PRCTL_CMD_CHECK_SAFEMODE:
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;

	case PRCTL_CMD_ENABLE_SU:
		/* su(1) --disable-sucompat: prctl(0xDEADBEEF, CMD_ENABLE_SU=15).
		 * Toggle the real su_compat kernel feature (id 0) so su actually
		 * works/disabled.  Deferred to task_work because ksu_set_feature()
		 * takes a mutex (sleeps). */
	{
		struct ksu_feature_set_tw *tw = NULL;
		if (try_module_get(THIS_MODULE)) {
			tw = my_kzalloc(sizeof(*tw), GFP_ATOMIC);
			if (tw) {
				tw->feature_id = 0;   /* KSU_FEATURE_SU_COMPAT */
				tw->value = 0;        /* su(1) --disable-sucompat disables */
				tw->cb.func = feature_set_tw_func;
				if (ksu_task_work_add(current, &tw->cb, TWA_RESUME)) {
					kfree(tw);
					module_put(THIS_MODULE);
				}
			} else {
				module_put(THIS_MODULE);
			}
		}
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;
	}

	case PRCTL_CMD_ENABLE_KPM: {
		int enabled = 1;
		if (access_ok((void __user *)arg1, 4))
			copy_to_user((void __user *)arg1, &enabled, 4);
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;
	}

	case PRCTL_CMD_HOOK_TYPE: {
		char ht[16];
		strscpy(ht, SUKISU_HOOK_TYPE_STR, sizeof(ht));
		if (access_ok((void __user *)arg1, sizeof(ht)))
			copy_to_user((void __user *)arg1, ht, strlen(ht) + 1);
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;
	}

	case PRCTL_CMD_SUSFS_STATUS: {
		struct susfs_status s = {0};
		if (access_ok((void __user *)arg1, sizeof(s)))
			copy_to_user((void __user *)arg1, &s, sizeof(s));
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;
	}

	/* ---- Root profile: SukiSU compact <-> KSU-Next 784-byte ---- */
	case PRCTL_CMD_SET_APP_PROFILE: {
		struct sukisu_app_profile sp;
		bool was_granted;
		if (copy_from_user(&sp, (void __user *)arg1, sizeof(sp))) {
			uregs->regs[0] = 0;
			break;
		}
		/* Normalize a denied (non-root) profile before caching.  The
		 * SukiSU manager's startup "sync" writes allow_su==0 with
		 * nrp_config.use_default==0 for EVERY installed app -- an empty
		 * non-root profile (umount_modules==0).  The real SukiSU kernel
		 * reports a denied profile as use_default==1 ("follow the default"
		 * == deny), so caching the sync's use_default==0 verbatim makes
		 * the manager file every app under "custom / disabled"
		 * ("鍏抽棴鐨勮嚜瀹氫箟").  Match the kernel: a denied profile with no
		 * custom content is use_default==1.  A genuine custom-deny (one
		 * carrying umount_modules) keeps use_default==0 so it still shows
		 * as custom. */
		if (sp.allow_su == 0 && sp.nrp_config.profile.umount_modules == 0)
			sp.nrp_config.use_default = 1;
		/* 1) Authoritative cache: the SukiSU manager's view is ours alone,
		 *    fully isolated from KSU-Next's allow_list.  Done AFTER the
		 *    fallback above so the cached profile matches the enforced
		 *    grant (GET returns the same allow_su the kernel applied). */
		pr_info("sukisu_bridge: [PRCTL-SET] key=%.40s ver=%u uid=%u allow=%d use_default=%d um=%d set_fn=%d sz=%zu\n",
			sp.key, sp.version, sp.current_uid,
			sp.allow_su,
			(sp.allow_su ? sp.rp_config.use_default : sp.nrp_config.use_default),
			sp.nrp_config.profile.umount_modules,
			g_ksu_set_app_profile ? 1 : 0, sizeof(sp));
		/* 2) SukiSU view only -- KSU-Next is NEVER written by this module.
		 *
		 *    ROOT-CAUSE FIX: the previous code mirrored SET_APP_PROFILE
		 *    into KSU-Next's kernel allow_list + .allowlist.  The SukiSU
		 *    manager is NOT the crowned manager; its startup "sync"
		 *    writes allow=0 for every installed app, and the old
		 *    was_granted logic (which counted seeded KernelSu grants)
		 *    let those sync DENYs permanently revoke KernelSu's native
		 *    grants -- com.rifsxd.ksunext's grant was wiped that way.
		 *    From now on SET is a pure in-memory cache update: real root
		 *    enforcement stays exactly as KernelSu configured it, and
		 *    nothing this module does can ever alter .allowlist again. */
		was_granted = sukisu_profile_was_mirrored(sp.key);

		sukisu_profile_store(&sp);	/* cache: manager UI source of truth */

		if (sp.allow_su) {
			/* GRANT (cache-only): record in allowlist_map so GET
			 * reports it.  mirrored marks "granted by SukiSU this
			 * run" so a later DENY revokes it from OUR cache only. */
			allowlist_map_store(sp.key, &sp);
			sukisu_profile_set_mirrored(sp.key, 1);
			pr_info("sukisu_bridge: SET grant key=%.24s (cache-only, KSU-Next untouched)\n",
				sp.key);
		} else if (was_granted) {
			/* Revoke of a SukiSU-run grant (cache-only).  A seeded
			 * KernelSu-owned grant has mirrored==0, so its
			 * startup-sync DENY falls to the default branch below
			 * and the native grant is preserved. */
			allowlist_map_remove(sp.key);
			sukisu_profile_set_mirrored(sp.key, 0);
			sukisu_profile_set_kernel_checked(sp.key, 1);
			pr_info("sukisu_bridge: SET revoke key=%.24s (cache-only, KSU-Next untouched)\n",
				sp.key);
		} else {
			/* Default denial of a never-granted / KernelSu-owned app:
			 * KSU-Next and allowlist_map untouched; cache updated. */
			pr_debug("sukisu_bridge: SET skip-mirror (deny, not SukiSU-granted) key=%s\n",
				sp.key);
		}
		/* Write-through to KSU-Next (native-manager carve-out inside
		 * sukisu_profile_write_kernel). */
		sukisu_profile_write_kernel(&sp);
		if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		break;
	}
	case PRCTL_CMD_GET_APP_PROFILE: {
		struct sukisu_app_profile sp, out;
		bool cached, authoritative, is_default_denied;
		if (copy_from_user(&sp, (void __user *)arg1, sizeof(sp))) {
			uregs->regs[0] = 0;
			break;
		}
		/* The SukiSU manager's startup "sync" writes a default-denied
		 * (allow_su==0, use_default==1) profile into our cache for EVERY
		 * installed app.  That pollutes the cache so any grant owned by the
		 * KernelSu manager (which lives ONLY in KSU-Next's allow_list and is
		 * never mirrored into our cache) is masked behind a cached denial --
		 * the manager then "only sees its own settings".  Fix: a cached
		 * entry is authoritative ONLY when it is a definitive SukiSU
		 * decision -- an explicit grant (allow_su==1) or an explicit
		 * custom-deny (use_default==0).  A cached default-denial is NOT
		 * authoritative until we have actually queried KSU-Next for it
		 * (kernel_checked==1).  Every other key falls through to a read-only
		 * query of KSU-Next's allow_list, which surfaces BOTH KernelSu
		 * grants and our own mirrored grants.  kernel_checked dedups the
		 * query so we do not re-read KSU-Next on every supervisor refresh
		 * (avoids the per-app 5s freeze the old unconditional-fallback had). */
		cached = sukisu_profile_lookup(sp.key, &out);
		authoritative = false;
		if (cached) {
			is_default_denied =
				(out.allow_su == 0 &&
				 out.nrp_config.use_default == 1);
			if (!is_default_denied)
				authoritative = true;   /* explicit grant or custom-deny */
			else if (sukisu_profile_kernel_checked(sp.key))
				authoritative = true;   /* denial already confirmed vs kernel */
		}
		if (!authoritative) {
			struct sukisu_app_profile map_sp;
			if (allowlist_map_lookup(sp.key, &map_sp) &&
			    map_sp.allow_su) {
				/* KernelSu-managed grant found in our on-disk
				 * .allowlist mirror -- the reliable path, since the
				 * kernel allow_list read-back (ksu_get_app_profile)
				 * rejects our impersonated uid on this fork. */
				out = map_sp;
				pr_info("sukisu_bridge: GET from-allowlist key=%s allow=%d use_default=%d\n",
					sp.key, out.allow_su,
					(out.allow_su ? out.rp_config.use_default
						      : out.nrp_config.use_default));
			} else {
				struct sukisu_app_profile kp_out;
				if (sukisu_get_from_ksunext(sp.key,
							sp.current_uid, &kp_out)) {
					out = kp_out;
					pr_info("sukisu_bridge: GET from-ksunext key=%s allow=%d use_default=%d\n",
						sp.key, out.allow_su,
						(out.allow_su ? out.rp_config.use_default
							      : out.nrp_config.use_default));
				} else if (!cached) {
					memset(&out, 0, sizeof(out));
					out.version = SUKISU_PROFILE_VER;
					memcpy(out.key, sp.key, sizeof(out.key));
					out.current_uid = sp.current_uid;
					out.allow_su = 0;
					out.nrp_config.use_default = 1;
					pr_info("sukisu_bridge: GET default(no-kernel) key=%s use_default=1\n",
						sp.key);
				} else {
					pr_info("sukisu_bridge: GET keep-cached-denial key=%s (no record)\n",
						sp.key);
				}
			}
			/* Record the kernel query result so we don't re-query.  A
			 * default denial we just confirmed against KSU-Next stays
			 * denied; a KernelSu-owned grant now surfaces and is cached. */
			sukisu_profile_store(&out);
			sukisu_profile_set_kernel_checked(sp.key, 1);
		} else {
			pr_info("sukisu_bridge: GET cached-definitive key=%s allow=%d use_default=%d\n",
				sp.key, out.allow_su,
				(out.allow_su ? out.rp_config.use_default
					      : out.nrp_config.use_default));
		}
		if (copy_to_user((void __user *)arg1, &out, sizeof(out))) {
			uregs->regs[0] = 0;
			break;
		}
				if (access_ok(rp, 4))
			copy_to_user(rp, &result, 4);
		uregs->regs[0] = -1;
		pr_info("sukisu_bridge: GET_APP_PROFILE key=%s allow=%d use_default=%d\n",
			out.key, out.allow_su, out.nrp_config.use_default);
		break;
	}

	default:
		/* Unknown SukiSU command: NEVER spoof it. Leave KSU-Next's real
		 * response untouched so genuine root-grant / profile commands
		 * still work. Spoofing everything as success here was the cause
		 * of "instability / random crashes" -- it broke other processes
		 * that rely on KSU-Next. */
		pr_info("sukisu_bridge: prctl passthrough cmd=%lu (rtn=%ld)\n",
			cmd, (long)uregs->regs[0]);
		return 0;
	}

	pr_info("sukisu_bridge: prctl emu cmd=%lu -> rtn=%ld\n", cmd,
		(long)uregs->regs[0]);
	return 0;
}

/* SukiSU identity ioctl spoof at the SYSCALL layer (invoked from
 * svc_ret_handler). This is the fallback for the case where the manager does
 * NOT pick up OUR [ksu_driver] fd from the reboot handshake (a race seen in
 * the v3 manager: it scanned /proc/self/fd and dup()'d KSU-Next's real
 * [ksu_driver] fd instead). In that case its identity ioctls (GET_INFO nr=2,
 * GET_FULL_VERSION nr=100, GET_FEATURE nr=13, GRANT_ROOT nr=1, KPM nr=200,
 * HOOK_TYPE nr=101, ENABLE_KPM nr=102) bypass bridge_ioctl entirely and hit
 * KSU-Next's dispatcher, which does not implement nr=100 -> getFullVersion()
 * returns NULL -> Natives.b() NPE -> crash-restart loop.
 *
 * By intercepting the ioctl syscall for the manager app here (above the fd),
 * we spoof the same identity responses regardless of which fd the manager
 * used. Only type='K' identity commands are spoofed; everything else is left
 * untouched so genuine root-grant / profile ioctls still reach KSU-Next on
 * its own fd. uregs->regs[0] is overwritten with the (success) return code. */
/* SukiSU identity-ioctl command set, shared by BOTH the do_el0_svc main
 * channel (svc_entry_handler) and the __arm64_sys_ioctl fallback
 * (ioctl_entry/ret_handler).  These are the only commands emulated when an
 * ioctl arrives on an INVALID fd (the SukiSU manager's cached ksuctl fd == -1).
 * Valid-fd ioctls never reach this emulation, so the crowned KSU-Next manager
 * and every other process are completely untouched. */
static bool is_sukisu_identity_nr(unsigned int nr)
{
	switch (nr) {
	case 1:   /* GRANT_ROOT */
	case 2:   /* GET_INFO */
	case 11:  /* GET_APP_PROFILE */
	case 12:  /* SET_APP_PROFILE */
	case 13:  /* GET_FEATURE */
	case 14:  /* SET_FEATURE */
	case 100: /* GET_FULL_VERSION */
	case 101: /* HOOK_TYPE */
	case 102: /* ENABLE_KPM */
	case 200: /* KPM */
		return true;
	default:
		return false;
	}
}

static int emulate_sukisu_ioctl(struct pt_regs *uregs, unsigned int cmd,
				unsigned long arg)
{
	/* PANIC GUARD: same reasoning as emulate_sukisu_prctl -- bridge_ioctl()
	 * calls us with current_pt_regs() which may not be a usable frame in
	 * the VFS ioctl path; redirect to a local dummy to avoid the
	 * "Unable to handle kernel paging request" crash writing regs[0]. */
	struct pt_regs local_regs = {};
	void __user *uarg = (void __user *)arg;
	int rc = 0;

	if (!uregs || (unsigned long)uregs < TASK_SIZE)
		uregs = &local_regs;

	/* NOTE: we intentionally do NOT re-crown ksu_manager_uid to the SukiSU
	 * manager's own uid.  The bridge impersonates the crowned manager (uid
	 * == *g_ksu_manager_uid, i.e. the KSU-Next manager 10310) at syscall
	 * entry via spoof_begin(), so every KSU-Next control-plane check sees a
	 * legitimately-crowned manager and accepts profile writes / su.  Writing
	 * SukiSU's real uid into ksu_manager_uid would DESYNC from the spoof
	 * target and make is_manager() fail.  ksu_manager_uid is left at the
	 * value KSU-Next maintains (10310). */

	if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 2) {
		/* GET_INFO */
		struct ksu_get_info_cmd info = {};
		unsigned int wsize = (_IOC_SIZE(cmd) == sizeof(info))
					 ? sizeof(info)
					 : offsetof(struct ksu_get_info_cmd, uapi_version);
		if (access_ok(uarg, wsize) &&
		    copy_from_user(&info, uarg, wsize) == 0) {
			info.version = SUKISU_SPOOF_VERSION;
			/* LKM bit intentionally omitted (see bridge_ioctl GET_INFO note). */
			info.flags |= (1U << 1);
			/* features = max supported feature ID (see bridge_ioctl GET_INFO note):
			 * non-zero so the manager enables the SU/SULog/ADB-root/SELinux-hide
			 * toggles instead of greying them all out. */
			info.features = 5;
			if (wsize >= offsetof(struct ksu_get_info_cmd, uapi_version) + sizeof(__u32))
				info.uapi_version = 2;
			rc = (copy_to_user(uarg, &info, wsize) == 0) ? 0 : -EFAULT;
		}
	} else if (cmd == KSU_IOCTL_HOOK_TYPE) {
		struct ksu_hook_type_cmd h = {};
		strscpy(h.hook_type, SUKISU_HOOK_TYPE_STR, sizeof(h.hook_type));
		if (access_ok(uarg, sizeof(h)))
			rc = (copy_to_user(uarg, &h, sizeof(h)) == 0) ? 0 : -EFAULT;
	} else if (cmd == KSU_IOCTL_ENABLE_KPM) {
		struct ksu_enable_kpm_cmd e = {};
		e.enabled = 1;
		if (access_ok(uarg, sizeof(e)))
			rc = (copy_to_user(uarg, &e, sizeof(e)) == 0) ? 0 : -EFAULT;
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 200) {
		/* KPM */
		struct ksu_kpm_cmd kcmd = {};
		int cc = 0, res = 0;
		if (access_ok(uarg, sizeof(kcmd)) &&
		    copy_from_user(&kcmd, uarg, sizeof(kcmd)) == 0) {
			if (kcmd.control_code &&
			    access_ok((void __user *)kcmd.control_code, sizeof(cc)))
				__get_user(cc, (int __user *)kcmd.control_code);
			switch (cc) {
			case SUKISU_KPM_VERSION: {
				char ver[32] = "1.0.0-sukisu";
				if (kcmd.arg1 &&
				    access_ok((void __user *)kcmd.arg1,
					      strlen(ver) + 1))
					copy_to_user((void __user *)kcmd.arg1, ver,
						     strlen(ver) + 1);
				break;
			}
			case SUKISU_KPM_NUM:
			case SUKISU_KPM_LIST:
				res = 0;
				break;
			case 0:
				res = -1;
				break;
			default:
				res = 0;
				break;
			}
			if (kcmd.result_code &&
			    access_ok((void __user *)kcmd.result_code, sizeof(res)))
				__put_user(res, (int __user *)kcmd.result_code);
		}
		rc = 0;
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 1) {
		/* GRANT_ROOT / becomeManager + GET_VERSION: report the version so
		 * mmrl's KsuNext.isAlive probe succeeds (see bridge_ioctl nr=1).
		 *
		 * SECURITY: this emulation is reachable from three unauthenticated
		 * syscall entry points (svc ioctl fd<0, ioctl_krp, bridge fd), so
		 * gate the ELEVATION here, not just at the callers.  An
		 * unauthorized app gets -EPERM and is NOT elevated. */
		int32_t ver;
		if (!sukisu_bridge_authorized()) {
			pr_warn("sukisu_bridge: ioctl GRANT_ROOT denied uid=%d\n",
				current_uid().val);
			rc = -EPERM;
		} else {
			bridge_queue_become_root();
			ver = SUKISU_PRCTL_VERSION;
			if (access_ok(uarg, sizeof(ver)))
				__put_user(ver, (int __user *)uarg);
			rc = 0;
		}
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 100) {
		/* GET_FULL_VERSION: fill the 255-byte buffer so getFullVersion()
		 * returns a non-NULL string (kills the NPE). */
		char buf[255] = {0};
		int ak = access_ok(uarg, sizeof(buf));
		strscpy(buf, SUKISU_PRCTL_FULL, sizeof(buf));
		if (ak)
			rc = (copy_to_user(uarg, buf, strlen(buf) + 1) == 0) ? 0 : -EFAULT;
		else
			rc = -EFAULT;
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 13) {
		/* GET_FEATURE: report our in-kernel feature table.  ROOT-CAUSE
		 * FIX: we no longer call ksu_get_feature() or ksu_set_feature()
		 * -- the SukiSU manager's SU / kernel-umount / SELinux-hide /
		 * SULOG toggles would alter the SHARED kernel state that the
		 * NOT call ksu_get_feature() here: this branch runs in the
		 * kretprobe RETURN handler (atomic context) and ksu_get_feature()
		 * takes feature_mutex (sleeps) -> panic.  Read the in-kernel
		 * g_features table (kept in sync by SET_FEATURE's task_work).  The
		 * process-context bridge_ioctl path (line ~377) DOES read the real
		 * kernel state safely. */
		struct ksu_get_feature_cmd fc = {};
		unsigned long fflags;
		if (access_ok(uarg, sizeof(fc)) &&
		    copy_from_user(&fc, uarg, sizeof(fc)) == 0) {
			spin_lock_irqsave(&g_features_lock, fflags);
			if (fc.feature_id < SB_MAX_FEATURE_ID)
				fc.value = g_features[fc.feature_id];
			spin_unlock_irqrestore(&g_features_lock, fflags);
			fc.supported = 1;
			rc = (copy_to_user(uarg, &fc, sizeof(fc)) == 0) ? 0 : -EFAULT;
			pr_info("sukisu_bridge: GET_FEATURE fid=%u val=%llu sup=1\n",
				fc.feature_id, fc.value);
		} else {
			rc = -EFAULT;
		}
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 14) {
		/* SET_FEATURE: drive the REAL kernel feature via ksu_set_feature()
		 * (ids map 1:1: 0=su_compat 1=kernel_umount 2=sulog 3=adb_root
		 * 4=selinux_hide), deferred to task_work because the set_handler
		 * may sleep.  The local g_features table stays in sync as the
		 * GET fallback.  Features are NOT the allow list -- this makes
		 * the SU / SELinux-hide switches actually take effect without
		 * ever touching native grants. */
		struct ksu_set_feature_cmd sc = {};
		unsigned long fflags;
		if (access_ok(uarg, sizeof(sc)) &&
		    copy_from_user(&sc, uarg, sizeof(sc)) == 0) {
			spin_lock_irqsave(&g_features_lock, fflags);
			if (sc.feature_id < SB_MAX_FEATURE_ID)
				g_features[sc.feature_id] = sc.value;
			spin_unlock_irqrestore(&g_features_lock, fflags);
			if (g_ksu_set_feature) {
				struct ksu_feature_set_tw *tw;
				if (!try_module_get(THIS_MODULE)) {
					rc = -EBUSY;
				} else {
					tw = my_kzalloc(sizeof(*tw), GFP_ATOMIC);
					if (!tw) {
						module_put(THIS_MODULE);
						rc = -ENOMEM;
					} else {
						tw->feature_id = sc.feature_id;
						tw->value = sc.value;
						tw->cb.func = feature_set_tw_func;
						if (ksu_task_work_add(current, &tw->cb,
								      TWA_RESUME)) {
							kfree(tw);
							module_put(THIS_MODULE);
							rc = -ENOMEM;
						} else {
							pr_info("sukisu_bridge: SET_FEATURE fid=%u val=%llu -> kernel\n",
								sc.feature_id, sc.value);
							rc = 0;
						}
					}
				}
			} else {
				pr_info("sukisu_bridge: SET_FEATURE fid=%u val=%llu (local table only)\n",
					sc.feature_id, sc.value);
				rc = 0;
			}
		} else {
			rc = -EFAULT;
		}
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 12) {
		/* SET_APP_PROFILE (ioctl 'K' nr=12): the SukiSU manager writes the
		 * per-app root profile through this ioctl (not the prctl
		 * supercall).  Its struct is the compact SukiSU app_profile (776B)
		 * while KSU-Next's dispatcher expects its own 784B packed layout,
		 * so a passthrough copy_from_user over-reads / fails
		 * profile_valid().  Translate here and call KSU-Next's set routine
		 * directly, deferred to task_work because it may sleep (same as
		 * the prctl SET path). */
		struct sukisu_app_profile sp;
		if (copy_from_user(&sp, uarg, sizeof(sp))) {
			rc = -EFAULT;
			pr_info("sukisu_bridge: [SET] nr=11 COPY_FAIL\n");
		} else {
			bool was_granted;
			/* Diag (L6: pr_debug so release builds do not leak app key
			 * hashes to dmesg): dump the raw SET so we can see what the
			 * manager actually sent regardless of allow_su. */
			pr_debug("sukisu_bridge: [SET-RAW] key=%.40s ver=%u uid=%u allow=%d use_default=%d um=%d sz=%zu\n",
				sp.key, sp.version, sp.current_uid,
				sp.allow_su, sp.nrp_config.use_default,
				sp.nrp_config.profile.umount_modules,
				sizeof(sp));
			{
				unsigned char *p = (unsigned char *)&sp;
				(void)p;
				pr_debug("sukisu_bridge: [SET-HEX] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
					p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
					p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
				pr_debug("sukisu_bridge: [SET-HEX2] off264=%02x off265=%02x off266=%02x off267=%02x off268=%02x off269=%02x off270=%02x off271=%02x\n",
					p[264], p[265], p[266], p[267], p[268], p[269], p[270], p[271]);
			}
			/* Normalize a denied (non-root) profile before caching: see
			 * the prctl SET path for the rationale (the manager's sync
			 * writes use_default==0 for every app; the real kernel
			 * reports a denied profile as use_default==1). */
			if (sp.allow_su == 0 &&
			    sp.nrp_config.profile.umount_modules == 0)
				sp.nrp_config.use_default = 1;
			/* Authoritative cache only -- KSU-Next is NEVER written by
			 * this module (same ROOT-CAUSE FIX as the prctl SET path:
			 * mirroring into KSU-Next's allow_list once let the SukiSU
			 * startup-sync DENY permanently revoke KernelSu's native
			 * grants).  Real root enforcement stays exactly as KernelSu
			 * configured it; nothing here can alter .allowlist again. */
		if (sp.allow_su)
			pr_info("sukisu_bridge: [SET-GRANT] key=%.24s allow=%d ver=%u uid=%d\n",
				sp.key, sp.allow_su, sp.version, sp.current_uid);
		was_granted = sukisu_profile_was_mirrored(sp.key);
		sukisu_profile_store(&sp);
		if (sp.allow_su) {
			/* GRANT (cache-only). */
			allowlist_map_store(sp.key, &sp);
			sukisu_profile_set_mirrored(sp.key, 1);
			pr_info("sukisu_bridge: ioctl SET grant key=%.24s (cache-only, KSU-Next untouched)\n",
				sp.key);
		} else if (was_granted) {
			/* Revoke of a SukiSU-run grant (cache-only). */
			allowlist_map_remove(sp.key);
			sukisu_profile_set_mirrored(sp.key, 0);
			sukisu_profile_set_kernel_checked(sp.key, 1);
			pr_info("sukisu_bridge: ioctl SET revoke key=%.24s (cache-only, KSU-Next untouched)\n",
				sp.key);
		} else {
			/* Default denial of a never-granted / KernelSu-owned app:
			 * KSU-Next and allowlist_map untouched; cache updated. */
			pr_debug("sukisu_bridge: ioctl SET skip-mirror (deny, not SukiSU-granted) key=%s\n",
				sp.key);
		}
		/* Write-through to KSU-Next (native-manager carve-out inside
		 * sukisu_profile_write_kernel). */
		sukisu_profile_write_kernel(&sp);
		rc = 0;
		}
	} else if (_IOC_TYPE(cmd) == 'K' && _IOC_NR(cmd) == 11) {
		/* GET_APP_PROFILE (ioctl 'K' nr=11): read the per-app profile back
		 * into the manager's compact struct.  Same cache-authority rule as
		 * the prctl path: a cached default-denial is NOT authoritative until
		 * confirmed against KSU-Next (kernel_checked), so KernelSu-owned
		 * grants surface instead of being masked by the startup sync. */
		struct sukisu_app_profile sp, out;
		if (copy_from_user(&sp, uarg, sizeof(sp))) {
			rc = -EFAULT;
		} else {
			bool cached = sukisu_profile_lookup(sp.key, &out);
			bool authoritative = false;
			if (cached) {
				bool is_default_denied =
					(out.allow_su == 0 &&
					 out.nrp_config.use_default == 1);
				if (!is_default_denied)
					authoritative = true;
				else if (sukisu_profile_kernel_checked(sp.key))
					authoritative = true;
			}
			if (!authoritative) {
				struct sukisu_app_profile map_sp;
				if (allowlist_map_lookup(sp.key, &map_sp) &&
				    map_sp.allow_su) {
					out = map_sp;
					pr_info("sukisu_bridge: ioctl GET from-allowlist key=%s allow=%d\n",
						sp.key, out.allow_su);
				} else {
					struct sukisu_app_profile kp_out;
					if (sukisu_get_from_ksunext(sp.key,
							sp.current_uid,
							&kp_out)) {
						out = kp_out;
						pr_info("sukisu_bridge: ioctl GET from-ksunext key=%s allow=%d\n",
							sp.key, out.allow_su);
					} else if (!cached) {
						memset(&out, 0, sizeof(out));
						out.version = SUKISU_PROFILE_VER;
						memcpy(out.key, sp.key,
						       sizeof(out.key));
						out.current_uid = sp.current_uid;
						out.allow_su = 0;
						out.nrp_config.use_default = 1;
					}
				}
				sukisu_profile_store(&out);
				sukisu_profile_set_kernel_checked(sp.key, 1);
			}
			rc = (copy_to_user(uarg, &out, sizeof(out)) == 0)
				? 0 : -EFAULT;
			pr_info("sukisu_bridge: ioctl GET_APP_PROFILE key=%s allow=%d use_default=%d\n",
				out.key, out.allow_su,
				out.nrp_config.use_default);
		}
	}

	uregs->regs[0] = rc;
	return 0;
}

/* Only spoof identity ioctls/prctls for the SukiSU manager PROCESS.  Match
 * the THREAD-GROUP LEADER's comm, NOT the current task's comm: on Android the
 * manager's native library spawns worker threads whose task comm is e.g.
 * "libksud.so" (no "sukisu" substring), and getFullVersion()/GET_FEATURE()
 * are frequently issued on such threads.  Matching current->comm missed them,
 * so those identity ioctls slipped past the spoof -> ioctl returned -ENOTTY
 * -> getFullVersion() returned NULL -> Natives.b() NPE (random crash, esp. on
 * Activity recreation / screen rotation).  The leader's comm is always
 * "com.sukisu.ultra" (contains "sukisu") for every thread in the process. */
static __attribute__((no_sanitize("cfi"))) bool is_target_app(void)
{
	kuid_t mgr;

	/* NO FIXED-UID LOCK (per user's design): any SukiSU manager -- across
	 * all forks/branches, whose uids all differ -- is serviced once the
	 * user grants it root through another crowned manager.  At that point
	 * the manager process runs as uid 0.
	 *
	 * uid==0 -> trusted.  This is NOT a privilege escalation: a uid-0
	 * process already holds every capability the bridge can confer (it can
	 * rewrite /data/adb/ksu/.allowlist, insmod modules, patch creds).  The
	 * bridge's security boundary exists to stop NON-root apps from using
	 * reboot(0xDEADBEEF,...) + ioctl(nr=1) to become root -- those never
	 * pass this check.
	 *
	 * This also matches the upstream kernel's per-command policy
	 * (kernel/supercall/dispatch.c): GET_FEATURE / SET_FEATURE are
	 * perm_check = manager_or_root, i.e. uid 0 is explicitly allowed to
	 * read and write features.  Only GET/SET_APP_PROFILE are only_manager;
	 * the write-through gate for those is separately bounded in
	 * sukisu_profile_write_kernel() (which swallows any deny targeting the
	 * native crowned manager uid), and a root process can already rewrite
	 * .allowlist directly anyway.
	 *
	 * Earlier hardening required sukisu_cred_escalated() (i.e. root granted
	 * BY THE BRIDGE) for uid-0 callers.  That broke the SukiSU manager's
	 * worker threads: after the manager forks/exec's the ksud "su" helper,
	 * KSU-Next's own sucompat elevates those threads to uid 0 with a cred
	 * the bridge never created, so sukisu_cred_escalated() == false and
	 * every GET_FEATURE/GET_INFO on the bridge fd was denied -> feature
	 * toggles greyed out ("supported=1" never reached the manager).
	 *
	 * We deliberately do NOT match on comm, which is attacker-controlled via
	 * prctl(PR_SET_NAME).  The crowned-manager-uid path is kept as a
	 * fallback for setups where the manager is NOT root but the KSU-Next
	 * manager uid is known/resolved. */
	if (current_uid().val == 0)
		return true;
	if (g_ksu_manager_uid && *g_ksu_manager_uid != 0)
		mgr = g_make_kuid(current_user_ns(), *g_ksu_manager_uid);
	else
		mgr = g_make_kuid(current_user_ns(), g_spoof_uid);
	return uid_eq(current_uid(), mgr);
}

/* SECURITY GATE: which processes may use the bridge's privileged services
 * (become-manager elevation, GRANT_ROOT su elevation, identity-ioctl
 * spoofing, profile read/write, KSU-Next forwarding).
 *
 * The bridge is a kernel rootkit-style escalation point: without this gate,
 * ANY app could call prctl(0xDEADBEEF, 0) or ioctl(-1, 'K', 1) and be
 * elevated to uid 0 with full capabilities -- a trivial root LPE.  We only
 * serve processes that already hold root-equivalent privilege in KSU-Next's
 * model:
 *   - uid 0 (root; is_target_app covers it),
 *   - the crowned KSU-Next manager uid,
 *   - any uid that has a GRANT in the allowlist mirror (i.e. the user has
 *     explicitly authorized that app for su through the crowned manager).
 *
 * NOTE: the mirror is seeded from /data/adb/ksu/.allowlist at load time and
 * updated by SukiSU SETs.  Grants added through the crowned manager AFTER
 * module load need a module reload (or a SukiSU-side SET) to become
 * effective here.  This matches the "authorize first, then the bridge works"
 * model and is strictly safer than trusting an unauthenticated syscall. */
static bool sukisu_bridge_authorized(void)
{
	/* 1) root / crowned manager (see is_target_app: root needs the bridge
	 *    escalation mark, manager uid is always trusted). */
	if (is_target_app())
		return true;
	/* 2) REAL-TIME kernel authorization: reflects the native manager's
	 *    grants AND revocations immediately (no snapshot staleness).
	 *    This is the ONLY non-root path.  init() refuses to load the module
	 *    if __ksu_is_allow_uid could not be resolved, so the defensive
	 *    check below never triggers in practice -- but if it somehow did
	 *    (e.g. symbol later disappears), we DENY rather than fall back to
	 *    a stale snapshot that would keep revoked apps authorized. */
	if (!g_ksu_is_allow_uid)
		return false;
	return ksu_is_allow_uid_call(current_uid().val);
}

static struct kretprobe prctl_krp;
static bool prctl_krp_registered;
static char prctl_symbol[64] = "__arm64_sys_prctl";
module_param_string(prctl_symbol, prctl_symbol, sizeof(prctl_symbol), 0644);
MODULE_PARM_DESC(prctl_symbol, "prctl syscall symbol to hook for SukiSU control-plane emulation");

static __attribute__((no_sanitize("cfi"))) int prctl_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct prctl_ctx *ctx = (struct prctl_ctx *)ri->data;
	/* __arm64_sys_prctl(const struct pt_regs *regs): x0 IS the user
	 * pt_regs pointer -- same indirection as __arm64_sys_ioctl above.
	 * The prctl args (option=0xDEADBEEF, cmd, arg1, arg2, &result) must
	 * be read from the pt_regs* pointed to by x0, not from the kretprobe
	 * saveframe.  Only intercept for the SukiSU manager app -- other
	 * processes must keep talking to KSU-Next undisturbed. */
	struct pt_regs *uregs = (struct pt_regs *)regs->regs[0];
	{
		char pc[TASK_COMM_LEN];
		g_get_task_comm(pc, sizeof(pc), current->group_leader);
		if (uregs && (unsigned long)uregs >= TASK_SIZE &&
		    uregs->regs[0] == KSU_INSTALL_MAGIC1 && uregs->regs[1] == 10)
			pr_info("sukisu_bridge: prctl CMD10 from comm=%s target=%d pid=%d\n",
				pc, is_target_app(), current->pid);
	}
	if (uregs && (unsigned long)uregs >= TASK_SIZE &&
	    uregs->regs[0] == KSU_INSTALL_MAGIC1 &&
	    sukisu_bridge_authorized()) {
		ctx->active = 1;
		ctx->cmd  = uregs->regs[1];
		ctx->arg1 = uregs->regs[2];
		ctx->arg2 = uregs->regs[3];
		ctx->arg5 = uregs->regs[4];
		ctx->uregs = (unsigned long)uregs;
		pr_info("sukisu_bridge: prctl ENTRY 0xDEADBEEF cmd=%lu arg1=0x%lx arg2=0x%lx\n",
			ctx->cmd, ctx->arg1, ctx->arg2);
		return 0;
	}
	/* Non-target prctl: skip the return-probe install. */
	ctx->active = 0;
	return 1;
}

static int prctl_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct prctl_ctx *ctx = (struct prctl_ctx *)ri->data;

	if (!ctx->active)
		return 0;
	ctx->active = 0;
	if (!ctx->uregs || (unsigned long)ctx->uregs < TASK_SIZE)
		return 0;
	/* The kretprobe regs at the return site is the probe saveframe, NOT
	 * the user pt_regs -- emulate against the pt_regs* captured at entry
	 * (writing uregs->regs[0] is what makes the SukiSU return visible to
	 * the manager). */
	emulate_sukisu_prctl((struct pt_regs *)ctx->uregs,
			     ctx->cmd, ctx->arg1, ctx->arg2, ctx->arg5);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Part 2b: syscall-dispatcher kretprobe (above KSU-Next's inline hook) */
/* ------------------------------------------------------------------ */
/* KSU-Next intercepts prctl(0xDEADBEEF) via an INLINE hook on          */
/* __arm64_sys_prctl, redirecting the entry to its own handler and       */
/* returning directly -- so a kretprobe on __arm64_sys_prctl never       */
/* fires (the original function body is bypassed). To beat it we hook    */
/* the syscall DISPATCHER (el0_svc_common / invoke_syscall) which runs   */
/* ABOVE the inline hook. At its return we overwrite the user pt_regs    */
/* and the manager's output buffers with the SukiSU identity.            */
#define AARCH64_NR_prctl 167
/* aarch64 (asm-generic/unistd.h) syscall numbers */
#define AARCH64_NR_ioctl 29
#define AARCH64_NR_execve 221
#define AARCH64_NR_execveat 281

static struct kretprobe svc_krp;
static bool svc_krp_registered;
static char svc_symbol[64] = "el0_svc_common";
module_param_string(svc_symbol, svc_symbol, sizeof(svc_symbol), 0644);
MODULE_PARM_DESC(svc_symbol, "syscall dispatcher symbol hooked ABOVE KSU-Next's prctl inline hook");

/* Dedicated COLD-path kretprobe on the ioctl SYSCALL itself (see
 * ioctl_entry_handler below). Used as the RELIABLE channel for identity-ioctl
 * spoofing during cold start, where el0_svc_common's instance pool can be
 * exhausted by the syscall storm and let the manager's GET_FULL_VERSION
 * (nr=100) slip through -> -ENOTTY -> Natives.b() NPE. */
static struct kretprobe ioctl_krp;
static bool ioctl_krp_registered;

static __attribute__((no_sanitize("cfi"))) int svc_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct prctl_ctx *ctx = (struct prctl_ctx *)ri->data;
	/* el0_svc_common(struct pt_regs *regs, int scno): x0 is the user pt_regs*. */
	struct pt_regs *uregs = (struct pt_regs *)regs->regs[0];

	/* PAN guard: this kretprobe may arm on el0_svc (a bare asm label) or
	 * on a dispatcher variant where x0 is NOT a pt_regs* at all -- it is a
	 * raw user register value.  Dereferencing it as pt_regs triggers
	 * "Unable to handle kernel access to user memory outside uaccess
	 * routines" (PAN) and reboots the device.
	 *
	 * NOTE: we deliberately do NOT use virt_addr_valid() here.  On this GKI
	 * kernel CONFIG_VMAP_STACK=y, so a task's pt_regs lives in the kernel
	 * vmalloc area and virt_addr_valid() returns FALSE for it (it only
	 * covers the linear map) -- which silently disabled the whole
	 * do_el0_svc dispatcher kretprobe.  Use an address-range check instead:
	 * a genuine kernel pt_regs pointer is always >= TASK_SIZE (user
	 * addresses are strictly below it), so test for "not a user address". */
	if (!uregs || (unsigned long)uregs < TASK_SIZE)
		return 1;
	/* Only care about prctl(0xDEADBEEF, ...) from the manager app.
	 * x8 = syscall number, x0 = option. */
	if (uregs->regs[8] == AARCH64_NR_prctl) {
		/* Diagnostic: log EVERY prctl issued by the manager, showing both
		 * the option and the cmd. This reveals which channel
		 * getFullVersion() actually uses (cmd=30 / option 0xDEADBEEF, or
		 * some other option/cmd) so we can see why it is not being emulated
		 * and returns null -> NPE in Natives.b(). */
		{
			char pc[TASK_COMM_LEN];
			g_get_task_comm(pc, sizeof(pc), current->group_leader);
			/* Diagnostic: log ONLY the SukiSU control-plane prctl
			 * (option == KSU_INSTALL_MAGIC1).  Normal apps' PR_SET_VMA
			 * (0x53564d41) and the manager's own bookkeeping prctls would
			 * otherwise flood the ring buffer and bury the profile
			 * GET/SET traffic we care about. */
		if (uregs->regs[0] == KSU_INSTALL_MAGIC1)
			/* regs[] 是 u64：显式转 unsigned long long 匹配 %llu/%llx，
			 * 兼容 clang 12/14（LP64 宽松）与 clang 18（严格 -Wformat）。 */
			pr_info("sukisu_bridge: [PRCTL-ALL] cmd=%llu comm=%s arg1=%llx arg2=%llx arg5=%llx\n",
				(unsigned long long)uregs->regs[1], pc,
				(unsigned long long)uregs->regs[2],
				(unsigned long long)uregs->regs[3],
				(unsigned long long)uregs->regs[4]);
		}
		/* Intercept EVERY SukiSU control-plane command (option
		 * 0xDEADBEEF), not just becomeManager/GET_VERSION.  The manager's
		 * app-profile GET/SET (PRCTL_CMD_GET_APP_PROFILE=10 / SET=11),
		 * SU_ENABLED, ALLOW_LIST and KPM commands are all prctl-based on
		 * this fork (ksu.cc falls back to legacy_get_info()/prctl when
		 * its cached ioctl fd is -1).  Native KSU-Next manager never
		 * issues prctl(0xDEADBEEF) (it uses fd-ioctl), so this gate does
		 * NOT touch the crowned manager.
		 *
		 * SECURITY: only intercept for AUTHORIZED processes
		 * (root / crowned manager / uid with an allowlist GRANT).
		 * An unauthenticated app calling prctl(0xDEADBEEF, 0) would
		 * otherwise reach emulate_sukisu_prctl()'s GRANT_ROOT case and be
		 * elevated to uid 0 -- a trivial root LPE.  Unauthorized prctls
		 * fall through to KSU-Next (which does not implement the SukiSU
		 * control plane) and are harmless. */
		if (uregs->regs[0] == KSU_INSTALL_MAGIC1 &&
		    sukisu_bridge_authorized()) {
			ctx->active = 1;
			ctx->is_ioctl = 0;
			ctx->is_su = 0;
			ctx->uregs = (unsigned long)uregs;
			ctx->cmd  = uregs->regs[1];
			ctx->arg1 = uregs->regs[2];
			ctx->arg2 = uregs->regs[3];
			ctx->arg5 = uregs->regs[4];
			/* Impersonate the crowned manager for the duration of this
			 * syscall so KSU-Next's is_manager() check passes during
			 * execution (the spoof must be live at execution time, not
			 * only at emulation/return time). */
			spoof_begin(&ctx->spoof);
			/* Target prctl: return 0 -> install the return probe so the
			 * ret handler can emulate and undo the spoof. */
			return 0;
		}
		/* Non-target prctl: return non-zero -> kretprobe skips the
		 * return-probe install; the syscall return path costs nothing. */
		ctx->active = 0;
		ctx->is_ioctl = 0;
		ctx->is_su = 0;
		return 1;
	} else if (uregs->regs[8] == AARCH64_NR_ioctl) {
		/* SukiSU identity-ioctl, MAIN channel (PRINCIPLE.md §5.2).
		 * The manager's ksuctl fd caches -1 when the reboot-handshake
		 * fd was installed AFTER its first /proc/self/fd scan, so every
		 * identity ioctl it issues hits an INVALID fd.  On this kernel
		 * ioctl(-1, ...) returns 0 (not -EBADF) but leaves the buffer
		 * EMPTY -> getFullVersion() == NULL -> Natives.b() NPE.
		 *
		 * We intercept ONLY when fd < 0 AND the command is a SukiSU
		 * identity command.  The crowned KSU-Next manager and every
		 * other process issue ioctls on VALID fds (>= 0) and are left
		 * completely untouched -- this fd<0 gate is exactly what
		 * guarantees the native manager is never disturbed. */
		int sfd = (int)uregs->regs[0];
		unsigned int scmd = (unsigned int)uregs->regs[1];
		unsigned long sarg = (unsigned long)uregs->regs[2];

		/* SECURITY: gate on sukisu_bridge_authorized() too -- an
		 * unauthenticated app could otherwise ioctl(-1, 'K', nr=1) and be
		 * elevated (emulate_sukisu_ioctl's GRANT_ROOT case). */
		if (sfd < 0 &&
		    _IOC_TYPE(scmd) == 'K' &&
		    is_sukisu_identity_nr(_IOC_NR(scmd)) &&
		    sukisu_bridge_authorized()) {
			ctx->active = 1;
			ctx->is_ioctl = 1;
			ctx->is_su = 0;
			ctx->uregs = (unsigned long)uregs;
			ctx->ioctl_fd = sfd;
			ctx->ioctl_cmd = scmd;
			ctx->ioctl_arg = sarg;
			/* Impersonate the crowned manager for the duration of
			 * this syscall (same as the prctl branch above). */
			spoof_begin(&ctx->spoof);
			/* Target identity-ioctl: install the return probe. */
			return 0;
		}
		/* Non-target ioctl: skip return-probe install (see prctl branch). */
		ctx->active = 0;
		ctx->is_ioctl = 0;
		ctx->is_su = 0;
		return 1;
	}
	/* Non-prctl/ioctl syscall (the overwhelming majority): it still pays the
	 * kretprobe ENTRY trampoline (unavoidable while hooked on the syscall
	 * dispatcher), but returning non-zero skips the return-probe install,
	 * which removes the ENTIRE return-path cost for these syscalls. */
	ctx->active = 0;
	ctx->is_ioctl = 0;
	ctx->is_su = 0;
	return 1;
}

static int svc_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct prctl_ctx *ctx = (struct prctl_ctx *)ri->data;

	if (!ctx->active)
		return 0;
	ctx->active = 0;
	if (ctx->is_su) {
		/* execve("su"): drop the spoof, let the helper keep root.
		 * spoof_end() refrains from restoring because current is now
		 * the "su" process (is_target_app() == false). */
		pr_info("sukisu_bridge: SVC execve(\"su\") ret; leaving helper escalated\n");
		spoof_end(&ctx->spoof);
		return 0;
	}
	if (ctx->is_ioctl) {
		emulate_sukisu_ioctl((struct pt_regs *)ctx->uregs,
				     ctx->ioctl_cmd, ctx->ioctl_arg);
	} else {
		emulate_sukisu_prctl((struct pt_regs *)ctx->uregs, ctx->cmd,
				     ctx->arg1, ctx->arg2, ctx->arg5);
	}
	spoof_end(&ctx->spoof);
	return 0;
}

/* Dedicated, MUCH colder kretprobe on the ioctl SYSCALL itself.
 * __arm64_sys_ioctl(struct pt_regs *regs): regs IS the user pt_regs, so
 * regs->regs[0]=fd, regs->regs[1]=cmd, regs->regs[2]=arg.
 *
 * PURPOSE (per PRINCIPLE.md §5.2 "双通道保活"): this is the fallback channel
 * for the manager's identity ioctls when the main do_el0_svc dispatcher's
 * instance pool is exhausted (cold-start) OR -- the common case -- when the
 * manager's ksuctl holds an invalid fd (-1) because libkernelsu's static fd
 * cache was populated by scan_driver_fd() BEFORE the reboot-handshake fd was
 * installed.  Then ioctl(fd=-1, KSU_IOCTL_GET_FULL_VERSION) returns -EBADF,
 * getFullVersion() returns NULL and Natives.b() (= requireNewKernel) NPEs.
 *
 * We only record the args here (no spoof yet) and decide in the ret handler
 * whether to synthesize the SukiSU identity response: ONLY when the real
 * ioctl FAILED (regs->regs[0] < 0) AND the command is a SukiSU identity
 * command (nr 1/2/13/100).  Native KSU-Next manager ioctls succeed on their
 * real fd and are left untouched, so we never disturb the native manager. */
static int ioctl_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct prctl_ctx *ctx = (struct prctl_ctx *)ri->data;
	/* __arm64_sys_ioctl(const struct pt_regs *regs): on entry x0 IS the
	 * user pt_regs pointer.  The kretprobe `regs` is the CPU saveframe
	 * captured AT THE PROBE SITE -- regs->regs[0] is x0 (the user
	 * pt_regs*), NOT the fd!  fd/cmd/arg must be read from the pt_regs*
	 * pointed to by x0.  (Reading them from the saveframe directly made
	 * ioctl_fd a kernel-vmalloc-address low-bits value -> almost always
	 * >= 0 -> the fd<0 fallback never fired -> GET_FULL_VERSION slipped
	 * through -> NPE.  This was the regression.) */
	struct pt_regs *uregs = (struct pt_regs *)regs->regs[0];

	ctx->active = 0;
	ctx->is_ioctl = 0;
	ctx->is_su = 0;
	if (!uregs || (unsigned long)uregs < TASK_SIZE)
		return 1;
	/* Only install a return probe for the rare identity ioctls on an INVALID
	 * fd (the manager's cached ksuctl fd == -1).  Ordinary ioctls (fd >= 0,
	 * the overwhelming majority system-wide) return non-zero here, so the
	 * kretprobe skips the return-probe install entirely and costs nothing on
	 * the return path.  The authorization gate stays in the ret handler
	 * (defense in depth) and is also checked below to avoid wasting a return
	 * probe on an unauthenticated caller. */
	if ((int)uregs->regs[0] >= 0)
		return 1;
	if (_IOC_TYPE((unsigned int)uregs->regs[1]) != 'K' ||
	    !is_sukisu_identity_nr(_IOC_NR((unsigned int)uregs->regs[1])))
		return 1;
	if (!sukisu_bridge_authorized())
		return 1;
	ctx->active = 1;
	ctx->is_ioctl = 1;
	ctx->is_su = 0;
	ctx->ioctl_fd = (int)uregs->regs[0];
	ctx->ioctl_cmd = (unsigned int)uregs->regs[1];
	ctx->ioctl_arg = (unsigned long)uregs->regs[2];
	ctx->uregs = (unsigned long)uregs;
	return 0;
}

static int ioctl_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct prctl_ctx *ctx = (struct prctl_ctx *)ri->data;
	if (!ctx->active)
		return 0;
	ctx->active = 0;
	if (!ctx->is_ioctl)
		return 0;
	/* Synthesize the SukiSU identity response when the manager's ksuctl
	 * fd is INVALID (fd < 0).  libkernelsu caches scan_driver_fd() == -1
	 * when it runs BEFORE the reboot-handshake fd was installed (the
	 * requireNewKernel()/getFullVersion() call happens at the very start
	 * of MainActivity.onCreate).  ioctl(-1, KSU_IOCTL_GET_FULL_VERSION)
	 * returns 0 (not -EBADF) but leaves the buffer empty, so
	 * DEFINE_CACHED_GETTER sees g_full_version[0]=='\0' and returns
	 * false -> getFullVersion() == NULL -> Natives.b() NPE.
	 *
	 * Native KSU-Next manager ioctls use a VALID fd (>= 0) and are left
	 * completely untouched, so this fallback never disturbs the native
	 * manager.  Only the SukiSU identity commands (see
	 * is_sukisu_identity_nr: nr 1/2/11/12/13/100/101/102/200) are
	 * synthesized, and only for an invalid fd. */
	if (ctx->ioctl_fd >= 0)
		return 0;
	if (!ctx->uregs || (unsigned long)ctx->uregs < TASK_SIZE)
		return 0;
	/* SECURITY: same authorization gate as svc_entry_handler's ioctl
	 * branch -- never emulate an identity ioctl for an unauthenticated
	 * process (ioctl(-1, 'K', 1) would otherwise elevate it to root). */
	if (!sukisu_bridge_authorized())
		return 0;
	emulate_sukisu_ioctl((struct pt_regs *)ctx->uregs,
			     ctx->ioctl_cmd, ctx->ioctl_arg);
	return 0;
}

/* NOTE: KSU-Next's anon_ksu_ioctl is kCFI + Shadow-Call-Stack protected.
 * A kretprobe on it rewrites the return address and trips the CFI check,
 * panicking the device ("CFI failure (target: anon_ksu_ioctlXX)"). The
 * SukiSU manager never reaches that function anyway -- all of its identity
 * ioctls arrive on OUR [ksu_driver] fd and are served by bridge_ioctl, so
 * no hook on anon_ksu_ioctl is needed. This block is intentionally absent.
 */

/* ------------------------------------------------------------------ */
/* close(2) kprobe -> keep manager's [ksu_driver] fd open            */
/* ------------------------------------------------------------------ */
/* The SukiSU manager obtains our [ksu_driver] fd via the reboot      */
/* handshake, but then immediately close(2)s it.  libkernelsu's       */
/* init() later scans /proc/self/fd for a "[ksu_driver]" entry and    */
/* dup()s it; if that fd is already gone, init() fails and            */
/* getFullVersion()/GET_INFO return NULL/invalid -> the manager's     */
/* Natives.b() hits a NullPointerException and the app crashes.        */
/* We intercept close(2) for any fd whose file->f_op == &sukisu_fops  */
/* (including the one init() dup()s) when issued by the manager, and  */
/* turn it into close(-1) (-EBADF) so the fd stays open and init()    */
/* can dup it.  Other processes/other fds are untouched.              */
static int close_entry_handler(struct kprobe *p, struct pt_regs *regs);

static struct kprobe close_kp = {
	.pre_handler = close_entry_handler,
};
static bool close_kp_registered;

static int close_entry_handler(struct kprobe *p, struct pt_regs *regs)
{
	int fd, i;
	/* __arm64_sys_close(const struct pt_regs *regs): on entry x0 IS the
	 * user pt_regs pointer -- the fd NUMBER must be read from the pt_regs*
	 * pointed to by x0, exactly like __arm64_sys_ioctl/__arm64_sys_reboot.
	 * (Reading regs->regs[0] directly treated a kernel vmalloc address
	 * low-bits value as the fd, so it never matched g_ksu_fds and the
	 * manager's handshake fd was closed normally -- "fd released by
	 * pid ..." in dmesg -- defeating the whole close protection.) */
	struct pt_regs *uregs = (struct pt_regs *)regs->regs[0];

	/* PAN guard: same TASK_SIZE range check as the other syscall hooks. */
	if (!uregs || (unsigned long)uregs < TASK_SIZE)
		return 0;

	/* NOTE: deliberately NOT gated on is_target_app().  Our [ksu_driver]
	 * fd is installed ONLY into the process that completed the reboot
	 * handshake (the manager), so matching the fd number recorded at
	 * handshake time is itself the authentication: no other process holds
	 * that fd number bound to our filp. */

	/* This is an INTEGER-ONLY comparison: no fcheck(), no rcu, no chasing
	 * any pointer derived from the fd. Therefore it is structurally
	 * impossible for this handler to NULL-panic, no matter what fd value
	 * arrives or whether the fd is valid. */
	fd = (int)uregs->regs[0];
	if (fd < 0)
		return 0;
	/* ONLY the task that completed the reboot handshake owns the protected
	 * fds.  Gating on pid is what keeps this global close(2) kprobe from
	 * rewriting every other process's close(same-fd-number) into close(-1)
	 * and leaking fds system-wide. */
	if (current->pid != READ_ONCE(g_ksu_fd_owner_pid))
		return 0;
	/* READ_ONCE: bridge_release publishes this count from another CPU's
	 * task_work; read it atomically (M1). Integer-only comparison. */
	for (i = 0; i < READ_ONCE(g_ksu_fd_cnt); i++) {
		if (g_ksu_fds[i] == fd) {
			uregs->regs[0] = -1;
			pr_info("sukisu_bridge: protected close of ksu fd %d\n", fd);
			break;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* init / exit                                                        */
/* ------------------------------------------------------------------ */

static int __init bridge_init(void)
{
	int rc;

	/* Resolve KSU-Next's real anon_ksu_ioctl.  We forward to it only from a
	 * no_sanitize("cfi") context, so its build-specific kCFI hash is harmless.
	 *
	 * The symbol is kCFI-hashed on disk as "anon_ksu_ioctl$<md5>", so the
	 * bare name never matches -- pass the FULL hashed name via target=
	 * (e.g. target=anon_ksu_ioctl\$f519c3b32aff0ee608d23e6f8dc70ee2).
	 * No prefix-walk fallback: resolving the walker via register_kprobe
	 * (module_kallsyms_on_each_symbol) hard-reboots this GKI build during
	 * init_module, so we fail cleanly instead of crashing the device. */
	ksu_next_ioctl = (ksu_ioctl_t)resolve_symbol(target);
	if (!ksu_next_ioctl) {
		pr_err("sukisu_bridge: cannot resolve target='%s'; abort (pass the full anon_ksu_ioctl$<md5> name)\n",
		       target);
		return -ENOENT;
	}
	pr_info("sukisu_bridge: resolved forward target %pS\n",
		(void *)ksu_next_ioctl);

	/* Resolve KSU-Next's native profile functions so we can translate the
	 * SukiSU compact app_profile into KSU-Next's 784-byte layout in-kernel.
	 * try a few candidate names (the symbol may or may not be EXPORT_SYMBOL;
	 * resolve_symbol() uses kallsyms so static symbols resolve too). */
	{
		void *p;
		p = (void *)resolve_symbol("ksu_set_app_profile");
		if (!p) p = (void *)resolve_symbol("ksu_profile_set");
		if (!p) p = (void *)resolve_symbol("set_app_profile");
		g_ksu_set_app_profile = (ksu_set_app_profile_fn)p;
		p = (void *)resolve_symbol("ksu_persistent_allow_list");
		g_ksu_persistent_allow_list =
			(ksu_persistent_allow_list_fn)p;
		if (!g_ksu_persistent_allow_list)
			pr_warn("sukisu_bridge: ksu_persistent_allow_list unresolved; SET will not persist across reboot\n");
		p = (void *)resolve_symbol("ksu_get_app_profile");
		if (!p) p = (void *)resolve_symbol("ksu_profile_get");
		if (!p) p = (void *)resolve_symbol("get_app_profile");
		g_ksu_get_app_profile = (ksu_get_app_profile_fn)p;
		p = (void *)resolve_symbol("ksu_put_app_profile");
		g_ksu_put_app_profile = (ksu_put_app_profile_fn)p;
		/* Real-time authorization: __ksu_is_allow_uid(uid) reflects the
		 * native manager's grants AND revocations immediately.  This is a
		 * HARD REQUIREMENT: if the symbol cannot be resolved the module
		 * REFUSES TO LOAD (init fails -> insmod fails, equivalent to an
		 * immediate rmmod).  Without it the authorization check would
		 * silently fall back to the load-time snapshot, and a revocation
		 * made by the user would not take effect until a reload -- an
		 * unacceptable security hole (a revoked app keeps its rights). */
		p = (void *)resolve_symbol("__ksu_is_allow_uid");
		g_ksu_is_allow_uid = (ksu_is_allow_uid_fn)p;
		if (!g_ksu_is_allow_uid) {
			pr_err("sukisu_bridge: cannot resolve __ksu_is_allow_uid; refusing to load (real-time auth required)\n");
			return -ENOENT;
		}
		/* Resolve KSU-Next's manager uid so we can re-crown the SukiSU
		 * manager (see re-crown logic in emulate_sukisu_ioctl). */
		p = (void *)resolve_symbol("ksu_manager_uid");
		g_ksu_manager_uid = (uid_t *)p;
		pr_info("sukisu_bridge: profile shim set=%ps get=%ps put=%ps is_allow_uid=%ps manager_uid=%ps\n",
			g_ksu_set_app_profile, g_ksu_get_app_profile,
			g_ksu_put_app_profile, g_ksu_is_allow_uid,
			g_ksu_manager_uid);
		}

		/* Populate the fd-handling fops with our own CFI-safe bridge_ioctl. */
		sukisu_fops.owner = THIS_MODULE;
		sukisu_fops.unlocked_ioctl = bridge_ioctl;
		sukisu_fops.compat_ioctl = bridge_ioctl;
		sukisu_fops.release = bridge_release;

		/* Resolve task_work_add (absent from this kernel's Module.symvers). */
		task_work_add_addr = resolve_symbol("task_work_add");
		if (!task_work_add_addr) {
			pr_err("sukisu_bridge: cannot resolve task_work_add; abort\n");
			return -ENOENT;
		}
		real_task_work_add = (int (*)(struct task_struct *, struct callback_head *,
					      int))task_work_add_addr;

		/* Resolve cred/uid helpers (NOT exported by the running Wild kernel). */
		g_commit_creds = (void *)resolve_symbol("commit_creds");
		g_groups_alloc = (void *)resolve_symbol("groups_alloc");
		g_groups_free  = (void *)resolve_symbol("groups_free");
		g_prepare_creds = (void *)resolve_symbol("prepare_creds");
		g_abort_creds = (void *)resolve_symbol("abort_creds");
		g_make_kuid = (void *)resolve_symbol("make_kuid");
		g_make_kgid = (void *)resolve_symbol("make_kgid");
		if (!g_commit_creds || !g_groups_alloc || !g_groups_free ||
		    !g_prepare_creds || !g_abort_creds || !g_make_kuid || !g_make_kgid) {
			pr_err("sukisu_bridge: cannot resolve cred funcs; abort\n");
			return -ENOENT;
		}
		/* Resolve KSU-Next's SELinux domain switch (static, in selinux.c).
		 * Missing is NOT fatal: escalation still works, but the process keeps
		 * its original domain and root-ish accesses may be SELinux-denied. */
		g_setup_selinux = (void *)resolve_symbol("setup_selinux");
		pr_info("sukisu_bridge: setup_selinux %ps\n", g_setup_selinux);
		/* Resolve the kernel feature interface so the SukiSU manager's SU /
		 * SELinux-hide switches drive the REAL kernel feature state.  These
		 * do NOT touch the allow list, so native grants stay untouched. */
		g_ksu_set_feature = (ksu_set_feature_fn)resolve_symbol("ksu_set_feature");
		g_ksu_get_feature = (ksu_get_feature_fn)resolve_symbol("ksu_get_feature");
		pr_info("sukisu_bridge: feature shim set=%ps get=%ps\n",
			g_ksu_set_feature, g_ksu_get_feature);
		/* Seed the local feature view from the kernel so the manager never
		 * sees a bogus "feature OFF" and syncs it OFF.  In particular
		 * su_compat is ON by default in KSU-Next; serving 0 previously
		 * made the manager disable it and broke su(1)/LSPosed. */
		sukisu_seed_features();
		/* Resolve CRC-mismatched but still-exported TEXT symbols.  resolve_symbol()
		 * uses register_kprobe, which can only target functions, never data symbols
		 * (that is why manager_uid uses the native module_param_named instead). */
		g_kmalloc = (void *)resolve_symbol("__kmalloc");
		g_get_task_comm = (void *)resolve_symbol("__get_task_comm");
		if (!g_kmalloc || !g_get_task_comm) {
			pr_err("sukisu_bridge: cannot resolve crc-fix symbols; abort\n");
			return -ENOENT;
		}
	/* Install the SukiSU reboot-handshake kprobe so the manager can obtain an
	 * fd in the first place. */
	reboot_kp.symbol_name = reboot_symbol;
	rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("sukisu_bridge: register_kprobe(%s) failed (%d); manager handshake may not work\n",
		       reboot_symbol, rc);
		pr_err("sukisu_bridge: try insmod with reboot_symbol=<correct reboot syscall symbol>\n");
	} else {
		reboot_kp_registered = true;
		pr_info("sukisu_bridge: reboot handshake kprobe registered on %s\n",
			reboot_symbol);
	}

	/* Install the prctl(0xDEADBEEF) kretprobe so the manager's control plane
	 * (becomeManager / version / KPM / hook-type / SUSFS / root) registers as
	 * a genuine SukiSU kernel instead of "not installed". */
	prctl_krp.entry_handler = prctl_entry_handler;
	prctl_krp.handler = prctl_ret_handler;
	prctl_krp.data_size = sizeof(struct prctl_ctx);
	prctl_krp.maxactive = 32;
	prctl_krp.kp.symbol_name = prctl_symbol;
	rc = register_kretprobe(&prctl_krp);
	if (rc) {
		pr_err("sukisu_bridge: register_kretprobe(%s) failed (%d); prctl control-plane emulation disabled\n",
		       prctl_symbol, rc);
		pr_err("sukisu_bridge: try insmod with prctl_symbol=<correct prctl syscall symbol>\n");
	} else {
		prctl_krp_registered = true;
		pr_info("sukisu_bridge: prctl(0xDEADBEEF) kretprobe registered on %s\n",
			prctl_symbol);
	}

	/* Install the syscall-dispatcher kretprobe ABOVE KSU-Next's inline hook
	 * on __arm64_sys_prctl. KSU-Next redirects the prctl entry to its own
	 * handler and returns directly, so the kretprobe above never fires for
	 * manager prctls; this one runs after the whole syscall and overrides
	 * the result. Try a few candidate dispatcher symbols. */
	{
		static const char *const syms[] = {
			"el0_svc_common", "invoke_syscall", "el0_svc_handler",
			"do_el0_svc", NULL
		};
		int i;
		svc_krp.entry_handler = svc_entry_handler;
		svc_krp.handler = svc_ret_handler;
		svc_krp.data_size = sizeof(struct prctl_ctx);
		/* Bump maxactive: the dispatcher kretprobe arms one instance per
		 * in-flight syscall, and the manager's app-list refresh storms
		 * __arm64_sys_prctl with hundreds of concurrent getAppProfile() calls.
		 * With the default/small pool the profile GET/SET prctl(0xDEADBEEF)
		 * slips through un-intercepted, reaches KSU-Next natively with the
		 * wrong (776-byte) struct, and set_app_profile() returns false
		 * ("update app profile failed").  2048 instances × sizeof(prctl_ctx)
		 * (~200B) is ~400KB -- a reasonable balance between never dropping
		 * control-plane events and not wasting ~1.6MB (the old 8192 pool). */
		svc_krp.maxactive = 2048;
		for (i = 0; syms[i]; i++) {
			svc_krp.kp.symbol_name = syms[i];
			rc = register_kretprobe(&svc_krp);
			if (!rc) {
				svc_krp_registered = true;
				pr_info("sukisu_bridge: syscall-dispatcher kretprobe registered on %s\n",
					syms[i]);
				break;
			}
		}
		if (!svc_krp_registered)
			pr_err("sukisu_bridge: no syscall-dispatcher symbol found; prctl(0xDEADBEEF) emulation may be blocked by KSU-Next inline hook\n");
	}

	/* Dedicated identity-ioctl kretprobe on the ioctl syscall (COLD path).
	 * This is the RELIABLE channel for GET_FULL_VERSION (nr=100) etc. during
	 * cold start, where el0_svc_common's instance pool can be exhausted.
	 * el0_svc_common above remains a fallback for prctl() and any ioctl the
	 * dedicated probe misses. */
	{
		static const char *const iosyms[] = {
			"__arm64_sys_ioctl", "ksys_ioctl", "do_sys_ioctl",
			"__arm64_sys_ioctl_compat", NULL
		};
		int i;
		ioctl_krp.entry_handler = ioctl_entry_handler;
		ioctl_krp.handler = ioctl_ret_handler;
		ioctl_krp.data_size = sizeof(struct prctl_ctx);
		ioctl_krp.maxactive = 2048;
		for (i = 0; iosyms[i]; i++) {
			ioctl_krp.kp.symbol_name = iosyms[i];
			rc = register_kretprobe(&ioctl_krp);
			if (!rc) {
				ioctl_krp_registered = true;
				pr_info("sukisu_bridge: ioctl kretprobe registered on %s\n",
					iosyms[i]);
				break;
			}
		}
		if (!ioctl_krp_registered)
			pr_err("sukisu_bridge: no ioctl syscall symbol found; identity-ioctl spoof relies on el0_svc_common fallback only\n");
	}

	/* Intercept close(2) so the manager cannot close our [ksu_driver] fd;
	 * otherwise libkernelsu's init() cannot dup it and getFullVersion()
	 * returns NULL (Java NPE / random crash). */
	close_kp.symbol_name = "__arm64_sys_close";
	rc = register_kprobe(&close_kp);
	if (rc) {
		pr_err("sukisu_bridge: register_kprobe(%s) failed (%d); close protection disabled\n",
		       "__arm64_sys_close", rc);
	} else {
		close_kp_registered = true;
		pr_info("sukisu_bridge: close(2) kprobe registered on __arm64_sys_close\n");
	}

	/* Resolve fs helpers and seed KSU-Next's in-kernel allow_list from the
	 * on-disk .allowlist.  This makes native GETs (the manager's
	 * getAppProfile() goes out over binder from a non-manager process that
	 * svc_entry does not intercept) return real grants instead of "denied".
	 * Must run after g_ksu_set_app_profile is resolved above. */
	g_filp_open   = (void *)resolve_symbol("filp_open");
	g_filp_close  = (void *)resolve_symbol("filp_close");
	g_kernel_read = (void *)resolve_symbol("kernel_read");
	if (!g_kernel_read)
		g_kernel_read = (void *)resolve_symbol("__kernel_read");
	if (!g_filp_open || !g_filp_close || !g_kernel_read)
		pr_warn("sukisu_bridge: seed fs helpers unresolved; .allowlist seed skipped\n");
	sukisu_seed_allowlist();

	/* Unconditional load banner (NOT gated by SB_DEBUG): lets anyone reading
	 * `dmesg | grep sukisu_bridge` confirm the module is really loaded and
	 * report a consistent reference point when something later goes wrong. */
	pr_notice("sukisu_bridge: loaded (bridge KSU-Next -> SukiSU), ready for handshake\n");

	return 0;
}
module_init(bridge_init);

static void __exit bridge_exit(void)
{
	if (svc_krp_registered) {
		unregister_kretprobe(&svc_krp);
		svc_krp_registered = false;
	}
	if (ioctl_krp_registered) {
		unregister_kretprobe(&ioctl_krp);
		ioctl_krp_registered = false;
	}
	if (prctl_krp_registered) {
		unregister_kretprobe(&prctl_krp);
		prctl_krp_registered = false;
	}
	if (reboot_kp_registered) {
		unregister_kprobe(&reboot_kp);
		reboot_kp_registered = false;
	}
	if (close_kp_registered) {
		unregister_kprobe(&close_kp);
		close_kp_registered = false;
	}
	/* Drop the recorded fd set so a stale fd number cannot be protected after
	 * reload if the manager re-opens the bridge (L3). */
	WRITE_ONCE(g_ksu_fd_cnt, 0);
	memset(g_ksu_fds, 0, sizeof(g_ksu_fds));
	WRITE_ONCE(g_bridge_filp, NULL);
	sukisu_profile_purge();
	allowlist_map_purge();
	pr_notice("sukisu_bridge: unloaded\n");
}
module_exit(bridge_exit);

/* Build shim: when the prepared KDIR's vmlinux.symvers does not export
 * __stack_chk_guard (its ksymtab was regenerated locally with wrong CRCs /
 * STACKPROTECTOR symbols dropped), modpost fails with
 *   ERROR: modpost: "__stack_chk_guard" [...] undefined!
 * Provide it as a WEAK symbol from inside the module so the .ko links; the
 * real, kernel-provided __stack_chk_fail still resolves at load time. This is
 * purely a link shim and does NOT change runtime behaviour. The proper fix is
 * to restore the device-real vmlinux.symvers for this KDIR. */
__attribute__((weak)) unsigned long __stack_chk_guard = 0UL;
