/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __KSU_UAPI_APP_PROFILE_H
#define __KSU_UAPI_APP_PROFILE_H

#include <linux/types.h>

/*
 * app_profile layout consumed by sukisu_uapi_supercall.h (struct ksu_get/set_app_profile_cmd
 * embeds `struct app_profile profile` by value, so the type must be complete at compile time).
 *
 * The field offsets below are taken from the SukiSU manager / Xposed bridge field map and
 * MUST be re-verified against the target KernelSU Next kernel's own uapi/app_profile.h before
 * relying on any get/set_app_profile translation. They are sufficient for the kretprobe spoof
 * (which does NOT touch app_profile) to compile today.
 *
 *   key_len    @ 0
 *   key        @ 4   (package name, up to 256 bytes)
 *   uid        @ 260
 *   allow      @ 264
 *   use_default@ 272  (4-byte gap at 268 on some builds)
 *   selinux    @ 704
 */
struct app_profile {
	int key_len;                  /* @0   */
	char key[256];                /* @4   package name */
	int uid;                      /* @260 */
	int allow;                   /* @264 */
	int _gap268;                 /* @268 (4-byte gap before use_default) */
	int use_default;             /* @272 (matches manager field map) */
	char _pad[704 - 272 - 4];     /* gap before selinux */
	char selinux_policy[256];     /* ~@704 */
};

#endif /* __KSU_UAPI_APP_PROFILE_H */
