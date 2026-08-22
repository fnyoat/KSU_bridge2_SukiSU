#!/bin/bash
# KSU_bridge2_SukiSU：把已编译的 sukisu_bridge.ko 打包成 KernelSU 模块 zip。
# 每个内核一个模块包；service.sh 在开机时自动检查内核版本是否匹配，匹配才 insmod。
#
# 用法：
#   build_module.sh <ko路径> <内核分支> <模块ID后缀> <版本号> <描述>
# 示例：
#   build_module.sh sukisu_bridge.ko android12-5.10 5.10 1.0 "GKI 5.10 (android12)"
#
# 依赖：zip（宿主自带或 CI 里 apt install）
set -e

KO="${1:?usage: build_module.sh <ko> <kernel> <idsuffix> <ver> <desc>}"
KERNEL="${2:?}"
ID_SUFFIX="${3:?}"
VER="${4:?}"
DESC="${5:?}"

SCRIPT_DIR="${0%/*}"
case "$SCRIPT_DIR" in
  ""|"$0") SCRIPT_DIR="." ;;
esac
SCRIPT_DIR="$(cd "$SCRIPT_DIR" && pwd)"
OUT="$SCRIPT_DIR/dist"
STAGE="$OUT/stage-$KERNEL"
ZIP="$OUT/KSU_bridge2_SukiSU-$KERNEL.zip"

rm -rf "$STAGE"
mkdir -p "$STAGE"

# ---- module.prop（KSU 模块元数据；作者固定 fnyoat）----
cat > "$STAGE/module.prop" <<EOF
id=ksu_bridge2_sukiSU_$ID_SUFFIX
name=KSU Bridge2 SukiSU ($KERNEL)
version=$VER
versionCode=1
author=fnyoat
description=$DESC
EOF

# ---- service.sh（开机时由 ksud 派生执行）----
# 自动检查当前内核与模块匹配，匹配才 insmod；不匹配静默跳过（绝不 panic）。
# 注意：厂商定制内核（如 5.10.260-android12-Wild）的 uname -r 不含分支名
# "android12-5.10"，所以除分支名外还按 "版本号 + Android 大版本" 组合兜底匹配，
# 防止标准 GKI 与定制内核都装不上、又避免跨 Android 版本误加载。
cat > "$STAGE/service.sh" <<'EOF'
#!/system/bin/sh
# KSU_bridge2_SukiSU boot loader: check kernel compatibility, then insmod.
# __KERNEL_BRANCH__ / __KERNEL_VER__ / __KERNEL_ANDROID__ are filled at build time.
# 开机阶段由 ksud 独立执行；优先用 KernelSU 注入的 $MODDIR，兜底 ${0%/*}。
MODDIR="${MODDIR:-${0%/*}}"
KO="$MODDIR/sukisu_bridge.ko"
LOG=/data/local/tmp/ksu_bridge2_sukiSU.log
EXPORTED_KERNEL="__KERNEL_BRANCH__"
EXPORTED_VER="__KERNEL_VER__"
EXPORTED_ANDROID="__KERNEL_ANDROID__"

kernel="$(uname -r 2>/dev/null || echo unknown)"
echo "=== $(date) start kernel=$kernel exported=$EXPORTED_KERNEL ($EXPORTED_ANDROID-$EXPORTED_VER) ===" >> "$LOG"

# 1) 内核粗匹配：分支名精确匹配，或 "版本号...android大版本" 组合覆盖厂商定制名。
#    例如 android12-5.10 模块：5.10.x-android12-5.10 (GKI) 或 5.10.x-android12-Wild
#    (定制) 都能命中；android13-5.10 设备因缺 android12 而不会误加载本包。
case "$kernel" in
  *"$EXPORTED_KERNEL"*) ;;
  *"$EXPORTED_VER"*"$EXPORTED_ANDROID"*) ;;
  *)
    echo "SKIP: kernel '$kernel' does not match '$EXPORTED_KERNEL'" >> "$LOG"
    exit 0
    ;;
esac

# 2) 已加载则不重复加载
if lsmod 2>/dev/null | grep -q sukisu_bridge; then
    echo "already loaded" >> "$LOG"
    exit 0
fi

# 3) insmod。KernelSU-Next 用 ksud insmod；回退到系统 insmod。
if command -v ksud >/dev/null 2>&1; then
    if ksud insmod "$KO" >> "$LOG" 2>&1; then
        echo "LOADED via ksud" >> "$LOG"
    else
        echo "ksud insmod FAILED" >> "$LOG"
    fi
elif insmod "$KO" >> "$LOG" 2>&1; then
    echo "LOADED via insmod" >> "$LOG"
else
    echo "insmod FAILED (rc=$?)" >> "$LOG"
fi
echo "=== done ===" >> "$LOG"
EOF

# ---- customize.sh（安装时由 ksud source 执行）----
# 三重防护，把"不兼容风险"前移到安装阶段：
#   1) 内核兼容校验（与 service.sh 同一套规则）：不匹配 -> abort，安装失败且
#      模块被清理，开机绝不加载 -> 杜绝循环重启；
#   2) 警告 + 等待：强制 2 秒 + 轮询电源键最多 8 秒（按电源键立即继续），给用户
#      反应时间，避免把正在进行的工作炸掉；
#   3) insmod 前检测已有实例（lsmod | grep sukisu_bridge），已加载则跳过。
# 注意：abort() 是 installer.sh 提供的函数（会 exit 1 结束安装，预期行为）；
#       匹配路径绝不能直接 exit（source 执行会杀掉 installer）。
cat > "$STAGE/customize.sh" <<'EOF'
#!/system/bin/sh
# KSU Bridge2 SukiSU - install-time hook (sourced by ksud)
# 注意：KernelSU 用 `. $MODPATH/customize.sh` source 本脚本，此时 $0 是 "sh"，
#       ${0%/*} 解析不到模块目录！必须用 installer 提供的 $MODPATH 环境变量。
MODDIR="$MODPATH"
KO="$MODDIR/sukisu_bridge.ko"
EXPORTED_KERNEL="__KERNEL_BRANCH__"
EXPORTED_VER="__KERNEL_VER__"
EXPORTED_ANDROID="__KERNEL_ANDROID__"

kernel="$(uname -r 2>/dev/null || echo unknown)"

ui_print "=================================="
ui_print " KSU Bridge2 SukiSU"
ui_print " by fnyoat"
ui_print "=================================="

# ---- 1) 内核兼容校验 ----
case "$kernel" in
  *"$EXPORTED_KERNEL"*) ;;
  *"$EXPORTED_VER"*"$EXPORTED_ANDROID"*) ;;
  *)
    ui_print "! Kernel '$kernel' does NOT match this module"
    ui_print "! (expect $EXPORTED_KERNEL). Aborting install."
    abort "! Incompatible kernel - module NOT installed"
    ;;
esac
ui_print "- Kernel OK: $kernel"

# ---- 2) 警告 + 等待（10 秒内可按键跳过）----
ui_print "! WARNING: about to insmod on this kernel."
ui_print "! If the module is incompatible the device may PANIC/reboot."
ui_print "! - Mandatory 2s wait..."
sleep 2
ui_print "! - Press VOLUME to continue now (auto in 8s)."
key_pressed=0
end=$(( $(date +%s) + 8 ))
while [ "$(date +%s)" -lt "$end" ]; do
    for dev in /dev/input/event*; do
        [ -e "$dev" ] || continue
        ev="$(timeout 1 /system/bin/getevent -lc 1 "$dev" 2>/dev/null)"
        case "$ev" in
          *KEY_VOLUMEUP*|*KEY_VOLUMEDOWN*) key_pressed=1 ;;
        esac
        [ "$key_pressed" -eq 1 ] && break 2
    done
    sleep 1
done
if [ "$key_pressed" -eq 1 ]; then
    ui_print "- VOLUME pressed, continuing now."
else
    ui_print "- Timeout, continuing."
fi

# ---- 3) 已有实例处理：必须测试"当前这份 ko" ----
# 不跳过：若已有同名实例在跑，先卸载它，再加载当前 ko 验证兼容性。
# 否则安装的这份 ko 可能从未被测试，重启自动加载不兼容版本反而更危险。
if lsmod 2>/dev/null | grep -q sukisu_bridge; then
    ui_print "! Existing sukisu_bridge running; removing it to test this module."
    if ! rmmod sukisu_bridge 2>/dev/null; then
        abort "! Failed to remove existing instance (in use)."
    fi
    ui_print "- Old instance removed."
fi

# ---- 4) insmod 当前 ko 测试 ----
ui_print "- insmod $KO"
if command -v ksud >/dev/null 2>&1; then
    if ksud insmod "$KO"; then
        ui_print "- insmod OK - this module verified compatible"
    else
        abort "! insmod FAILED - module NOT installed"
    fi
elif insmod "$KO"; then
    ui_print "- insmod OK - this module verified compatible"
else
    abort "! insmod FAILED - module NOT installed"
fi
ui_print "- Done"
EOF
chmod 755 "$STAGE/customize.sh"

# 写入内核分支标识、版本号、Android 大版本，并设可执行位（service.sh + customize.sh）
KERNEL_VER="${KERNEL##*-}"     # android12-5.10 -> 5.10
KERNEL_ANDROID="${KERNEL%%-*}" # android12-5.10 -> android12
sed -i "s|__KERNEL_BRANCH__|$KERNEL|g; s|__KERNEL_VER__|$KERNEL_VER|g; s|__KERNEL_ANDROID__|$KERNEL_ANDROID|g" \
  "$STAGE/service.sh" "$STAGE/customize.sh"
chmod 755 "$STAGE/service.sh"

# ---- .ko ----
cp "$KO" "$STAGE/sukisu_bridge.ko"

# ---- 打包 ----
# zip 不可用时回退到 Bandizip(bz)/7z（Windows 宿主常见，如 MSYS2 精简版）。
mkdir -p "$OUT"
if command -v zip >/dev/null 2>&1; then
    (cd "$STAGE" && zip -q -r "$ZIP" .)
elif command -v bz >/dev/null 2>&1; then
    (cd "$STAGE" && bz a -y "$ZIP" . >/dev/null)
elif command -v 7z >/dev/null 2>&1; then
    (cd "$STAGE" && 7z a -tzip "$ZIP" . >/dev/null)
else
    echo "[!] no zip/bz/7z found; skipping pack" >&2
    exit 1
fi
echo "[*] MODULE PACKAGED: $ZIP"
ls -la "$ZIP"
