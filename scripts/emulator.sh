#!/bin/bash

# 1. Configuration
AVD_NAME="dev"
EMULATOR_PATH="$ANDROID_HOME/emulator/emulator"
AVD_DIR="${ANDROID_AVD_HOME:-$HOME/.android/avd}/$AVD_NAME.avd"
DEBUG=true 

# --- Flag: --kill ---
if [[ "$1" == "--kill" ]]; then
    echo "💾 Saving state and shutting down..."
    adb -s emulator-5554 emu kill > /dev/null 2>&1
    
    timeout=30
    while pgrep -f "qemu-system" > /dev/null && [ $timeout -gt 0 ]; do
        sleep 1
        ((timeout--))
    done

    if pgrep -f "qemu-system" > /dev/null; then
        echo "🔪 Shutdown timed out, force killing..."
        pkill -9 -f "qemu-system"
    fi
    echo "✅ Shutdown complete."
    exit 0
fi

# --- Flag: --wipe ---
WIPE_FLAG=""
if [[ "$1" == "--wipe" ]]; then
    echo "🧼 Wiping AVD data and preparing fresh boot..."
    pkill -9 -f "qemu-system" > /dev/null 2>&1
    sleep 1
    rm -f "$AVD_DIR"/*.lock
    WIPE_FLAG="-wipe-data"
fi

# --- Standard Start-up Logic ---
echo "🧹 Cleaning stale lock files..."
rm -f "$AVD_DIR"/*.lock

if [[ "$1" != "--wipe" ]] && adb devices | grep -q "emulator"; then
    echo "⚠️  Emulator already running. Use --kill or --wipe."
    exit 1
fi

LOG_TARGET="/dev/null"
[[ "$DEBUG" = true ]] && LOG_TARGET="/dev/stdout"

BOOT_ARGS="-avd $AVD_NAME -no-window -no-audio -no-boot-anim -memory 2048 -gpu off $WIPE_FLAG"

if [[ "$1" == "--wipe" ]]; then
    echo "🚀 Starting fresh boot (Wipe mode)..."
else
    echo "🚀 Booting from Snapshot (Quickboot)..."
fi

$EMULATOR_PATH $BOOT_ARGS > $LOG_TARGET 2>&1 &
EMU_PID=$!

echo "⏳ Waiting for Android OS..."
adb -s emulator-5554 wait-for-device

# FIXED LINE: Uses [[ ]] for better string handling and prevents syntax errors if adb returns empty
while [[ "$(adb -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]]; do
    sleep 2
done

# --- Post-Boot Optimizations ---
echo "✨ Applying UI/CPU optimizations..."
adb -s emulator-5554 shell <<EOF
    settings put global window_animation_scale 0
    settings put global transition_animation_scale 0
    settings put global animator_duration_scale 0
    settings put global wifi_scan_always_enabled 0
    settings put global bluetooth_on 0
    settings put global assisted_gps_enabled 0
    settings put global auto_time 0
    settings put global auto_time_zone 0
    settings put global stay_on_while_plugged_in 3
    settings put global package_verifier_enable 0
    settings put secure location_mode 0
    settings put system screen_brightness 0
    cmd power set-fixed-performance-mode-enabled true
    settings put global restricted_device_performance 0,0
    settings put global cached_apps_freezer enabled
    settings put global system_capabilities 100
    setprop debug.sf.hw 1
EOF


echo "✨ Disabling pre-installed apps..."
adb -s emulator-5554 shell <<EOF
    pm disable-user --user 0 com.android.chrome
    pm disable-user --user 0 com.google.android.youtube
    pm disable-user --user 0 com.google.android.apps.youtube.music
    pm disable-user --user 0 com.google.android.contacts
    pm disable-user --user 0 com.google.android.calendar
    pm disable-user --user 0 com.google.android.apps.docs
    pm disable-user --user 0 com.google.android.apps.maps
    pm disable-user --user 0 com.google.android.apps.photos
    pm disable-user --user 0 com.google.android.apps.messaging
EOF

echo "✅ Emulator is ready!"