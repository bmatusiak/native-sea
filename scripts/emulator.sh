#!/bin/bash

# 1. Configuration
AVD_NAME="dev"
EMULATOR_PATH="$ANDROID_HOME/emulator/emulator"
DEBUG=true 

# --- Handle the --kill flag ---
if [[ "$1" == "--kill" ]]; then
    echo "🧹 Shutting down all emulator instances..."
    adb emu kill > /dev/null 2>&1
    sleep 2
    if pgrep -f "qemu-system" > /dev/null; then
        echo "🔪 Force killing processes..."
        pkill -9 -f "qemu-system"
        pkill -9 -f "emulator"
    fi
    echo "✅ Shutdown complete."
    exit 0
fi

# --- Standard Start-up Logic ---
echo "🧹 Checking for running emulators..."
if adb devices | grep -q "emulator"; then
    echo "⚠️  Existing emulator found. Shutting it down first..."
    adb emu kill > /dev/null 2>&1
    sleep 2
    pkill -9 -f "qemu-system" > /dev/null 2>&1
fi

echo "🚀 Starting Emulator: $AVD_NAME in Headless Mode..."

OUTPUT="/dev/null"
[[ "$DEBUG" = true ]] && OUTPUT="/dev/stdout"

$EMULATOR_PATH -avd "$AVD_NAME" \
    -no-window \
    -no-audio \
    -no-boot-anim \
    -memory 2048 \
    -no-snapshot \
    -no-snapshot-save \
    -gpu off > $OUTPUT 2>&1 &

EMU_PID=$!
echo "🆔 Emulator process started with PID: $EMU_PID"

echo "⏳ Waiting for Android OS to finish booting..."
adb wait-for-device
while [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" != "1" ]; do
    sleep 2
done

echo "✨ Killing animations & reducing CPU load..."
adb shell <<EOF
  settings put global window_animation_scale 0
  settings put global transition_animation_scale 0
  settings put global animator_duration_scale 0
  settings put global auto_time 0
  settings put global auto_time_zone 0
  settings put secure location_mode 0
  pm disable-user com.android.vending
EOF

echo "✅ Emulator is ready and optimized!"
echo "------------------------------------------------------"
echo "📌 Usage: ./$(basename $0) --kill (to stop)"
echo "📌 Logs:  adb logcat"
echo "------------------------------------------------------"