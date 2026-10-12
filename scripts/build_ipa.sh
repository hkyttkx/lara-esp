#!/bin/bash
set -euo pipefail

rm -rf build/
mkdir -p build

LOG="$PWD/build/build.log"

echo "Build Started!"
echo

set +e
xcodebuild \
  -project lara.xcodeproj \
  -scheme lara \
  -configuration Debug \
  -sdk iphoneos \
  -arch arm64e \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGN_ENTITLEMENTS="Config/lara.entitlements" \
  archive \
  -archivePath "$PWD/build/lara.xcarchive" > "$LOG" 2>&1
XCODE_RC=$?
set -e

if command -v xcpretty >/dev/null 2>&1; then
  xcpretty < "$LOG" || true
fi

if [ $XCODE_RC -ne 0 ]; then
  echo
  echo "================= BUILD FAILED ================="
  echo "----- error: 行 -----"
  grep -nE "error:" "$LOG" | head -80 || true
  echo "----- 上下文 -----"
  grep -nE "error:" -B 3 -A 6 "$LOG" | head -160 || true
  echo "==============================================="
  exit 1
fi

APP_PATH="$PWD/build/lara.xcarchive/Products/Applications/lara.app"
if [ ! -d "$APP_PATH" ]; then
  echo "Missing app at $APP_PATH"
  echo "----- 日志尾部 -----"
  tail -60 "$LOG" || true
  exit 1
fi

rm -rf "$PWD/build/Payload"
mkdir -p "$PWD/build/Payload"
cp -R "$APP_PATH" "$PWD/build/Payload/"

plutil -replace UIFileSharingEnabled -bool YES "$PWD/build/Payload/lara.app/Info.plist"

if ! command -v ldid >/dev/null 2>&1; then
  echo "ERROR: ldid not installed. Install with: brew install ldid" >&2
  exit 1
fi
ldid -SConfig/lara.entitlements "$PWD/build/Payload/lara.app/lara"
(cd "$PWD/build" && /usr/bin/zip -qry lara.ipa Payload)

echo
echo "build successful!"
echo "ipa at: build/lara.ipa"
exit 0
