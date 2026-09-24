#!/bin/bash
# Builds, signs and installs the app. Xcode cannot sign this itself: the
# NetworkExtension entitlement Apple grants us has no -systemextension variant,
# so the bundles are built unsigned and signed here against the profiles Xcode
# fetched into ~/Library/Developer/Xcode/UserData/Provisioning Profiles.
set -euo pipefail
cd "$(dirname "$0")"

# Everything team-specific comes from here; .env is per-checkout and untracked.
[ -f .env ] && . ./.env
: "${TEAM:?set TEAM in macos/.env}"
export TEAM
APP_ID=ai.strix.firewall
EXT_ID=ai.strix.firewall.extension
IDENTITY=${IDENTITY:-$(security find-identity -v -p codesigning | awk -F'"' "/Apple Development/ {print \$2; exit}")}
PROFILES="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"

profile_for() { # bundle id -> newest matching profile
  local want=$TEAM.$1 newest= newest_time=0
  for p in "$PROFILES"/*.provisionprofile; do
    local id
    id=$(security cms -D -i "$p" | plutil -extract Entitlements.com\\.apple\\.application-identifier raw -o - -)
    [ "$id" = "$want" ] || continue
    local t; t=$(stat -f %m "$p")
    [ "$t" -gt "$newest_time" ] && { newest=$p; newest_time=$t; }
  done
  [ -n "$newest" ] || { echo "no provisioning profile for $want" >&2; exit 1; }
  echo "$newest"
}

xcodegen generate >/dev/null
xcodebuild -project Firewall.xcodeproj -scheme Installer -configuration Debug \
  -derivedDataPath build CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" CODE_SIGN_ENTITLEMENTS="" build >/dev/null

APP=build/Build/Products/Debug/Installer.app
EXT=$APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension
cp "$(profile_for $APP_ID)" "$APP/Contents/embedded.provisionprofile"
cp "$(profile_for $EXT_ID)" "$EXT/Contents/embedded.provisionprofile"

codesign --force --options runtime --timestamp=none \
  --entitlements Extension/Extension.entitlements -s "$IDENTITY" "$EXT"
codesign --force --options runtime --timestamp=none \
  --entitlements Installer/Installer.entitlements -s "$IDENTITY" "$APP"
codesign --verify --deep --strict "$APP"

# Activation only works from /Applications, and on-demand relaunches by path.
rm -rf /Applications/Firewall.app
cp -R "$APP" /Applications/Firewall.app
echo "installed /Applications/Firewall.app"

# The shipping artifact. The app is not relocatable: installer would otherwise
# update a stray copy with the same bundle id, such as the one under build/.
PKG_ROOT=build/pkg-root
rm -rf "$PKG_ROOT" && mkdir -p "$PKG_ROOT/Applications" "$PKG_ROOT/Library/LaunchAgents"
cp -R "$APP" "$PKG_ROOT/Applications/Firewall.app"
cp LaunchAgents/ai.strix.firewall.env.plist "$PKG_ROOT/Library/LaunchAgents/"
pkgbuild --analyze --root "$PKG_ROOT" build/components.plist >/dev/null
plutil -replace 0.BundleIsRelocatable -bool NO build/components.plist
pkgbuild --root "$PKG_ROOT" --component-plist build/components.plist --scripts pkg \
  --identifier $APP_ID --version 0.1 --install-location / build/Firewall.pkg >/dev/null
echo "built macos/build/Firewall.pkg"
