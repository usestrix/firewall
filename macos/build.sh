#!/bin/bash
# Builds and signs Firewall.app, installs it to /Applications, and packages it as build/Firewall.pkg.
#
# Xcode builds the bundles unsigned; they are signed here because the granted NetworkExtension
# entitlement has no -systemextension variant, so Xcode cannot sign them itself.
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] && . ./.env
: "${TEAM:?set TEAM in macos/.env}"
export TEAM

APP_ID=ai.strix.firewall
EXT_ID=ai.strix.firewall.extension
VERSION=0.1
IDENTITY=${IDENTITY:-$(security find-identity -v -p codesigning | awk -F'"' '/Apple Development/ {print $2; exit}')}
PROFILES="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"

APP=build/Build/Products/Debug/Installer.app
EXT=$APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension
PKG_ROOT=build/pkg-root

main() {
  build
  sign
  install_app
  package
}

build() {
  echo "==> Building"
  xcodegen generate >/dev/null
  xcodebuild -project Firewall.xcodeproj -scheme Installer -configuration Debug \
    -derivedDataPath build CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY="" CODE_SIGN_ENTITLEMENTS="" build >/dev/null
}

sign() {
  echo "==> Signing with $IDENTITY"
  cp "$(profile_for $APP_ID)" "$APP/Contents/embedded.provisionprofile"
  cp "$(profile_for $EXT_ID)" "$EXT/Contents/embedded.provisionprofile"
  codesign --force --options runtime --timestamp=none \
    --entitlements Extension/Extension.entitlements -s "$IDENTITY" "$EXT"
  codesign --force --options runtime --timestamp=none \
    --entitlements Installer/Installer.entitlements -s "$IDENTITY" "$APP"
  codesign --verify --deep --strict "$APP"
}

# The extension can only be activated from /Applications.
install_app() {
  echo "==> Installing /Applications/Firewall.app"
  rm -rf /Applications/Firewall.app
  cp -R "$APP" /Applications/Firewall.app
}

# Marked non-relocatable so the installer never updates another copy with the same bundle id.
package() {
  echo "==> Packaging build/Firewall.pkg"
  rm -rf "$PKG_ROOT"
  mkdir -p "$PKG_ROOT/Applications" "$PKG_ROOT/Library/LaunchAgents"
  cp -R "$APP" "$PKG_ROOT/Applications/Firewall.app"
  cp LaunchAgents/ai.strix.firewall.env.plist "$PKG_ROOT/Library/LaunchAgents/"

  pkgbuild --analyze --root "$PKG_ROOT" build/components.plist >/dev/null
  plutil -replace 0.BundleIsRelocatable -bool NO build/components.plist
  pkgbuild --root "$PKG_ROOT" --component-plist build/components.plist --scripts pkg \
    --identifier $APP_ID --version $VERSION --install-location / build/Firewall.pkg >/dev/null
}

# Prints the newest provisioning profile Xcode has downloaded for a bundle id.
profile_for() {
  local want=$TEAM.$1 newest= newest_time=0 id t
  for p in "$PROFILES"/*.provisionprofile; do
    id=$(security cms -D -i "$p" | plutil -extract Entitlements.com\\.apple\\.application-identifier raw -o - -)
    [ "$id" = "$want" ] || continue
    t=$(stat -f %m "$p")
    if [ "$t" -gt "$newest_time" ]; then newest=$p; newest_time=$t; fi
  done
  [ -n "$newest" ] || { echo "no provisioning profile for $want" >&2; exit 1; }
  echo "$newest"
}

main "$@"
