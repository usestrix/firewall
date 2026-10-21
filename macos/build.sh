#!/bin/bash
# Builds and signs StrixFirewall.app, installs it to /Applications, and packages it as build/Firewall.pkg.
# The package is notarized with the notarytool keychain profile in NOTARY_PROFILE; `build.sh debug`
# makes a Debug build and skips notarization.
#
# Xcode builds the bundles unsigned; they are signed here. Debug builds use Apple Development signing
# because macOS refuses to activate a Developer ID extension that is not notarized.
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] && . ./.env
: "${TEAM:?set TEAM in macos/.env}"
export TEAM

# Identities are matched as a substring of the certificate name; set them if more than one matches.
# Development profiles grant only the plain NetworkExtension values, Developer ID ones only -systemextension.
if [ "${1:-}" = debug ]; then
  CONFIGURATION=Debug
  IDENTITY=${DEBUG_IDENTITY:-Apple Development}
  NE_PROVIDER=app-proxy-provider
else
  CONFIGURATION=Release
  IDENTITY=${IDENTITY:-Developer ID Application}
  NE_PROVIDER=app-proxy-provider-systemextension
  : "${NOTARY_PROFILE:?set NOTARY_PROFILE in macos/.env}"
fi
export NE_PROVIDER

APP_ID=com.usestrix.firewall
EXT_ID=com.usestrix.firewall.extension
VERSION=0.1
INSTALLER_IDENTITY=${INSTALLER_IDENTITY:-Developer ID Installer}
PROFILES="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"

APP=build/Build/Products/$CONFIGURATION/StrixFirewall.app
EXT=$APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension
PKG_ROOT=build/pkg-root

main() {
  build
  sign
  install_app
  package
  [ $CONFIGURATION = Debug ] || notarize
}

build() {
  echo "==> Building"
  xcodegen generate >/dev/null
  xcodebuild -project Firewall.xcodeproj -scheme StrixFirewall -configuration $CONFIGURATION \
    -derivedDataPath build CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY="" CODE_SIGN_ENTITLEMENTS="" build >/dev/null
}

sign() {
  echo "==> Signing with $IDENTITY"
  cp "$(profile_for $APP_ID)" "$APP/Contents/embedded.provisionprofile"
  cp "$(profile_for $EXT_ID)" "$EXT/Contents/embedded.provisionprofile"
  codesign --force --options runtime --timestamp -s "$IDENTITY" "$APP/Contents/MacOS/firewall"
  codesign --force --options runtime --timestamp \
    --entitlements Extension/Extension.entitlements -s "$IDENTITY" "$EXT"
  codesign --force --options runtime --timestamp \
    --entitlements App/App.entitlements -s "$IDENTITY" "$APP"
  codesign --verify --deep --strict "$APP"
}

# The extension can only be activated from /Applications.
install_app() {
  echo "==> Installing /Applications/StrixFirewall.app"
  rm -rf /Applications/StrixFirewall.app
  cp -R "$APP" /Applications/StrixFirewall.app
}

# Marked non-relocatable so the installer never updates another copy with the same bundle id.
package() {
  echo "==> Packaging build/Firewall.pkg"
  rm -rf "$PKG_ROOT"
  mkdir -p "$PKG_ROOT/Applications" "$PKG_ROOT/Library/LaunchAgents"
  cp -R "$APP" "$PKG_ROOT/Applications/StrixFirewall.app"
  cp LaunchAgents/com.usestrix.firewall.env.plist "$PKG_ROOT/Library/LaunchAgents/"

  pkgbuild --analyze --root "$PKG_ROOT" build/components.plist >/dev/null
  plutil -replace 0.BundleIsRelocatable -bool NO build/components.plist
  pkgbuild --root "$PKG_ROOT" --component-plist build/components.plist --scripts pkg \
    --identifier $APP_ID --version $VERSION --install-location / --sign "$INSTALLER_IDENTITY" \
    build/Firewall.pkg >/dev/null
}

notarize() {
  echo "==> Notarizing build/Firewall.pkg"
  xcrun notarytool submit build/Firewall.pkg --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple build/Firewall.pkg
}

# Prints the newest provisioning profile Xcode has downloaded for a bundle id that grants NE_PROVIDER.
profile_for() {
  local want=$TEAM.$1 newest= newest_time=0 profile id t
  for p in "$PROFILES"/*.provisionprofile; do
    profile=$(security cms -D -i "$p")
    id=$(plutil -extract Entitlements.com\\.apple\\.application-identifier raw -o - - <<<"$profile")
    [ "$id" = "$want" ] || continue
    plutil -extract Entitlements.com\\.apple\\.developer\\.networking\\.networkextension json -o - - <<<"$profile" |
      grep -q "\"$NE_PROVIDER\"" || continue
    t=$(stat -f %m "$p")
    if [ "$t" -gt "$newest_time" ]; then newest=$p; newest_time=$t; fi
  done
  [ -n "$newest" ] || { echo "no provisioning profile for $want" >&2; exit 1; }
  echo "$newest"
}

main "$@"
