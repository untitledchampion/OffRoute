#!/bin/bash
# Builds dist/OffRoute.pkg — the one installer (Apple Silicon).
# Needs build/python: python-build-standalone cpython 3.12 aarch64 install_only, with rumps and pywebview installed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/build/python"
APP="$ROOT/dist/OffRoute.app"
VERSION="0.3.6"

rm -rf "$ROOT/dist" && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/app/icon"

echo "launcher…"
clang -O2 -o "$APP/Contents/MacOS/OffRoute" "$ROOT/packaging/launcher.c" \
  -I"$PY/include/python3.12" -L"$PY/lib" -lpython3.12 \
  -Wl,-rpath,@executable_path/../Resources/python/lib -mmacosx-version-min=12.0

echo "python…"
rsync -a --delete \
  --exclude 'lib/python3.12/test' --exclude 'lib/python3.12/idlelib' --exclude 'lib/python3.12/tkinter' \
  --exclude 'lib/python3.12/turtledemo' --exclude 'lib/tcl*' --exclude 'lib/tk*' --exclude 'lib/itcl*' \
  --exclude 'lib/thread*' --exclude 'share' --exclude 'include' --exclude '__pycache__' \
  "$PY/" "$APP/Contents/Resources/python/"

echo "app code…"
cp "$ROOT"/{main.py,autoroute.py,sni.py,window.py,menubar.py,ui.html,dock_clean.py,amnezia.py,ipc.py} "$APP/Contents/Resources/app/"
cp "$ROOT"/icon/{app.png,helmet.png,menubarTemplate.png,menubarTemplate@2x.png} "$APP/Contents/Resources/app/icon/"
cp "$ROOT/icon/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>OffRoute</string>
  <key>CFBundleDisplayName</key><string>OffRoute</string>
  <key>CFBundleIdentifier</key><string>local.vpn-autoroute</string>
  <key>CFBundleExecutable</key><string>OffRoute</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSUIElement</key><true/>
</dict></plist>
EOF

echo "ad-hoc signature…"
codesign --force --deep --sign - "$APP"  # ad-hoc; Developer ID signing and notarization need an Apple account

"$APP/Contents/MacOS/OffRoute" --selftest  # the embedded Python imports every module
echo "pkg…"
PKGROOT="$ROOT/dist/pkgroot"
rm -rf "$PKGROOT" && mkdir -p "$PKGROOT/Applications" && cp -R "$APP" "$PKGROOT/Applications/"
pkgbuild --analyze --root "$PKGROOT" "$ROOT/dist/component.plist" >/dev/null
# never "relocate" onto an older copy of the app somewhere else on the disk
plutil -replace 0.BundleIsRelocatable -bool NO "$ROOT/dist/component.plist"
pkgbuild --quiet --root "$PKGROOT" --component-plist "$ROOT/dist/component.plist" \
  --scripts "$ROOT/packaging/pkg-scripts" --identifier local.vpn-autoroute.pkg --version "$VERSION" \
  --install-location / "$ROOT/dist/OffRoute-component.pkg"
sed "s/VERSION/$VERSION/" "$ROOT/packaging/distribution.xml" > "$ROOT/dist/distribution.xml"
productbuild --quiet --distribution "$ROOT/dist/distribution.xml" --resources "$ROOT/packaging/resources" --package-path "$ROOT/dist" "$ROOT/dist/OffRoute.pkg"
rm -rf "$PKGROOT" "$ROOT/dist/component.plist" "$ROOT/dist/OffRoute-component.pkg" "$ROOT/dist/distribution.xml"
du -sh "$ROOT/dist/OffRoute.pkg"
rm -rf "$APP"  # only the installer stays in dist/
