"""Remove OffRoute tiles from the Dock (pinned and «recent apps»): the app lives in the menu bar."""
import plistlib, subprocess, sys, tempfile, os
user = sys.argv[1] if len(sys.argv) > 1 else None
pre = ["sudo", "-u", user] if user else []
fd, tmp = tempfile.mkstemp(suffix=".plist"); os.close(fd)
if user:  # root runs this for the user: the user's `defaults export` must be able to write the file
    import pwd
    os.chown(tmp, pwd.getpwnam(user).pw_uid, -1)
subprocess.run(pre + ["defaults", "export", "com.apple.dock", tmp], check=True)
with open(tmp, "rb") as f:
    d = plistlib.load(f)
ours = lambda a: a.get("tile-data", {}).get("bundle-identifier") == "local.vpn-autoroute"
before = len(d.get("recent-apps", [])) + len(d.get("persistent-apps", []))
for key in ("recent-apps", "persistent-apps"):
    d[key] = [a for a in d.get(key, []) if not ours(a)]
if len(d["recent-apps"]) + len(d["persistent-apps"]) != before:
    with open(tmp, "wb") as f:
        plistlib.dump(d, f)
    os.chmod(tmp, 0o644)
    subprocess.run(pre + ["defaults", "import", "com.apple.dock", tmp], check=True)
    subprocess.run(["killall", "-u", user, "Dock"] if user else ["killall", "Dock"])
os.unlink(tmp)
