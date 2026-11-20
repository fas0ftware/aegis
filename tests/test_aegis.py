import json
import stat
from datetime import datetime, timedelta, timezone

import pytest

from aegis import __main__ as cli
from aegis import checks, demo, report
from aegis.probe import FakeProbe, Probe

D, F = stat.S_IFDIR, stat.S_IFREG


def one(probe, id_):
    [r] = checks.run_all(probe, {id_})
    return r


def fake(**kw):
    return FakeProbe(**kw)


# --- firewall ---------------------------------------------------------------------------------

def test_firewall_ufw_on_off_and_missing():
    on = fake(files={"/etc/ufw/ufw.conf": "ENABLED=yes\n"}, commands={("systemctl", "is-active", "ufw"): (0, "active\n")})
    assert one(on, "firewall").status == "pass"
    off = fake(files={"/etc/ufw/ufw.conf": "# comment\nENABLED=no\n"},
               commands={("systemctl", "is-active", "ufw"): (0, "active\n")})
    r = one(off, "firewall")
    assert r.status == "fail" and "service runs, but loads no rules" in r.summary
    assert "$ sudo ufw enable" in r.fix
    fw = fake(commands={("systemctl", "is-active", "firewalld"): (0, "active\n")})
    assert one(fw, "firewall").status == "pass"
    assert one(fake(), "firewall").status == "unknown", "no guessing without root"


# --- disk encryption --------------------------------------------------------------------------

def lsblk(tree):
    return {("lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"): (0, json.dumps({"blockdevices": tree}))}


def test_disk_encryption():
    luks = [{"name": "nvme0n1", "type": "disk", "children": [
        {"name": "nvme0n1p3", "type": "part", "fstype": "crypto_LUKS", "children": [
            {"name": "dm_crypt-0", "type": "crypt", "fstype": "LVM2_member", "children": [
                {"name": "ubuntu--vg-root", "type": "lvm", "fstype": "ext4", "mountpoints": ["/"]}]}]}]}]
    assert one(fake(commands=lsblk(luks)), "disk-encryption").status == "pass"
    plain = [{"name": "sda", "type": "disk", "children": [
        {"name": "sda2", "type": "part", "fstype": "ext4", "mountpoints": ["/"]},
        {"name": "sda3", "type": "part", "fstype": "ext4", "mountpoints": ["/home"]}]}]
    r = one(fake(commands=lsblk(plain)), "disk-encryption")
    assert r.status == "fail" and r.summary.endswith("/, /home")
    old_lsblk = [{"name": "sda1", "type": "part", "fstype": "ext4", "mountpoint": "/"}]
    assert one(fake(commands=lsblk(old_lsblk)), "disk-encryption").status == "fail"
    assert one(fake(), "disk-encryption").status == "unknown"


# --- updates ----------------------------------------------------------------------------------

def test_auto_updates_last_setting_wins():
    base = {"/usr/bin/unattended-upgrade": ""}
    on = fake(files={**base, "/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Unattended-Upgrade "1";'})
    assert one(on, "auto-updates").status == "pass"
    off = fake(files={**base, "/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Unattended-Upgrade "1";',
                      "/etc/apt/apt.conf.d/99local": 'APT::Periodic::Unattended-Upgrade "0";'})
    assert one(off, "auto-updates").summary == "unattended-upgrades is installed but switched off"
    missing = fake(files={"/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Unattended-Upgrade "1";'})
    assert one(missing, "auto-updates").summary == "unattended-upgrades is not installed"
    assert one(fake(), "auto-updates").status == "unknown"


def test_pending_updates_and_reboot():
    p = demo.probe()
    r = one(p, "pending-updates")
    assert r.status == "fail" and r.details == ["libssl3t64", "openssl"]
    p.commands[("apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")] = (0, "Reading package lists...\n")
    assert one(p, "pending-updates").status == "pass"
    r = one(p, "reboot")
    assert r.status == "warn" and r.details == ["libc6", "linux-image-7.0.0-44-generic"]
    del p.files["/var/run/reboot-required"]
    assert one(p, "reboot").status == "pass"


# --- ssh --------------------------------------------------------------------------------------

def sshd(**files):
    return fake(files={"/usr/sbin/sshd": "", **files}, commands={("systemctl", "is-active", "ssh"): (0, "active\n")})


def test_ssh_server_first_value_wins_and_includes():
    assert one(fake(), "ssh-server").summary == "no SSH server is running"
    r = one(sshd(**{"/etc/ssh/sshd_config": "PermitRootLogin yes\n"}), "ssh-server")
    assert r.status == "fail" and "password logins" in r.summary, "PasswordAuthentication defaults to yes"
    hardened = sshd(**{"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n",
                       "/etc/ssh/sshd_config.d/10-keys.conf": "PasswordAuthentication no  # keys only\n"})
    assert one(hardened, "ssh-server").status == "pass", "the include comes first, so its value wins"
    match = sshd(**{"/etc/ssh/sshd_config": "PasswordAuthentication no\nMatch User guest\n  PasswordAuthentication yes\n"})
    assert one(match, "ssh-server").status == "pass", "a Match block does not change the defaults"
    loop = sshd(**{"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config\n"})
    assert one(loop, "ssh-server").status == "warn", "a self-include ends instead of looping"


def test_exposed_services():
    p = demo.probe()
    r = one(p, "exposed-services")
    assert r.status == "warn" and r.details == ["tcp 0.0.0.0:3000", "udp 0.0.0.0:5353"]
    p.commands[("ss", "-ltnuH")] = (0, "tcp LISTEN 0 5 127.0.0.1:8000 0.0.0.0:*\n"
                                       "tcp LISTEN 0 5 [::1]:8000 [::]:*\nudp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n"
                                       "udp UNCONN 0 0 0.0.0.0:41000 0.0.0.0:*\n")
    assert one(p, "exposed-services").status == "pass"
    p.commands[("ss", "-ltnuH")] = (0, "udp UNCONN 0 0 [::]:1194 [::]:*\n")
    assert one(p, "exposed-services").status == "info"


# --- kernel, session --------------------------------------------------------------------------

def test_kernel_switches():
    p = demo.probe()
    r = one(p, "kernel")
    assert r.status == "warn" and "net.ipv4.conf.all.accept_redirects = 0" in r.fix[1]
    p.files["/proc/sys/net/ipv4/conf/all/accept_redirects"] = "0\n"
    p.files["/proc/sys/net/ipv6/conf/all/accept_redirects"] = "0\n"
    assert one(p, "kernel").status == "pass"
    assert one(fake(), "kernel").status == "unknown"


def test_mac_secure_boot_time_autologin():
    assert one(fake(files={"/sys/module/apparmor/parameters/enabled": "Y\n"}), "mac").status == "pass"
    assert one(fake(files={"/sys/fs/selinux/enforce": "0"}), "mac").status == "fail"
    assert one(fake(), "mac").status == "fail"
    efi = {"/sys/firmware/efi": D | 0o755}
    off = fake(modes=efi, commands={("mokutil", "--sb-state"): (0, "SecureBoot disabled\nPlatform is in Setup Mode\n")})
    assert one(off, "secure-boot").status == "warn" and "Setup Mode" in one(off, "secure-boot").details[0]
    assert one(fake(), "secure-boot").status == "info"
    assert one(fake(commands={("timedatectl", "show"): (0, "NTP=no\nNTPSynchronized=no\n")}), "time-sync").status == "warn"
    auto = fake(files={"/etc/gdm3/custom.conf": "[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=demo\n"})
    assert one(auto, "autologin").summary == "GDM logs in automatically as demo"
    assert one(fake(files={"/etc/lightdm/lightdm.conf": "[Seat:*]\nautologin-user=kid\n"}), "autologin").status == "fail"
    assert one(fake(), "autologin").status == "pass"


def gs(lock="true", idle="uint32 300", delay="uint32 0"):
    k = ("gsettings", "get")
    return fake(commands={(*k, "org.gnome.desktop.screensaver", "lock-enabled"): (0, lock),
                          (*k, "org.gnome.desktop.session", "idle-delay"): (0, idle),
                          (*k, "org.gnome.desktop.screensaver", "lock-delay"): (0, delay)})


def test_screen_lock():
    assert one(gs(), "screen-lock").status == "pass"
    assert one(gs(idle="uint32 0"), "screen-lock").status == "fail"
    assert one(gs(lock="false"), "screen-lock").status == "fail"
    assert one(gs(idle="uint32 900", delay="uint32 600"), "screen-lock").summary == "the screen locks only after 25 minutes"
    assert one(fake(), "screen-lock").status == "unknown"


# --- files ------------------------------------------------------------------------------------

def test_private_key_detection_reads_only_the_header():
    assert checks._private_key_kind(demo.PLAIN_KEY) == "plain"
    assert checks._private_key_kind(demo.LOCKED_KEY) == "encrypted"
    assert checks._private_key_kind("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n") == "plain"
    assert checks._private_key_kind("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n") == "encrypted"
    assert checks._private_key_kind("-----BEGIN ENCRYPTED PRIVATE KEY-----\n") == "encrypted"
    assert checks._private_key_kind("ssh-ed25519 AAAA public\n") is None
    assert checks._private_key_kind("-----BEGIN OPENSSH PRIVATE KEY-----\n!!!!\n-----END") == "encrypted", \
        "an unreadable header is not reported as unprotected"


def test_home_permissions_and_keys():
    p = demo.probe()
    assert one(p, "home-permissions").status == "pass"
    r = one(p, "ssh-keys")
    assert r.status == "warn" and r.summary.endswith("id_ed25519")
    p.modes["/home/demo"] = D | 0o755
    assert one(p, "home-permissions").status == "warn"
    p.modes["/home/demo/.ssh/id_ed25519"] = F | 0o644
    r = one(p, "home-permissions")
    assert r.status == "fail" and "$ chmod 600 ~/.ssh/id_ed25519" in r.fix
    assert one(fake(modes={"/home/demo": D | 0o700}), "ssh-keys").status == "pass"


def test_path():
    good = fake(environ={"PATH": "/usr/bin:/bin"}, modes={"/usr/bin": D | 0o755, "/bin": D | 0o755})
    assert one(good, "path").status == "pass"
    dot = fake(environ={"PATH": "/usr/bin::/bin"})
    assert "current folder" in one(dot, "path").summary
    ww = fake(environ={"PATH": "/opt/tools/bin:/tmp"},
              modes={"/opt/tools/bin": D | 0o777, "/tmp": D | stat.S_ISVTX | 0o777})
    r = one(ww, "path")
    assert r.status == "fail" and r.details == ["/opt/tools/bin can be written by anyone"], "sticky /tmp is not flagged"


def test_path_follows_links_on_the_real_system(tmp_path):
    (tmp_path / "real").mkdir(mode=0o755)
    (tmp_path / "link").symlink_to(tmp_path / "real")
    p = Probe()
    p.env = lambda name: str(tmp_path / "link") if name == "PATH" else ""
    assert one(p, "path").status == "pass", "a symlink's own 777 mode is not the folder's"


def test_backups():
    now = datetime.now(timezone.utc)

    def status(*hours):
        repos = {f"/r{i}": {"last_good_backup": {"time": (now - timedelta(hours=h)).isoformat()}} if h is not None else {}
                 for i, h in enumerate(hours)}
        return fake(files={"/home/demo/.local/state/mnemosyne/status.json": json.dumps({"repos": repos})})
    assert one(status(1, 2), "backups").status == "pass"
    assert one(status(1, 60), "backups").status == "warn"
    assert one(status(100), "backups").status == "fail"
    assert one(status(None), "backups").summary == "no backup has succeeded yet"
    assert one(fake(), "backups").status == "unknown"
    assert one(fake(files={"/home/demo/.local/state/mnemosyne/status.json": "{"}), "backups").status == "unknown"


# --- the whole run ----------------------------------------------------------------------------

def test_a_crashing_check_does_not_hide_the_others(monkeypatch):
    def boom(probe, r):
        raise ValueError("bad data")
    monkeypatch.setattr(checks, "CHECKS", [("x", "X", "high", "", boom), *checks.CHECKS[:1]])
    results = checks.run_all(demo.probe())
    assert results[0].status == "unknown" and "ValueError: bad data" in results[0].summary
    assert results[1].status == "fail"


def test_score_counts_only_decided_checks():
    R = checks.Result
    assert checks.score([R("a", "", "high", "pass"), R("b", "", "low", "fail")]) == 75
    assert checks.score([R("a", "", "high", "warn")]) == 50
    assert checks.score([R("a", "", "high", "unknown"), R("b", "", "low", "info")]) is None


def test_demo_report_text_json_html(tmp_path):
    results = checks.run_all(demo.probe())
    assert len(results) == len(checks.CHECKS) and all(r.why for r in results)
    assert all(r.status != "unknown" for r in results), "the demo answers every check"
    data = report.to_json(results)
    assert data["score"] == checks.score(results) and data["checks"][0]["status"] == "fail"
    txt = report.text(results, color=False)
    assert txt.startswith("Aegis ") and "✗ Firewall" in txt and "\033[" not in txt
    page = report.to_html(results)
    assert "Content-Security-Policy" in page and "<script" not in page
    evil = checks.Result("x", "<b>t</b>", "high", "fail", "<script>alert(1)</script>", why="w", fix=["$ <rm>"])
    assert "<script>alert" not in report.to_html([evil]) and "&lt;rm&gt;" in report.to_html([evil])
    report.write_status(results, tmp_path / "s" / "status.json")
    saved = tmp_path / "s" / "status.json"
    assert json.loads(saved.read_text())["counts"]["fail"] == 3 and stat.S_IMODE(saved.stat().st_mode) == 0o600


def test_cli(capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATUS_FILE", tmp_path / "status.json")
    assert cli.main(["--demo"]) == 0
    assert "Aegis" in capsys.readouterr().out
    assert cli.main(["--demo", "check", "--strict"]) == 1
    capsys.readouterr()
    assert cli.main(["--demo", "check", "--json", "--only", "mac,path"]) == 0
    assert [c["id"] for c in json.loads(capsys.readouterr().out)["checks"]] == ["mac", "path"]
    assert cli.main(["--demo", "explain", "firewall"]) == 0
    assert "Why it matters" in capsys.readouterr().out
    assert cli.main(["--demo", "explain", "nope"]) == 2
    assert cli.main(["--demo", "report", str(tmp_path / "r.html")]) == 0
    assert (tmp_path / "r.html").read_text().startswith("<!doctype html>")
    assert cli.main(["list"]) == 0
    assert "disk-encryption" in capsys.readouterr().out
    assert cli.main(["--demo", "check", "--save"]) == 0
    assert cli.main(["--demo", "--strict"]) == 1, "check is the default command, its options work without it"
    assert cli.main(["--demo", "--json", "--only", "mac"]) == 0
    assert cli._default_command(["--save", "--no-fixes"]) == ["check", "--save", "--no-fixes"]
    assert cli._default_command(["--demo", "list"]) == ["--demo", "list"]
    assert cli._default_command(["--version"]) == ["--version"]
    assert not (tmp_path / "status.json").exists(), "the demo never writes the real status file"


@pytest.mark.skipif(not Probe().exists("/proc/sys"), reason="needs Linux")
def test_runs_read_only_on_this_machine():
    results = checks.run_all(Probe())
    assert {r.status for r in results} <= set(checks.STATUSES)
    assert not any("the check itself failed" in r.summary for r in results)
