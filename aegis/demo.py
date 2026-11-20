"""A made-up laptop for screenshots and trying Aegis: python -m aegis --demo

A typical fresh install with a few things left open: the firewall never switched on,
no disk encryption, a key without a passphrase, a restart pending, a café's open
Wi-Fi saved, a browser update waiting for the browser to be closed.
"""

from __future__ import annotations

import json
import stat
from datetime import datetime, timedelta, timezone

from .probe import FakeProbe

D = stat.S_IFDIR
F = stat.S_IFREG

# An unencrypted OpenSSH key header ("openssh-key-v1", cipher "none"); the rest is cut off.
PLAIN_KEY = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
             "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
             "-----END OPENSSH PRIVATE KEY-----\n")
# The same with cipher "aes256-ctr" (passphrase protected).
LOCKED_KEY = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
              "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD\n"
              "-----END OPENSSH PRIVATE KEY-----\n")

LSBLK = {"blockdevices": [
    {"name": "nvme0n1", "type": "disk", "fstype": None, "mountpoints": [None], "children": [
        {"name": "nvme0n1p1", "type": "part", "fstype": "vfat", "mountpoints": ["/boot/efi"]},
        {"name": "nvme0n1p2", "type": "part", "fstype": "ext4", "mountpoints": ["/"]}]}]}

SS = """tcp   LISTEN 0      4096       127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      128          127.0.0.1:631        0.0.0.0:*
tcp   LISTEN 0      511            0.0.0.0:3000       0.0.0.0:*
udp   UNCONN 0      0              0.0.0.0:5353       0.0.0.0:*
"""

APT_SIM = """Reading package lists...
Inst libssl3t64 [3.4.1-1ubuntu2] (3.4.1-1ubuntu2.1 Ubuntu:26.04/resolute-security [amd64])
Inst openssl [3.4.1-1ubuntu2] (3.4.1-1ubuntu2.1 Ubuntu:26.04/resolute-security [amd64])
Inst firefox [140.0-1] (141.0-1 Ubuntu:26.04/resolute-updates [amd64])
Conf libssl3t64 (3.4.1-1ubuntu2.1 Ubuntu:26.04/resolute-security [amd64])
"""


def probe(now: datetime | None = None) -> FakeProbe:
    now = now or datetime.now(timezone.utc)
    home = "/home/demo"
    sysctl = {"kernel/randomize_va_space": "2", "kernel/kptr_restrict": "1", "kernel/dmesg_restrict": "1",
              "kernel/yama/ptrace_scope": "1", "kernel/unprivileged_bpf_disabled": "2",
              "fs/protected_symlinks": "1", "fs/protected_hardlinks": "1", "fs/protected_fifos": "1",
              "fs/protected_regular": "2", "net/ipv4/tcp_syncookies": "1", "net/ipv4/conf/all/rp_filter": "2",
              "net/ipv4/conf/all/accept_redirects": "1", "net/ipv6/conf/all/accept_redirects": "1"}
    status = {"version": 1, "repos": {
        "/home/demo/Backup": {"last_good_backup": {"time": (now - timedelta(minutes=40)).isoformat()}},
        "/media/demo/usb/Backup": {"last_good_backup": {"time": (now - timedelta(days=4)).isoformat()}}}}
    files = {
        "/etc/ufw/ufw.conf": "# /etc/ufw/ufw.conf\nENABLED=no\nLOGLEVEL=low\n",
        "/etc/apt/apt.conf.d/20auto-upgrades": 'APT::Periodic::Update-Package-Lists "1";\n'
                                              'APT::Periodic::Unattended-Upgrade "1";\n',
        "/usr/bin/unattended-upgrade": "",
        "/var/run/reboot-required": "*** System restart required ***\n",
        "/var/run/reboot-required.pkgs": "linux-image-7.0.0-44-generic\nlibc6\n",
        "/usr/sbin/sshd": "",
        "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\n",
        "/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
        "/sys/module/apparmor/parameters/enabled": "Y\n",
        "/etc/gdm3/custom.conf": "[daemon]\nAutomaticLoginEnable=false\n",
        f"{home}/.ssh/id_ed25519": PLAIN_KEY,
        f"{home}/.ssh/id_ed25519.pub": "ssh-ed25519 AAAA demo@laptop\n",
        f"{home}/.ssh/work_rsa": LOCKED_KEY,
        f"{home}/.ssh/known_hosts": "",
        f"{home}/.local/state/mnemosyne/status.json": json.dumps(status),
        **{f"/proc/sys/{k}": v + "\n" for k, v in sysctl.items()},
    }
    modes = {home: D | 0o750, f"{home}/.ssh": D | 0o700, f"{home}/.ssh/id_ed25519": F | 0o600,
             f"{home}/.ssh/work_rsa": F | 0o600, "/sys/firmware/efi": D | 0o755,
             "/var/lib/snapd/snaps/firefox_9229.snap": F | 0o600, "/var/lib/snapd/snaps/firefox_9301.snap": F | 0o600,
             "/usr/local/bin": D | 0o755, "/usr/bin": D | 0o755, "/bin": D | 0o755, f"{home}/.local/bin": D | 0o755}
    commands = {
        ("systemctl", "is-active", "ufw"): (0, "active\n"),
        ("systemctl", "is-active", "ssh"): (0, "active\n"),
        ("systemctl", "is-active", "sshd"): (3, "inactive\n"),
        ("lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"): (0, json.dumps(LSBLK)),
        ("apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"): (0, APT_SIM),
        ("ss", "-ltnuH"): (0, SS),
        ("mokutil", "--sb-state"): (0, "SecureBoot enabled\n"),
        ("gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"): (0, "true\n"),
        ("gsettings", "get", "org.gnome.desktop.session", "idle-delay"): (0, "uint32 300\n"),
        ("gsettings", "get", "org.gnome.desktop.screensaver", "lock-delay"): (0, "uint32 0\n"),
        ("timedatectl", "show"): (0, "NTP=yes\nNTPSynchronized=yes\n"),
        ("snap", "list"): (0, "Name     Version   Rev   Tracking       Publisher  Notes\n"
                               "core24   20261022  2307  latest/stable  canonical  base\n"
                               "firefox  160.0-1   9229  latest/stable  mozilla    -\n"),
        ("bluetoothctl", "show"): (0, "Controller 00:00:00:00:00:00 (public)\n\tPowered: yes\n\tDiscoverable: no\n"),
        ("nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"):
            (0, "Home:802-11-wireless\nCafe Free WiFi:802-11-wireless\nlo:loopback\n"),
        ("nmcli", "-t", "-f", "802-11-wireless-security.key-mgmt,connection.autoconnect", "connection", "show", "Home"):
            (0, "802-11-wireless-security.key-mgmt:wpa-psk\nconnection.autoconnect:yes\n"),
        ("nmcli", "-t", "-f", "802-11-wireless-security.key-mgmt,connection.autoconnect", "connection", "show",
         "Cafe Free WiFi"): (0, "802-11-wireless-security.key-mgmt:\nconnection.autoconnect:yes\n"),
    }
    return FakeProbe(files=files, modes=modes, commands=commands,
                     environ={"PATH": f"{home}/.local/bin:/usr/local/bin:/usr/bin:/bin"})
