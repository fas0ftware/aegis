"""The checks. Each one looks at the machine through a Probe and returns a Result that
says what it found, why it matters and how to fix it.

Statuses: pass, warn, fail, info (worth knowing, not scored) and unknown (Aegis could
not tell, usually because the answer needs root; never guessed).
"""

from __future__ import annotations

import base64
import json
import re
import shlex
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone

WEIGHT = {"high": 3, "medium": 2, "low": 1}
STATUSES = ("pass", "warn", "fail", "info", "unknown")


@dataclass
class Result:
    id: str
    title: str
    severity: str                   # high / medium / low: how much it counts in the score
    status: str = "unknown"
    summary: str = ""               # one line: what Aegis found
    details: list[str] = field(default_factory=list)
    why: str = ""                   # why it matters
    fix: list[str] = field(default_factory=list)   # steps; lines starting with "$ " are commands


CHECKS = []


def check(id_, title, severity, why):
    def wrap(fn):
        CHECKS.append((id_, title, severity, why, fn))
        return fn
    return wrap


def run_all(probe, only: set[str] | None = None) -> list[Result]:
    out = []
    for id_, title, severity, why, fn in CHECKS:
        if only and id_ not in only:
            continue
        r = Result(id_, title, severity, why=why)
        try:
            fn(probe, r)
        except Exception as exc:  # a broken check must not hide the others
            r.status, r.summary = "unknown", f"the check itself failed: {type(exc).__name__}: {exc}"
        out.append(r)
    return out


def score(results: list[Result]) -> int | None:
    total = got = 0
    for r in results:
        if r.status in ("pass", "warn", "fail"):
            w = WEIGHT[r.severity]
            total += w
            got += w if r.status == "pass" else w / 2 if r.status == "warn" else 0
    return round(100 * got / total) if total else None


def _kv(text: str, sep: str = "=") -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and sep in line:
            k, v = line.split(sep, 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def _systemctl_active(probe, unit: str) -> bool | None:
    r = probe.run(["systemctl", "is-active", unit])
    return None if r is None else r[1].strip() == "active"


# --- firewall ---------------------------------------------------------------------------------

@check("firewall", "Firewall", "high",
       "A firewall decides which connections from the network reach the programs on this "
       "computer. Without one, any service that listens on the network (file sharing, a "
       "development server someone forgot, a printer daemon) is reachable by every device "
       "on the same Wi-Fi: a café, a hotel, an airport.")
def firewall(probe, r):
    conf = probe.read("/etc/ufw/ufw.conf")
    if conf is not None:
        enabled = _kv(conf).get("ENABLED", "no").lower() == "yes"
        active = _systemctl_active(probe, "ufw")
        if enabled and active is not False:
            r.status, r.summary = "pass", "ufw is on"
            return
        r.status = "fail"
        r.summary = ("ufw is installed but switched off (ENABLED=no in /etc/ufw/ufw.conf): "
                     + ("its service runs, but loads no rules" if active else "no rules are loaded"))
        r.fix = ["Block everything that comes in, allow everything that goes out, and switch it on:",
                 "$ sudo ufw default deny incoming",
                 "$ sudo ufw default allow outgoing",
                 "$ sudo ufw enable",
                 "If you share something on purpose (say SSH from your own network), allow only that:",
                 "$ sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp"]
        return
    if _systemctl_active(probe, "firewalld"):
        r.status, r.summary = "pass", "firewalld is running"
        return
    r.status = "unknown"
    r.summary = "neither ufw nor firewalld is set up; nftables rules can only be read as root"
    r.fix = ["Check as root whether any rules exist:", "$ sudo nft list ruleset",
             "If that prints nothing, install and switch on ufw:", "$ sudo apt install ufw && sudo ufw enable"]


# --- disk encryption --------------------------------------------------------------------------

def _mount_chain(tree: list, target: str, chain=()):
    """The devices from the disk down to the one mounted at target."""
    for node in tree:
        here = (*chain, node)
        if target in (node.get("mountpoints") or []) or node.get("mountpoint") == target:
            return here
        found = _mount_chain(node.get("children") or [], target, here)
        if found:
            return found
    return None


@check("disk-encryption", "Disk encryption", "high",
       "A laptop gets lost or stolen. Without full-disk encryption anyone can take the disk "
       "out (or boot a USB stick) and read every file, saved browser session and key on it; "
       "your login password does not protect the disk itself.")
def disk_encryption(probe, r):
    out = probe.run(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"])
    if out is None or out[0] != 0:
        r.status, r.summary = "unknown", "lsblk is not available"
        return
    tree = json.loads(out[1]).get("blockdevices", [])
    checked = []
    for mount in ("/", "/home"):
        chain = _mount_chain(tree, mount)
        if chain is None:
            continue
        crypt = any(n.get("type") == "crypt" or n.get("fstype") == "crypto_LUKS" for n in chain)
        checked.append((mount, crypt, chain[-1].get("name", "?")))
    if not checked:
        r.status, r.summary = "unknown", "could not find the device mounted at /"
        return
    r.details = [f"{m} on {dev}: {'encrypted (LUKS)' if c else 'not encrypted'}" for m, c, dev in checked]
    if all(c for _, c, _ in checked):
        r.status, r.summary = "pass", "the system and home folders are on encrypted devices"
        return
    r.status = "fail"
    r.summary = "files are stored unencrypted: " + ", ".join(m for m, c, _ in checked if not c)
    r.fix = ["An existing installation cannot be encrypted in place. The safe way is a fresh install",
             "with \"Encrypt the new installation\" (LUKS) ticked, after a full backup and a test restore.",
             "Until then, keep the most sensitive files in an encrypted folder, for example:",
             "$ sudo apt install gocryptfs",
             "$ gocryptfs -init ~/.vault-data && mkdir -p ~/Vault && gocryptfs ~/.vault-data ~/Vault"]


# --- updates ----------------------------------------------------------------------------------

@check("auto-updates", "Automatic security updates", "high",
       "Most attacks use holes that were already fixed. Installing security updates every "
       "day without waiting for you to remember closes them within a day instead of weeks.")
def auto_updates(probe, r):
    names = probe.listdir("/etc/apt/apt.conf.d")
    if names is None:
        r.status, r.summary = "unknown", "not an apt-based system"
        return
    value = None
    for name in names:   # apt reads them in order; the last setting wins
        text = probe.read(f"/etc/apt/apt.conf.d/{name}") or ""
        for m in re.finditer(r'APT::Periodic::Unattended-Upgrade\s+"?(\d+)"?\s*;', text):
            value = m.group(1)
    installed = probe.exists("/usr/bin/unattended-upgrade")
    if installed and value not in (None, "0"):
        r.status, r.summary = "pass", "unattended-upgrades installs security updates automatically"
        return
    r.status = "fail"
    r.summary = ("unattended-upgrades is not installed" if not installed
                 else "unattended-upgrades is installed but switched off")
    r.fix = ["$ sudo apt install unattended-upgrades",
             "$ sudo dpkg-reconfigure -plow unattended-upgrades    # answer Yes"]


@check("pending-updates", "Security updates waiting", "high",
       "Updates that are downloaded but not installed protect nothing. This counts what apt "
       "would install now (a dry run, nothing is changed).")
def pending_updates(probe, r):
    if probe.listdir("/etc/apt/apt.conf.d") is None:
        r.status, r.summary = "unknown", "not an apt-based system"
        return
    out = probe.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"])
    if out is None:
        r.status, r.summary = "unknown", "apt-get did not answer"
        return
    inst = [line for line in out[1].splitlines() if line.startswith("Inst ")]
    security = [line.split()[1] for line in inst if "-security" in line]
    if not inst:
        r.status, r.summary = "pass", "everything is up to date (as of the last package list refresh)"
        return
    if security:
        r.status = "fail"
        r.summary = f"{len(security)} security update(s) waiting ({len(inst)} updates in total)"
        r.details = security[:15] + ([f"... and {len(security) - 15} more"] if len(security) > 15 else [])
    else:
        r.status, r.summary = "warn", f"{len(inst)} update(s) waiting, none marked as security"
    r.fix = ["$ sudo apt update && sudo apt upgrade"]


@check("reboot", "Restart after updates", "medium",
       "A new kernel or system library only protects you after a restart; until then the old, "
       "vulnerable copy keeps running.")
def reboot(probe, r):
    if not probe.exists("/var/run/reboot-required"):
        r.status, r.summary = "pass", "no restart pending"
        return
    pkgs = sorted(set((probe.read("/var/run/reboot-required.pkgs") or "").split()))
    r.status = "warn"
    r.summary = "a restart is pending" + (f" for {len(pkgs)} package(s)" if pkgs else "")
    r.details = pkgs[:10]
    r.fix = ["Save your work and restart:", "$ systemctl reboot"]


# --- remote access ----------------------------------------------------------------------------

def _sshd_settings(probe) -> dict[str, str]:
    """sshd keeps the first value it reads; Include lines are read in place."""
    seen: dict[str, str] = {}

    def read(path, depth=0):
        text = probe.read(path)
        if text is None or depth > 3:
            return
        for line in text.splitlines():
            parts = line.split("#", 1)[0].split()
            if len(parts) < 2:
                continue
            key, value = parts[0].lower(), " ".join(parts[1:])
            if key == "match":
                return            # settings after Match apply only to some connections
            if key == "include":
                for pattern in parts[1:]:
                    pattern = pattern if pattern.startswith("/") else "/etc/ssh/" + pattern
                    folder, _, glob = pattern.rpartition("/")
                    rx = re.compile("^" + re.escape(glob).replace(r"\*", ".*") + "$")
                    for name in probe.listdir(folder) or []:
                        if rx.match(name):
                            read(f"{folder}/{name}", depth + 1)
                continue
            seen.setdefault(key, value.lower())
    read("/etc/ssh/sshd_config")
    return seen


@check("ssh-server", "SSH server", "high",
       "An SSH server lets people log in over the network. If it accepts passwords, anyone who "
       "can reach it can try passwords forever; if it accepts root, one guessed password is the "
       "whole machine.")
def ssh_server(probe, r):
    running = [u for u in ("ssh", "sshd") if _systemctl_active(probe, u)]
    if not probe.exists("/usr/sbin/sshd") or not running:
        r.status, r.summary = "pass", "no SSH server is running"
        return
    s = _sshd_settings(probe)
    password = s.get("passwordauthentication", "yes")
    kbd = s.get("kbdinteractiveauthentication", s.get("challengeresponseauthentication", "yes"))
    root = s.get("permitrootlogin", "prohibit-password")
    problems = []
    if password == "yes":  # nosec B105
        problems.append("password logins are allowed (PasswordAuthentication)")
    if root == "yes":
        problems.append("root can log in with a password (PermitRootLogin yes)")
    r.details = [f"PasswordAuthentication {password}", f"KbdInteractiveAuthentication {kbd}",
                 f"PermitRootLogin {root}"]
    if not problems:
        r.status, r.summary = "pass", "SSH runs with keys only"
        return
    r.status = "fail" if root == "yes" else "warn"
    r.summary = "SSH is running and " + "; ".join(problems)
    r.fix = ["First make sure your key works (ssh-copy-id from the other computer), then:",
             "$ printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\nPermitRootLogin no\\n' "
             "| sudo tee /etc/ssh/sshd_config.d/10-aegis.conf",
             "$ sudo sshd -t && sudo systemctl reload ssh",
             "If you do not use SSH at all: $ sudo systemctl disable --now ssh"]


def _listeners(text: str):
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        host, _, port = local.rpartition(":")
        host = host.strip("[]").split("%")[0]
        if host.startswith("127.") or host == "::1" or "%lo" in local:
            continue
        yield proto, host, port


@check("exposed-services", "Services reachable from the network", "medium",
       "Every program that listens on all addresses (0.0.0.0 or ::) is a door the firewall has to "
       "keep shut. Fewer doors, fewer surprises: development servers and sharing tools should "
       "listen on 127.0.0.1 unless they are meant for other devices.")
def exposed_services(probe, r):
    out = probe.run(["ss", "-ltnuH"])
    if out is None:
        r.status, r.summary = "unknown", "ss is not available"
        return
    tcp, udp = [], []
    for proto, host, port in _listeners(out[1]):
        (tcp if proto == "tcp" else udp).append(f"{proto} {host or '*'}:{port}")
    tcp, udp = sorted(set(tcp)), sorted(set(udp))
    r.details = tcp + udp
    known_udp = {"5353", "68", "546", "5355", "3702"}
    odd_udp = [u for u in udp if u.rsplit(":", 1)[1] not in known_udp and int(u.rsplit(":", 1)[1]) < 32768]
    if tcp:
        r.status = "warn"
        r.summary = f"{len(tcp)} TCP service(s) listen on the network"
        r.fix = ["See which program owns each one:", "$ sudo ss -ltnp",
                 "Stop what you do not need, or make it listen on 127.0.0.1 only; keep the firewall on."]
    elif odd_udp:
        r.status = "info"
        r.summary = f"no TCP services; UDP listeners: {', '.join(odd_udp)}"
    else:
        r.status = "pass"
        r.summary = "no TCP service listens on the network" + (
            " (UDP: discovery services such as mDNS only)" if udp else "")


# --- the kernel and the session ---------------------------------------------------------------

SYSCTLS = [
    # key, wanted test, value to suggest, what it does
    ("kernel.randomize_va_space", lambda v: v == 2, 2, "full address-space randomization"),
    ("kernel.kptr_restrict", lambda v: v >= 1, 1, "hide kernel addresses from normal users"),
    ("kernel.dmesg_restrict", lambda v: v == 1, 1, "kernel log readable by admins only"),
    ("kernel.yama.ptrace_scope", lambda v: v >= 1, 1, "programs cannot read other programs' memory"),
    ("kernel.unprivileged_bpf_disabled", lambda v: v >= 1, 1, "no BPF programs for normal users"),
    ("fs.protected_symlinks", lambda v: v == 1, 1, "symlink tricks in shared folders blocked"),
    ("fs.protected_hardlinks", lambda v: v == 1, 1, "hardlink tricks blocked"),
    ("fs.protected_fifos", lambda v: v >= 1, 1, "FIFO tricks in /tmp blocked"),
    ("fs.protected_regular", lambda v: v >= 1, 2, "file tricks in /tmp blocked"),
    ("net.ipv4.tcp_syncookies", lambda v: v == 1, 1, "SYN flood protection"),
    ("net.ipv4.conf.all.rp_filter", lambda v: v in (1, 2), 2, "drop packets with spoofed source addresses"),
    ("net.ipv4.conf.all.accept_redirects", lambda v: v == 0, 0, "ignore ICMP redirects (route hijacking)"),
    ("net.ipv6.conf.all.accept_redirects", lambda v: v == 0, 0, "ignore IPv6 redirects"),
]


@check("kernel", "Kernel hardening", "medium",
       "A few kernel switches make many attacks harder (guessing memory addresses, reading other "
       "programs, tricks with links in /tmp, spoofed packets). Most distributions set them; this "
       "checks that nothing turned them off.")
def kernel(probe, r):
    bad, read = [], 0
    for key, ok, want, what in SYSCTLS:
        text = probe.read("/proc/sys/" + key.replace(".", "/"))
        if text is None:
            continue
        read += 1
        try:
            value = int(text.split()[0])
        except (ValueError, IndexError):
            continue
        if not ok(value):
            bad.append((key, value, want, what))
    if not read:
        r.status, r.summary = "unknown", "/proc/sys is not readable"
        return
    if not bad:
        r.status, r.summary = "pass", f"all {read} switches checked are on"
        return
    r.status = "warn"
    r.summary = f"{len(bad)} of {read} switches are off: " + ", ".join(k for k, *_ in bad)
    r.details = [f"{k} = {v} (want {w}: {what})" for k, v, w, what in bad]
    r.fix = ["Write them to a file read at every boot, then load it now:",
             "$ printf '" + "\\n".join(f"{k} = {w}" for k, _, w, _ in bad) + "\\n' "
             "| sudo tee /etc/sysctl.d/90-aegis.conf",
             "$ sudo sysctl --system"]


@check("mac", "AppArmor or SELinux", "medium",
       "AppArmor and SELinux fence in programs such as the browser, the PDF viewer and system "
       "services, so a bug in one cannot read your whole home folder.")
def mac(probe, r):
    if (probe.read("/sys/module/apparmor/parameters/enabled") or "").strip() == "Y":
        r.status, r.summary = "pass", "AppArmor is enabled"
    elif (probe.read("/sys/fs/selinux/enforce") or "").strip() == "1":
        r.status, r.summary = "pass", "SELinux is enforcing"
    elif probe.exists("/sys/fs/selinux"):
        r.status, r.summary = "fail", "SELinux is present but not enforcing"
        r.fix = ["$ sudo setenforce 1   # and SELINUX=enforcing in /etc/selinux/config"]
    else:
        r.status, r.summary = "fail", "neither AppArmor nor SELinux is active"
        r.fix = ["$ sudo apt install apparmor apparmor-utils && sudo systemctl enable --now apparmor"]


@check("secure-boot", "Secure Boot", "low",
       "Secure Boot checks that the boot loader and kernel are signed before they run, so malware "
       "cannot hide below the operating system. It matters most together with disk encryption.")
def secure_boot(probe, r):
    if not probe.exists("/sys/firmware/efi"):
        r.status, r.summary = "info", "the machine boots in legacy BIOS mode (no Secure Boot)"
        return
    out = probe.run(["mokutil", "--sb-state"])
    text = (out[1] if out else "").lower()
    if "secureboot enabled" in text:
        r.status, r.summary = "pass", "Secure Boot is on"
    elif "secureboot disabled" in text:
        r.status, r.summary = "warn", "Secure Boot is off"
        if "setup mode" in text:
            r.details = ["the firmware is in Setup Mode (no platform key enrolled)"]
        r.fix = ["Turn it on in the firmware settings (usually F2/Del at power-on, Security or Boot tab).",
                 "Ubuntu boots signed with Secure Boot on; extra kernel modules (NVIDIA, VirtualBox) need",
                 "to be signed with a MOK key, which Ubuntu offers to set up when they are installed."]
    else:
        r.status, r.summary = "unknown", "mokutil is not installed"


@check("screen-lock", "Screen lock", "medium",
       "An unlocked screen gives anyone walking past your session: mail, browser logins, the "
       "terminal. A short idle time with a lock covers the moment you forget.")
def screen_lock(probe, r):
    def g(schema, key):
        out = probe.run(["gsettings", "get", schema, key])
        return out[1].strip() if out and out[0] == 0 else None
    lock = g("org.gnome.desktop.screensaver", "lock-enabled")
    idle = g("org.gnome.desktop.session", "idle-delay")
    delay = g("org.gnome.desktop.screensaver", "lock-delay")
    if lock is None or idle is None:
        r.status, r.summary = "unknown", "not a GNOME session (gsettings has no answer)"
        return
    idle_s = int(idle.split()[-1])
    delay_s = int(delay.split()[-1]) if delay else 0
    r.details = [f"lock-enabled {lock}", f"blank after {idle_s} s" if idle_s else "screen never blanks",
                 f"lock {delay_s} s after blanking"]
    if lock != "true" or idle_s == 0:
        r.status = "fail"
        r.summary = "the screen never locks by itself"
    elif idle_s + delay_s > 900:
        r.status = "warn"
        r.summary = f"the screen locks only after {(idle_s + delay_s) // 60} minutes"
    else:
        r.status = "pass"
        r.summary = f"the screen locks after {max(1, (idle_s + delay_s) // 60)} minute(s) idle"
        return
    r.fix = ["$ gsettings set org.gnome.desktop.screensaver lock-enabled true",
             "$ gsettings set org.gnome.desktop.session idle-delay 300",
             "$ gsettings set org.gnome.desktop.screensaver lock-delay 0",
             "And lock by hand when you walk away: Super+L."]


@check("autologin", "Automatic login", "medium",
       "With automatic login, switching the laptop on is enough to be inside your session; the "
       "password only protects you when it is asked.")
def autologin(probe, r):
    gdm = _kv(probe.read("/etc/gdm3/custom.conf") or probe.read("/etc/gdm/custom.conf") or "")
    lightdm = probe.read("/etc/lightdm/lightdm.conf") or ""
    if gdm.get("AutomaticLoginEnable", "").lower() == "true" or gdm.get("TimedLoginEnable", "").lower() == "true":
        r.status, r.summary = "fail", "GDM logs in automatically" + (
            f" as {gdm['AutomaticLogin']}" if gdm.get("AutomaticLogin") else "")
        r.fix = ["Settings → Users → turn off Automatic Login, or set AutomaticLoginEnable=false",
                 "in /etc/gdm3/custom.conf."]
    elif re.search(r"^\s*autologin-user\s*=\s*\S", lightdm, re.M):
        r.status, r.summary = "fail", "LightDM logs in automatically"
        r.fix = ["Remove the autologin-user line from /etc/lightdm/lightdm.conf."]
    else:
        r.status, r.summary = "pass", "a password is asked at login"


@check("time-sync", "Clock synchronization", "low",
       "TLS certificates, two-factor codes and log timestamps all depend on the right time. A "
       "clock that drifts makes valid certificates look invalid (and the other way round).")
def time_sync(probe, r):
    out = probe.run(["timedatectl", "show"])
    if out is None:
        r.status, r.summary = "unknown", "timedatectl is not available"
        return
    kv = _kv(out[1])
    if kv.get("NTPSynchronized") == "yes":
        r.status, r.summary = "pass", "the clock is synchronized"
    elif kv.get("NTP") == "yes":
        r.status, r.summary = "warn", "time sync is on but not synchronized yet (offline?)"
    else:
        r.status, r.summary = "warn", "automatic time sync is off"
        r.fix = ["$ sudo timedatectl set-ntp true"]


# --- browsers, radios, Wi-Fi ---------------------------------------------------------------

BROWSER_SNAPS = ("firefox", "chromium", "brave", "vivaldi", "opera", "thunderbird")


def _snap_revs(text: str) -> dict[str, str]:
    """`snap list` -> {name: installed revision}."""
    out = {}
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 3:
            out[cols[0]] = cols[2]
    return out


@check("browser-updates", "Browser updates", "medium",
       "The browser opens untrusted pages all day, so its security fixes matter most and attackers "
       "use a fixed bug within days. A snap browser is updated automatically, but only after it is "
       "closed: one that stays open for weeks keeps running the old version while the new one "
       "waits on disk. (Browsers from apt are covered by the security updates check.)")
def browser_updates(probe, r):
    listed = probe.run(["snap", "list"])
    if listed is None or listed[0] != 0:
        r.status, r.summary = "info", "no snap packages; browsers from apt are covered by the update checks"
        return
    installed = {n: rev for n, rev in _snap_revs(listed[1]).items() if n in BROWSER_SNAPS}
    if not installed:
        r.status, r.summary = "info", "no snap browser installed"
        return
    files = probe.listdir("/var/lib/snapd/snaps") or []
    waiting, names = [], []
    for name, rev in sorted(installed.items()):
        downloaded = [int(f[len(name) + 1:-5]) for f in files
                      if f.startswith(name + "_") and f.endswith(".snap") and f[len(name) + 1:-5].isdigit()]
        if rev.isdigit() and downloaded and max(downloaded) > int(rev):
            waiting.append(f"{name}: running revision {rev}, revision {max(downloaded)} is downloaded and waits")
            names.append(name)
    if waiting:
        r.status, r.details = "warn", waiting
        r.summary = f"{len(waiting)} browser update(s) downloaded but not installed: close the browser"
        r.fix = ["Close the browser completely (all windows); snap installs the waiting version then. Or:",
                 f"$ snap refresh {' '.join(names)}"]
    else:
        r.status = "pass"
        r.summary = f"no downloaded update is waiting ({', '.join(sorted(installed))})"


@check("bluetooth", "Bluetooth visibility", "low",
       "A discoverable laptop announces its name to everyone nearby and accepts pairing requests, "
       "which is how most Bluetooth attacks start. Discoverable is needed only while pairing a new "
       "device; switching Bluetooth off when unused is safer still.")
def bluetooth(probe, r):
    out = probe.run(["bluetoothctl", "show"])
    if out is None:
        r.status, r.summary = "info", "bluetoothctl is not installed (no Bluetooth stack)"
        return
    kv = _kv(out[1], ":")
    if not kv:
        r.status, r.summary = "info", "no Bluetooth controller"
        return
    powered, disc = kv.get("Powered") == "yes", kv.get("Discoverable") == "yes"
    if powered and disc:
        r.status, r.summary = "warn", "Bluetooth is on and discoverable to everyone nearby"
        r.fix = ["$ bluetoothctl discoverable off",
                 "Or switch Bluetooth off in Settings when you do not use it."]
    elif powered:
        r.status, r.summary = "pass", "Bluetooth is on, not discoverable"
    else:
        r.status, r.summary = "pass", "Bluetooth is off"


def _nm_wifi(probe) -> list[str] | None:
    out = probe.run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    if out is None or out[0] != 0:
        return None
    names = []
    for line in out[1].splitlines():
        # nmcli -t escapes ":" in names as "\:"
        name, _, kind = line.replace("\\:", "\0").rpartition(":")
        if kind == "802-11-wireless":
            names.append(name.replace("\0", ":"))
    return names


@check("open-wifi", "Open Wi-Fi networks", "medium",
       "A saved Wi-Fi network without a password is joined again by name, and anyone can create a "
       "network with that name (\"Airport Free WiFi\"). The laptop then connects to them by itself, "
       "and everything that is not encrypted end to end passes through their hands.")
def open_wifi(probe, r):
    names = _nm_wifi(probe)
    if names is None:
        r.status, r.summary = "unknown", "NetworkManager (nmcli) is not available"
        return
    risky, open_names, unknown = [], [], 0
    for name in names:
        out = probe.run(["nmcli", "-t", "-f", "802-11-wireless-security.key-mgmt,connection.autoconnect",
                         "connection", "show", name])
        if out is None or out[0] != 0:
            unknown += 1
            continue
        kv = _kv(out[1], ":")
        key = kv.get("802-11-wireless-security.key-mgmt", "")
        if key in ("", "none") and kv.get("connection.autoconnect") == "yes":
            risky.append(f"{name}: {'no password' if key == '' else 'WEP (broken)'}, joins automatically")
            open_names.append(name)
    if risky:
        r.status, r.details = "warn", risky
        r.summary = f"{len(risky)} saved open Wi-Fi network(s) join automatically"
        r.fix = ["Forget them, or at least stop joining them by themselves:",
                 *[f"$ nmcli connection modify {shlex.quote(n)} connection.autoconnect no" for n in open_names]]
    elif unknown and unknown == len(names):
        r.status, r.summary = "unknown", "the saved Wi-Fi networks could not be read"
    else:
        r.status = "pass"
        r.summary = f"all {len(names)} saved Wi-Fi network(s) use a password" if names else "no saved Wi-Fi networks"


# --- your files -------------------------------------------------------------------------------

def _private_key_kind(text: str) -> str | None:
    """"encrypted", "plain" or None if this is not a private key. Only the header is
    decoded (the cipher name); the key itself is never looked at."""
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in text:
        body = text.split("-----BEGIN OPENSSH PRIVATE KEY-----", 1)[1].split("-----END", 1)[0]
        try:
            raw = base64.b64decode("".join(body.split())[:200] + "===", validate=False)
        except ValueError:
            return "encrypted"
        magic = b"openssh-key-v1\0"
        if not raw.startswith(magic) or len(raw) < len(magic) + 4:
            return "encrypted"
        n = int.from_bytes(raw[len(magic):len(magic) + 4], "big")
        cipher = raw[len(magic) + 4:len(magic) + 4 + n]
        return "plain" if cipher == b"none" else "encrypted"
    m = re.search(r"-----BEGIN (RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----", text)
    if not m:
        return None
    return "encrypted" if m.group(1) == "ENCRYPTED " or "Proc-Type: 4,ENCRYPTED" in text else "plain"


def _ssh_private_keys(probe):
    for name in probe.listdir("~/.ssh") or []:
        if name.endswith(".pub") or name in ("known_hosts", "known_hosts.old", "authorized_keys", "config"):
            continue
        text = probe.read(f"~/.ssh/{name}")
        kind = _private_key_kind(text[:20000]) if text else None
        if kind:
            yield name, kind


@check("home-permissions", "Home folder permissions", "medium",
       "Other accounts on the machine (and services that run as their own user) should not be "
       "able to read your files, and your SSH and GnuPG keys must be readable by you alone.")
def home_permissions(probe, r):
    problems, fix = [], []
    home = probe.stat("~")
    if home is None:
        r.status, r.summary = "unknown", "cannot read the home folder"
        return
    if home.mode & 0o007:
        problems.append(f"the home folder is open to other users ({oct(home.mode & 0o777)[2:]})")
        fix.append("$ chmod 750 ~")
    for folder in ("~/.ssh", "~/.gnupg"):
        st = probe.stat(folder)
        if st is not None and st.mode & 0o077:
            problems.append(f"{folder} can be read by others ({oct(st.mode & 0o777)[2:]})")
            fix.append(f"$ chmod 700 {folder}")
    for name, _ in _ssh_private_keys(probe):
        st = probe.stat(f"~/.ssh/{name}")
        if st is not None and st.mode & 0o077:
            problems.append(f"private key ~/.ssh/{name} can be read by others ({oct(st.mode & 0o777)[2:]})")
            fix.append(f"$ chmod 600 ~/.ssh/{name}")
    st = probe.stat("~/.ssh/authorized_keys")
    if st is not None and st.mode & 0o022:
        problems.append("~/.ssh/authorized_keys can be changed by others")
        fix.append("$ chmod 600 ~/.ssh/authorized_keys")
    if not problems:
        r.status, r.summary = "pass", f"home is {oct(home.mode & 0o777)[2:]}; keys are private"
        return
    r.status = "fail" if any("private key" in p or "authorized_keys" in p for p in problems) else "warn"
    r.summary = problems[0] + (f" (and {len(problems) - 1} more)" if len(problems) > 1 else "")
    r.details, r.fix = problems, fix


@check("ssh-keys", "SSH key passphrases", "medium",
       "A private key without a passphrase works for whoever copies the file: a stolen backup, "
       "a synced folder or malware reading your home is enough. With a passphrase (and ssh-agent "
       "so you type it once per session) the file alone is useless.")
def ssh_keys(probe, r):
    keys = list(_ssh_private_keys(probe))
    if not keys:
        r.status, r.summary = "pass", "no private SSH keys in ~/.ssh"
        return
    plain = [n for n, kind in keys if kind == "plain"]
    r.details = [f"{n}: {'no passphrase' if kind == 'plain' else 'passphrase protected'}" for n, kind in keys]
    if not plain:
        r.status, r.summary = "pass", f"all {len(keys)} private key(s) have a passphrase"
        return
    r.status = "warn"
    r.summary = f"{len(plain)} private key(s) without a passphrase: {', '.join(plain)}"
    r.fix = [f"$ ssh-keygen -p -f ~/.ssh/{plain[0]}    # adds a passphrase, the key stays the same"]


@check("path", "Safe PATH", "medium",
       "PATH decides which program runs when you type a command. A folder in it that others can "
       "write to (or '.', the current folder) lets someone plant a fake 'ls' or 'sudo'.")
def path(probe, r):
    value = probe.env("PATH")
    if not value:
        r.status, r.summary = "unknown", "PATH is empty"
        return
    problems = []
    for entry in value.split(":"):
        if entry in ("", "."):
            problems.append("the current folder is in PATH ('.' or an empty entry)")
            continue
        st = probe.stat(entry, follow=True)    # /bin is often a link to /usr/bin
        if st is None:
            continue
        if st.mode & 0o002 and not st.mode & stat.S_ISVTX:
            problems.append(f"{entry} can be written by anyone")
        elif st.uid not in (0, probe.uid):
            problems.append(f"{entry} belongs to another user (uid {st.uid})")
    if not problems:
        r.status, r.summary = "pass", f"all {len(value.split(':'))} PATH folders are yours or root's"
        return
    r.status, r.summary, r.details = "fail", problems[0], problems
    r.fix = ["Remove the entry from PATH in ~/.profile or ~/.bashrc, or fix the folder:",
             "$ chmod o-w <folder>"]


@check("backups", "Recent backup", "medium",
       "Disk failure, theft and ransomware all end the same way without a backup. Aegis reads "
       "the status file of Mnemosyne; other tools are listed as unknown.")
def backups(probe, r):
    text = probe.read("~/.local/state/mnemosyne/status.json")
    if text is None:
        r.status = "unknown"
        r.summary = "no backup tool Aegis knows about reported (looked for Mnemosyne's status file)"
        return
    try:
        repos = json.loads(text).get("repos", {})
    except ValueError:
        r.status, r.summary = "unknown", "Mnemosyne's status file is not valid JSON"
        return
    now = datetime.now(timezone.utc)
    ages = []
    for name, info in repos.items():
        t = ((info or {}).get("last_good_backup") or {}).get("time")
        if not t:
            ages.append((name, None))
            continue
        ages.append((name, (now - datetime.fromisoformat(t.replace("Z", "+00:00"))).total_seconds() / 3600))
    if not ages:
        r.status, r.summary = "fail", "Mnemosyne is set up but has no repository"
        return
    r.details = [f"{n}: {'never' if a is None else f'{a:.0f} h ago'}" for n, a in ages]
    newest = min((a for _, a in ages if a is not None), default=None)
    if newest is None:
        r.status, r.summary = "fail", "no backup has succeeded yet"
    elif newest > 72:
        r.status, r.summary = "fail", f"the newest good backup is {newest / 24:.0f} days old"
    elif any(a is None or a > 48 for _, a in ages):
        r.status, r.summary = "warn", "one backup copy is behind (older than 2 days)"
    else:
        r.status, r.summary = "pass", f"{len(ages)} backup copies, newest {newest:.0f} h ago"
