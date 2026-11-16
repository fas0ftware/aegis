"""How Aegis looks at the system: read a file, run a command, list a folder.

Every check goes through a Probe, so the tests (and the demo) can hand in a made-up
machine. The real probe only reads: it never writes, never asks for a password and
never runs anything through a shell.
"""

from __future__ import annotations

import os
import shutil
import stat
# fixed argument lists, never a shell
import subprocess  # nosec B404
from dataclasses import dataclass, field
from pathlib import Path

MAX_READ = 1_000_000


@dataclass
class StatInfo:
    mode: int
    uid: int


class Probe:
    """The real machine."""

    def __init__(self, root: str = "/", home: str | None = None, timeout: float = 5.0):
        self.root = Path(root)
        self.home = Path(home or os.path.expanduser("~"))
        self.timeout = timeout
        self.uid = os.getuid()
        self.user = os.environ.get("USER") or str(self.uid)

    def _path(self, path: str) -> Path:
        p = Path(path.replace("~", str(self.home), 1) if path.startswith("~") else path)
        return self.root / p.relative_to("/") if self.root != Path("/") and p.is_absolute() else p

    def read(self, path: str) -> str | None:
        """File text, or None if it is missing or not readable (without root)."""
        try:
            with open(self._path(path), "rb") as f:
                return f.read(MAX_READ).decode("utf-8", "replace")
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        return os.path.lexists(self._path(path))

    def stat(self, path: str, follow: bool = False) -> StatInfo | None:
        try:
            st = os.stat(self._path(path)) if follow else os.lstat(self._path(path))
        except OSError:
            return None
        return StatInfo(st.st_mode, st.st_uid)

    def listdir(self, path: str) -> list[str] | None:
        try:
            return sorted(os.listdir(self._path(path)))
        except OSError:
            return None

    def run(self, argv: list[str]) -> tuple[int, str] | None:
        """(exit code, stdout) or None when the program is not installed or hangs."""
        exe = shutil.which(argv[0])
        if exe is None:
            return None
        try:
            r = subprocess.run([exe, *argv[1:]], capture_output=True, text=True, timeout=self.timeout,  # nosec B603
                               env={**os.environ, "LC_ALL": "C"}, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return r.returncode, r.stdout

    def env(self, name: str) -> str:
        return os.environ.get(name, "")


@dataclass
class FakeProbe:
    """A made-up machine for tests and the demo."""

    files: dict[str, str] = field(default_factory=dict)
    modes: dict[str, int] = field(default_factory=dict)        # path -> st_mode (with type bits)
    commands: dict[tuple, tuple[int, str]] = field(default_factory=dict)
    environ: dict[str, str] = field(default_factory=dict)
    home: Path = Path("/home/demo")
    uid: int = 1000
    user: str = "demo"

    def _p(self, path: str) -> str:
        return str(self.home) + path[1:] if path.startswith("~") else path

    def read(self, path: str) -> str | None:
        return self.files.get(self._p(path))

    def exists(self, path: str) -> bool:
        p = self._p(path)
        return p in self.files or p in self.modes or any(k.startswith(p.rstrip("/") + "/") for k in self.files)

    def stat(self, path: str, follow: bool = False) -> StatInfo | None:
        p = self._p(path)
        if p in self.modes:
            return StatInfo(self.modes[p], self.uid)
        if p in self.files:
            return StatInfo(stat.S_IFREG | 0o644, self.uid)
        return None

    def listdir(self, path: str) -> list[str] | None:
        p = self._p(path).rstrip("/") + "/"
        names = {k[len(p):].split("/")[0] for k in [*self.files, *self.modes] if k.startswith(p)}
        return sorted(names) if names or p.rstrip("/") in self.modes else None

    def run(self, argv: list[str]) -> tuple[int, str] | None:
        return self.commands.get(tuple(argv))

    def env(self, name: str) -> str:
        return self.environ.get(name, "")
