from __future__ import annotations

from collections.abc import Iterable

from ..strings import StringFinding

from dataclasses import dataclass, field

import re


@dataclass
class BusyBoxInfo:
    version: str | None = None
    applets: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)


APPLETS = frozenset({
    "ash",
    "sh",
    "mount",
    "umount",
    "ls",
    "cp",
    "mv",
    "rm",
    "mkdir",
    "ifconfig",
    "ip",
    "route",
    "wget",
    "httpd",
    "telnetd",
    "telnet",
    "ftpd",
    "ftpget",
    "ftpput",
    "udhcpd",
    "udhcpc",
    "mdev",
    "syslogd",
    "klogd",
    "init",
    "reboot",
    "poweroff",
})

BUSYBOX_VERSION = re.compile(
    r"BusyBox(?:\s+v)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.I,
)

def analyze_busybox(strings: Iterable[StringFinding]) -> BusyBoxInfo | None:

    info = BusyBoxInfo()

    for s in strings:

        m = BUSYBOX_VERSION.search(s.text)
        if m:
            info.version = m.group(1)

            if s.text not in info.evidence:
                info.evidence.append(s.text)

        if s.text in APPLETS:
            info.applets.add(s.text)

    if not info.version and not info.applets:
        return None

    return info