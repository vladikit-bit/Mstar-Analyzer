from __future__ import annotations

from .strings import StringFinding

KEYWORDS = (
    "elf",
    ".so",
    "/bin/",
    "/usr/",
    "/etc/",
    "/lib/",
    "init",
    "busybox",
    "lua",
    "sqlite",
    "jpeg",
    "png",
    "font",
    "xml",
    "html",
    "http",
    "https",
    "ssl",
    "openssl",
    "curl",
    "wifi",
    "wlan",
    "eth",
    "mstar",
    "mboot",
    "miu",
    "panel",
    "hdmi",
    "audio",
    "video",
    "mpeg",
    "h264",
    "h265",
    "ffmpeg",
    "codec",
    "netsrv",
)


def score_string(text: str) -> int:

    score = 0

    lower = text.lower()

    if len(text) >= 20:
        score += 1

    if "/" in text:
        score += 2

    if "." in text:
        score += 1

    if "%" in text:
        score += 2

    if "[" in text:
        score += 2

    for keyword in KEYWORDS:
        if keyword in lower:
            score += 5

    return score


def filter_strings(
    strings: list[StringFinding],
    min_score: int = 3,
) -> list[StringFinding]:

    return [
        s
        for s in strings
        if score_string(s.text) >= min_score
    ]
