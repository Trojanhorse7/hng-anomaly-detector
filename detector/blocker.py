"""
iptables NETFILTER (host net namespace). Needs NET_ADMIN; use network_mode: host
on the detector service so rules affect the host.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from typing import Final

log = logging.getLogger(__name__)

_V4: Final[re.Pattern[str]] = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$",
)


def valid_ipv4(s: str) -> bool:
    s = s.strip()
    if not _V4.match(s):
        return False
    try:
        ipaddress.IPv4Address(s)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return True


def _run_iptables(args: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    p = subprocess.run(  # noqa: S603
        ["iptables", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def drop_ip(ip: str) -> bool:
    if not valid_ipv4(ip):
        log.warning("blocker: skip invalid ip %r", ip)
        return False
    tag = f"hng-ban-{ip.replace('.', '_')}"
    # check exists
    code, _out, _ = _run_iptables(
        [
            "-C",
            "INPUT",
            "-s",
            f"{ip}/32",
            "-j",
            "DROP",
            "-m",
            "comment",
            "--comment",
            tag,
        ],
    )
    if code == 0:
        log.debug("blocker: already has rule for %s", ip)
        return True
    code, out, err = _run_iptables(
        [
            "-I",
            "INPUT",
            "1",
            "-s",
            f"{ip}/32",
            "-j",
            "DROP",
            "-m",
            "comment",
            "--comment",
            tag,
        ],
    )
    if code != 0:
        log.error("blocker: iptables add failed: %s", err)
        return False
    log.info("blocker: DROP %s", ip)
    return True


def undrop_ip(ip: str) -> bool:
    if not valid_ipv4(ip):
        return False
    tag = f"hng-ban-{ip.replace('.', '_')}"
    # delete by match (repeat until no rule)
    for _ in range(5):
        code, _, _ = _run_iptables(
            [
                "-D",
                "INPUT",
                "-s",
                f"{ip}/32",
                "-j",
                "DROP",
                "-m",
                "comment",
                "--comment",
                tag,
            ],
        )
        if code != 0:
            break
    # fallback: delete without comment match (older rule)
    _run_iptables(["-D", "INPUT", "-s", f"{ip}/32", "-j", "DROP"])
    log.info("blocker: removed DROP for %s", ip)
    return True
