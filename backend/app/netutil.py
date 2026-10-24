"""Hilfen rund um IP-Adressen."""
from __future__ import annotations

import ipaddress
from functools import lru_cache


@lru_cache(maxsize=65536)
def classify(ip: str) -> str:
    """'private' (Heimnetz, VPN, Docker), 'loopback', 'public' oder 'invalid'."""
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return "invalid"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_loopback:
        return "loopback"
    if addr.is_private or addr.is_link_local or addr.is_reserved or addr in ipaddress.ip_network("100.64.0.0/10"):
        return "private"
    return "public"


def is_public(ip: str) -> bool:
    return classify(ip) == "public"


def normalize_cidr(text: str) -> str:
    """Prüft eine Adresse oder ein Netz (1.2.3.4, 1.2.3.0/24, 2001:db8::/48) und gibt die Normalform zurück."""
    text = text.strip()
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 16):
                raise ValueError("zu groß")
            return str(net)
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError(f"„{text}“ ist keine gültige Adresse oder kein gültiges Netz (z. B. 203.0.113.7 oder 203.0.113.0/24)")


def ip_in(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
