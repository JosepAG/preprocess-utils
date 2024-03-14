import ipaddress


def ip_string_to_ip_net(ip_string: str) -> str:
    ip = ipaddress.ip_address(ip_string)
    return "PRIVATE" if ip.is_private else "PUBLIC"
