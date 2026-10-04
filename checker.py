"""Network checks used by PingBoard: DNS, then a TCP handshake."""
import ipaddress
import socket
import time
 
 
class CheckError(Exception):
    """Raised for invalid user input (bad port, blocked address)."""
 
 
def validate_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise CheckError("port must be a number")
    if not 1 <= port <= 65535:
        raise CheckError("port must be between 1 and 65535")
    return port
 
 
def resolve(host):
    """DNS step: return the first IPv4 address for a host name."""
    return socket.gethostbyname(host)
 
 
def is_internal(ip):
    """True for private, loopback or link-local addresses."""
    addr = ipaddress.ip_address(ip)
    return addr.is_private or addr.is_loopback or addr.is_link_local
 
 
def tcp_check(ip, port, timeout=3.0):
    """Try a TCP handshake. Returns (state, milliseconds)."""
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open", round((time.monotonic() - start) * 1000)
    except ConnectionRefusedError:
        return "refused", None      # host answered: nothing is listening
    except socket.timeout:
        return "timeout", None      # no answer: firewall drop or host down
    except OSError:
        return "error", None
 
 
def run_check(host, port, allow_private=False):
    """Full check: DNS first, then TCP. Returns a dict ready for JSON."""
    result = {"host": host, "port": port}
    try:
        result["ip"] = resolve(host)
    except socket.gaierror as exc:
        result.update(dns="failed", tcp="not tested", error=str(exc))
        return result
    result["dns"] = "ok"
    if not allow_private and is_internal(result["ip"]):
        raise CheckError("private/internal addresses are not allowed")
    state, ms = tcp_check(result["ip"], port)
    result["tcp"] = state
    if ms is not None:
        result["ms"] = ms
    return result
