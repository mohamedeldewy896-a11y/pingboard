import socket
 
import pytest
 
import checker
 
 
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
 
 
def test_validate_port_ok():
    assert checker.validate_port("443") == 443
 
 
@pytest.mark.parametrize("bad", ["abc", "0", "70000", None, ""])
def test_validate_port_rejects_bad_values(bad):
    with pytest.raises(checker.CheckError):
        checker.validate_port(bad)
 
 
def test_tcp_open():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        state, ms = checker.tcp_check("127.0.0.1", port)
        assert state == "open" and ms is not None
    finally:
        server.close()
 
 
def test_tcp_refused_when_nothing_listens():
    state, ms = checker.tcp_check("127.0.0.1", free_port())
    assert state == "refused" and ms is None
 
 
def test_internal_addresses_are_detected():
    assert checker.is_internal("127.0.0.1")
    assert checker.is_internal("10.0.2.15")
    assert checker.is_internal("169.254.169.254")
    assert not checker.is_internal("8.8.8.8")
 
 
def test_private_blocked_by_default():
    with pytest.raises(checker.CheckError):
        checker.run_check("127.0.0.1", 80)
