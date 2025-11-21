import pytest
from password_checker import check_password_strength
from intrusion_detection import extract_raddr
from encryption_tool import load_or_create_key
from pathlib import Path
import os

def test_password_strength():
    assert "Weak Password ❌" == check_password_strength("abc123")  # lowercase + numbers only
    assert "Medium Password ⚠️" == check_password_strength("Abc123")  # upper, lower, numbers
    assert "Strong Password ✅" == check_password_strength("StrongP@ss123")  # all criteria

def test_extract_raddr():
    # Test tuple format
    assert extract_raddr(("127.0.0.1", 8080)) == ("127.0.0.1", 8080)
    assert extract_raddr(()) is None
    assert extract_raddr((1,)) is None
    
    # Test object format
    class Addr:
        def __init__(self, ip, port):
            self.ip = ip
            self.port = port
    addr = Addr("192.168.1.1", 443)
    assert extract_raddr(addr) == ("192.168.1.1", 443)

def test_encryption():
    # Create temporary key file
    test_key_file = Path("test_secret.key")
    key = load_or_create_key(test_key_file)
    assert len(key) > 0
    assert test_key_file.exists()
    
    # Clean up
    test_key_file.unlink()