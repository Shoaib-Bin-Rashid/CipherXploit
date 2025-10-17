#!/usr/bin/env python3
"""
Integration tests to ensure main functionality works correctly
"""

import sys
import os
import subprocess
import base64

def run_cipherxploit(flag_format, ciphertext, key=None):
    """Run cipherxploit and return output"""
    cmd = [sys.executable, "cipherxploit.py", flag_format, "-c", ciphertext]
    if key:
        cmd.extend(["-k", key])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"

def test_base64_flag():
    """Test that Base64 encoded flags are found correctly"""
    print("Testing Base64 flag detection...")
    
    flag = "picoctf{test_flag}"
    encoded = base64.b64encode(flag.encode()).decode()
    
    returncode, stdout, stderr = run_cipherxploit("picoctf", encoded)
    
    assert returncode == 0, f"Expected success, got return code {returncode}"
    assert "Flag Found" in stdout, f"Expected 'Flag Found' in output: {stdout}"
    assert flag in stdout, f"Expected '{flag}' in output: {stdout}"
    assert "[base64]" in stdout, f"Expected '[base64]' operation in output: {stdout}"
    
    print("✅ Base64 flag test passed")

def test_hex_flag():
    """Test that hex encoded flags are found correctly"""
    print("Testing hex flag detection...")
    
    flag = "picoctf{hex_test}"
    encoded = flag.encode().hex()
    
    returncode, stdout, stderr = run_cipherxploit("picoctf", encoded)
    
    assert returncode == 0, f"Expected success, got return code {returncode}"
    assert "Flag Found" in stdout, f"Expected 'Flag Found' in output: {stdout}"
    assert flag in stdout, f"Expected '{flag}' in output: {stdout}"
    assert "[hex]" in stdout, f"Expected '[hex]' operation in output: {stdout}"
    
    print("✅ Hex flag test passed")

def test_caesar_flag():
    """Test Caesar cipher flag detection"""
    print("Testing Caesar flag detection...")
    
    # Create Caesar cipher manually (shift +3)
    flag = "picoctf{caesar_test}"
    shifted = ""
    for char in flag:
        if 'a' <= char <= 'z':
            shifted += chr(((ord(char) - ord('a') + 3) % 26) + ord('a'))
        elif 'A' <= char <= 'Z':
            shifted += chr(((ord(char) - ord('A') + 3) % 26) + ord('A'))
        else:
            shifted += char
    
    returncode, stdout, stderr = run_cipherxploit("picoctf", shifted)
    
    assert returncode == 0, f"Expected success, got return code {returncode}"
    assert "Flag Found" in stdout, f"Expected 'Flag Found' in output: {stdout}"
    assert flag in stdout, f"Expected '{flag}' in output: {stdout}"
    
    print("✅ Caesar flag test passed")

def test_detection_suggestions():
    """Test that detection suggestions appear in output"""
    print("Testing detection suggestions...")
    
    # Test Base64 suggestion
    b64_data = base64.b64encode(b"picoctf{test}").decode()
    returncode, stdout, stderr = run_cipherxploit("picoctf", b64_data)
    
    assert "Smart suggestion:" in stdout, f"Expected 'Smart suggestion:' in output: {stdout}"
    assert "base64" in stdout, f"Expected 'base64' suggestion in output: {stdout}"
    
    # Test hex suggestion  
    hex_data = "picoctf{test}".encode().hex()
    returncode, stdout, stderr = run_cipherxploit("picoctf", hex_data)
    
    assert "Smart suggestion:" in stdout, f"Expected 'Smart suggestion:' in output: {stdout}"
    assert "hex" in stdout, f"Expected 'hex' suggestion in output: {stdout}"
    
    print("✅ Detection suggestions test passed")

def test_no_flag_found():
    """Test behavior when no flag is found"""
    print("Testing no flag found scenario...")
    
    # Use random data that won't decode to a flag
    random_data = "xyzabc123notaflag"
    
    # Provide 'N' input for the interactive prompt
    cmd = [sys.executable, "cipherxploit.py", "picoctf", "-c", random_data]
    try:
        result = subprocess.run(cmd, input="N\n", capture_output=True, text=True, timeout=30)
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        returncode, stdout, stderr = -1, "", "Timeout"
    
    # Should exit with non-zero code when no flag found
    assert returncode != 0, f"Expected non-zero return code for no flag found"
    assert "No exact-case flag found" in stdout, f"Expected 'No exact-case flag found' message: {stdout}"
    
    print("✅ No flag found test passed")

def run_all_tests():
    """Run all integration tests"""
    print("🧪 Running integration tests...")
    print("=" * 50)
    
    # Change to correct directory
    os.chdir(os.path.dirname(os.path.dirname(__file__)))
    
    try:
        test_base64_flag()
        test_hex_flag()
        test_caesar_flag()
        test_detection_suggestions()
        test_no_flag_found()
        
        print("=" * 50)
        print("🎉 All integration tests passed!")
        return True
        
    except AssertionError as e:
        print(f"❌ Test failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)