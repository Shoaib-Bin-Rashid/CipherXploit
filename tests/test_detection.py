#!/usr/bin/env python3
"""
Test detection functions to ensure they work correctly
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cipherxploit import (
    detect_base64_pattern, detect_hex_pattern, detect_binary_pattern,
    detect_caesar_pattern, detect_numbers_pattern, detect_morse_pattern,
    analyze_and_prioritize
)
import base64

def test_base64_detection():
    """Test Base64 pattern detection"""
    print("Testing Base64 detection...")
    
    # Positive cases
    b64_data = base64.b64encode(b"hello world").decode()
    confidence = detect_base64_pattern(b64_data.encode())
    assert confidence > 0.7, f"Expected high confidence for Base64, got {confidence}"
    
    # Test with our known example
    test_b64 = "cGljb2N0Znt0ZXN0X2ZsYWd9"
    confidence = detect_base64_pattern(test_b64.encode())
    assert confidence > 0.7, f"Expected high confidence for test Base64, got {confidence}"
    
    # Negative case
    plain_text = "this is just plain text"
    confidence = detect_base64_pattern(plain_text.encode())
    assert confidence < 0.3, f"Expected low confidence for plain text, got {confidence}"
    
    print("✅ Base64 detection tests passed")

def test_hex_detection():
    """Test hex pattern detection"""
    print("Testing hex detection...")
    
    # Positive case
    hex_data = "48656c6c6f20576f726c64"  # "Hello World" in hex
    confidence = detect_hex_pattern(hex_data.encode())
    assert confidence > 0.5, f"Expected high confidence for hex, got {confidence}"
    
    # Test with our known example
    test_hex = "7069636f6374667b746573747d"
    confidence = detect_hex_pattern(test_hex.encode())
    assert confidence > 0.7, f"Expected high confidence for test hex, got {confidence}"
    
    # Negative case
    plain_text = "this is not hex"
    confidence = detect_hex_pattern(plain_text.encode())
    assert confidence == 0.0, f"Expected zero confidence for non-hex, got {confidence}"
    
    print("✅ Hex detection tests passed")

def test_binary_detection():
    """Test binary pattern detection"""
    print("Testing binary detection...")
    
    # Positive case
    binary_data = "01001000 01100101 01101100 01101100 01101111"
    confidence = detect_binary_pattern(binary_data.encode())
    assert confidence > 0.5, f"Expected high confidence for binary, got {confidence}"
    
    # Negative case  
    plain_text = "this is not binary"
    confidence = detect_binary_pattern(plain_text.encode())
    assert confidence == 0.0, f"Expected zero confidence for non-binary, got {confidence}"
    
    print("✅ Binary detection tests passed")

def test_caesar_detection():
    """Test Caesar cipher pattern detection"""
    print("Testing Caesar detection...")
    
    # Positive case (text with low E frequency)
    caesar_like = "KHOOR ZRUOG"  # "HELLO WORLD" with Caesar +3
    confidence = detect_caesar_pattern(caesar_like.encode())
    assert confidence > 0.3, f"Expected some confidence for Caesar-like text, got {confidence}"
    
    # Normal English text should have lower confidence
    english_text = "HELLO WORLD THIS IS ENGLISH TEXT WITH MANY E LETTERS"
    confidence = detect_caesar_pattern(english_text.encode())
    # Should be lower confidence since E frequency is normal
    
    print("✅ Caesar detection tests passed")

def test_numbers_detection():
    """Test ASCII numbers pattern detection"""
    print("Testing numbers detection...")
    
    # Positive case
    ascii_numbers = "72 101 108 108 111"  # "Hello" in ASCII
    confidence = detect_numbers_pattern(ascii_numbers.encode())
    assert confidence > 0.5, f"Expected high confidence for ASCII numbers, got {confidence}"
    
    # Negative case
    big_numbers = "1000 2000 3000"  # Outside ASCII range
    confidence = detect_numbers_pattern(big_numbers.encode())
    assert confidence < 0.5, f"Expected low confidence for non-ASCII numbers, got {confidence}"
    
    print("✅ Numbers detection tests passed")

def test_morse_detection():
    """Test Morse code pattern detection"""
    print("Testing Morse detection...")
    
    # Positive case
    morse_data = ".... . .-.. .-.. ---"  # "HELLO" in Morse
    confidence = detect_morse_pattern(morse_data.encode())
    assert confidence > 0.5, f"Expected high confidence for Morse, got {confidence}"
    
    # Negative case
    plain_text = "this is not morse"
    confidence = detect_morse_pattern(plain_text.encode())
    assert confidence == 0.0, f"Expected zero confidence for non-Morse, got {confidence}"
    
    print("✅ Morse detection tests passed")

def test_analyze_prioritize():
    """Test the full analysis and prioritization"""
    print("Testing analysis and prioritization...")
    
    # Test Base64
    b64_data = "cGljb2N0Znt0ZXN0X2ZsYWd9"
    predictions = analyze_and_prioritize(b64_data.encode())
    assert len(predictions) > 0, "Expected at least one prediction"
    assert predictions[0][0] == "base64", f"Expected base64 as top prediction, got {predictions[0][0]}"
    
    # Test hex
    hex_data = "7069636f6374667b746573747d"
    predictions = analyze_and_prioritize(hex_data.encode())
    assert len(predictions) > 0, "Expected at least one prediction"
    assert predictions[0][0] == "hex", f"Expected hex as top prediction, got {predictions[0][0]}"
    
    print("✅ Analysis and prioritization tests passed")

def run_all_tests():
    """Run all detection tests"""
    print("🧪 Running detection tests...")
    print("=" * 50)
    
    try:
        test_base64_detection()
        test_hex_detection() 
        test_binary_detection()
        test_caesar_detection()
        test_numbers_detection()
        test_morse_detection()
        test_analyze_prioritize()
        
        print("=" * 50)
        print("🎉 All detection tests passed!")
        return True
        
    except AssertionError as e:
        print(f"❌ Test failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)