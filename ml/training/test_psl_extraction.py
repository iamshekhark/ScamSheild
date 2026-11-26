"""
Public Suffix List (PSL) extraction verification test.
Validates that extract_registrable_domain correctly extracts the registrable domain
for multi-part ccTLDs (.co.uk, .com.au, .co.in, etc.) to prevent domain leakage.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prepare_datasets import extract_registrable_domain

cases = {
    'http://example.com/': 'example.com',
    'https://example.co.uk/page': 'example.co.uk',
    'https://example.com.au/login': 'example.com.au',
    'https://subdomain.example.co.in/path': 'example.co.in',
    'https://suspicious-example.com': 'suspicious-example.com',
    'http://192.168.1.1:8080/auth': '192.168.1.1',
    'localhost': 'localhost'
}

for inp, expected in cases.items():
    actual = extract_registrable_domain(inp)
    assert actual == expected, f"Failed on {inp}: expected {expected}, got {actual}"

print("PSL_VERIFIED")
