#!/usr/bin/env python3
"""
Test script for INMUX tools (HackerTarget API) without API key
"""

from har_analyzer import HARAdvancedAnalyzer

print("Testing INMUX tools (HackerTarget API) in free mode...")
print("=" * 60)

analyzer = HARAdvancedAnalyzer()

# Test DNS lookup
print("\n1. Testing DNS lookup for google.com...")
result = analyzer.dns_lookup('google.com')
print(f"Result: {result[:200]}...")

# Test GeoIP lookup
print("\n2. Testing GeoIP lookup for 8.8.8.8...")
result = analyzer.geoip_lookup('8.8.8.8')
print(f"Result: {result[:200]}...")

# Test Whois lookup
print("\n3. Testing Whois lookup for google.com...")
result = analyzer.whois_lookup('google.com')
print(f"Result: {result[:200]}...")

# Test Host finder
print("\n4. Testing Host finder for google.com...")
result = analyzer.host_finder('google.com')
print(f"Result: {result[:200]}...")

print("\n" + "=" * 60)
print("INMUX tools test completed!")
