#!/usr/bin/env python3
import socket
import sys

# DNS usually runs on port 53. 
# NOTE: Binding to port 53 requires ROOT privileges (sudo).
IP = '0.0.0.0'
PORT = 8080

def run_dns_server():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((IP, PORT))
        print(f"[+] DNS Listener running on {IP}:{PORT}")
        print("[!] Note: This server only logs queries; it does not send valid responses.")
        
        while True:
            data, addr = sock.recvfrom(512)
            print(f"\n[+] Received DNS query from {addr[0]}:{addr[1]}")
            
            try:
                # Basic parsing of the DNS Question Section
                # Header is 12 bytes. Question starts immediately after.
                # Format: [len][label][len][label]...[00]
                idx = 12
                domain_parts = []
                while idx < len(data):
                    length = data[idx]
                    if length == 0:
                        break
                    idx += 1
                    label = data[idx : idx + length]
                    domain_parts.append(label.decode('utf-8', errors='ignore'))
                    idx += length
                
                domain = ".".join(domain_parts)
                print(f"    Query for: {domain}")
            except Exception as e:
                print(f"    (Could not parse domain name: {e})")
                
    except PermissionError:
        print(f"[-] Error: Permission denied. You must run this script with 'sudo' to bind to port {PORT}.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    run_dns_server()
