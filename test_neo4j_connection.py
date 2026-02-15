#!/usr/bin/env python3
"""
Test Neo4j connectivity and configuration
"""

import sys
from neo4j import GraphDatabase
from urllib.parse import urlparse

# Neo4j connection details
URI = "neo4j+s://e023f02b.databases.neo4j.io"
USERNAME = "neo4j"
PASSWORD = "Mo_q36wZ3-VJtjgE5RtRUOIbS4uFP2O83Ne1krlay9A"

def test_connection():
    """Test direct Neo4j driver connection"""
    print("\n" + "="*60)
    print("NEO4J CONNECTION DIAGNOSTIC")
    print("="*60 + "\n")
    
    # Parse URI
    print(f"🔍 Testing connection to: {URI}")
    parsed = urlparse(URI)
    print(f"   Scheme: {parsed.scheme}")
    print(f"   Hostname: {parsed.hostname}")
    print(f"   Port: {parsed.port}\n")
    
    # Test basic DNS resolution
    print("Step 1: Testing DNS resolution...")
    try:
        import socket
        hostname = parsed.hostname
        ip = socket.gethostbyname(hostname)
        print(f"   ✓ DNS resolved {hostname} to {ip}\n")
    except socket.gaierror as e:
        print(f"   ✗ DNS resolution failed: {e}")
        print(f"   → Check internet connection or hostname spelling\n")
        return False
    except Exception as e:
        print(f"   ⚠ DNS check failed: {e}\n")
    
    # Test Neo4j driver connection
    print("Step 2: Testing Neo4j driver connection...")
    try:
        driver = GraphDatabase.driver(
            URI,
            auth=(USERNAME, PASSWORD),
            connection_timeout=10
        )
        print(f"   ✓ Driver created successfully\n")
        
        # Try to verify connectivity
        print("Step 3: Verifying connectivity with test query...")
        try:
            with driver.session() as session:
                result = session.run("RETURN 'Neo4j is alive' AS message")
                message = result.single()["message"]
                print(f"   ✓ Query successful: {message}\n")
        except Exception as query_error:
            print(f"   ✗ Query failed: {query_error}\n")
            raise query_error
        finally:
            driver.close()
        print("="*60)
        print("✅ NEO4J CONNECTION SUCCESSFUL!")
        print("="*60 + "\n")
        return True
        
    except Exception as e:
        print(f"   ✗ Connection failed: {e}\n")
        print("="*60)
        print("❌ NEO4J CONNECTION FAILED")
        print("="*60)
        print("\n⚠️  ERROR: Unable to retrieve routing information")
        print("\nThis typically means:")
        print("  ✗ Neo4j database instance is STOPPED or DELETED")
        print("  ✗ Database instance doesn't exist at this URI")
        print("  ✗ Invalid or expired credentials")
        print("  ✗ Database hasn't been started yet")
        print("\nTo fix:")
        print("  1. Go to https://console.neo4j.io/")
        print("  2. Check if instance 'e023f02b' is running")
        print("  3. If stopped, start it")
        print("  4. If deleted, create a new instance")
        print("  5. Update credentials in the code")
        print("  6. Re-run this diagnostic\n")
        return False


if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)
