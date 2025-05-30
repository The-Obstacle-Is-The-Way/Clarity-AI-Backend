#!/usr/bin/env python3
print("🏥 Clarity-AI Backend Health Check")
print("=" * 40)

import sys
print("🐍 Checking Python version...")
version = sys.version_info
if version.major == 3 and version.minor >= 10:
    print(f"   ✅ Python {version.major}.{version.minor}.{version.micro} (Compatible)")
else:
    print(f"   ❌ Python {version.major}.{version.minor}.{version.micro} (Requires 3.10+)")

print("📦 Checking dependencies...")
deps = ['fastapi', 'uvicorn', 'sqlalchemy', 'pydantic']
for dep in deps:
    try:
        __import__(dep)
        print(f"   ✅ {dep}")
    except ImportError:
        print(f"   ❌ {dep} (missing)")

print("🚀 Checking application import...")
try:
    from app.main import app
    print("   ✅ Main application imports successfully")
except Exception as e:
    print(f"   ❌ Failed to import app: {e}")

print("\n🎉 Basic health check complete!")
