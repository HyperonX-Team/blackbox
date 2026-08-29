"""Hello BLACKBOX: proof that runtime, environment and permissions all work."""

import os
import platform
import sys

print("Hello from inside a BLACKBOX!")
print(f"  name:       {os.environ.get('BLACKBOX_NAME', 'hello')}")
print(f"  python:     {sys.version.split()[0]} ({platform.machine()})")
print(f"  executable: {sys.executable}")
print(f"  APP_MODE:   {os.environ.get('APP_MODE', 'unset')}")
print(f"  work dir:   {os.environ.get('BLACKBOX_WORK', os.getcwd())}")

out = os.environ.get("BLACKBOX_OUTPUT")
if out:
    path = os.path.join(out, "hello.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("written from inside a BLACKBOX\n")
    print(f"  wrote:      {path}")
