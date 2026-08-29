import urllib.request, time

v = int(time.time())
base = "https://hyperonx-team.github.io/blackbox"

i = urllib.request.urlopen(f"{base}/assets/favicon.ico?v={v}", timeout=30)
ico = i.read()
print("favicon.ico:", i.status, len(ico), "bytes | ICO magic:", ico[:4] == b"\x00\x00\x01\x00")

s = urllib.request.urlopen(f"{base}/assets/blackbox-logo.svg?v={v}", timeout=30)
svg = s.read()
print("logo.svg:   ", s.status, len(svg), "bytes | svg root:", b"<svg" in svg[:200])

h = urllib.request.urlopen(f"{base}/?v={v}", timeout=30).read().decode("utf-8", "replace")
print("homepage favicon link:", "assets/favicon.ico" in h)
print("homepage header logo :", "assets/blackbox-logo.svg" in h)
print("homepage hero image  :", "BLACKBOX logo" in h)
