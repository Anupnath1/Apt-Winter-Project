import os

# Hard-disable proxies (keep this)
os.environ["NO_PROXY"] = "*"
os.environ["no_proxy"] = "*"
os.environ.pop("HTTP_PROXY", None)
os.environ.pop("HTTPS_PROXY", None)
os.environ.pop("http_proxy", None)
os.environ.pop("https_proxy", None)

from zapv2 import ZAPv2

# ✅ Fix: Use proxies parameter explicitly
zap = ZAPv2(
    apikey="pd6lnksuimrd3bd840bisjesn7",
    proxies={
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
)

print(zap.core.version)
