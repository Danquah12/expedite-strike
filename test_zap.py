from zapv2 import ZAPv2

zap = ZAPv2(
    apikey='abcd1234',
    proxies={
        'http': 'http://127.0.0.1:8090',
        'https': 'http://127.0.0.1:8090'
    }
)

print("ZAP version:", zap.core.version)
