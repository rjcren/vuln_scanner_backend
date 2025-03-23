# import logging
import os
import time
from zapv2 import ZAPv2

# logger = logging.getLogger(__name__)

class ZAP:
    api_base_url = os.getenv("ZAP_API_URL", "https://127.0.0.1:3443")
    _api_key = os.getenv("ZAP_API_KEY")
    auth_headers = {
        "X-Auth": _api_key,
        "content-type": "application/json"
    }
    zap = ZAPv2(apikey=_api_key, proxies={'http': api_base_url, 'https': api_base_url})

    @staticmethod
    def start_scan(target):
        scanID = ZAP.zap.ascan.scan(target)
        while int(ZAP.zap.ascan.status(scanID)) < 100:
            # Loop until the scanner has finished
            print('Scan progress %: {}'.format(ZAP.zap.ascan.status(scanID)))
            time.sleep(5)

        print('Active Scan completed')
        # Print vulnerabilities found by the scanning
        print('Hosts: {}'.format(', '.join(ZAP.zap.core.hosts)))
        print('Alerts: ')
        print(ZAP.zap.core.alerts(baseurl=target))

if __name__ == "__main__":
    ZAP.start_scan("http://192.168.125.134:801")