import time
import re
import subprocess
from prometheus_client.core import GaugeMetricFamily, REGISTRY, CounterMetricFamily
from prometheus_client import start_http_server

publickeys = []
result = subprocess.check_output(['wg','show','all','dump'])
result = result.decode('utf-8')

class CustomCollector(object):
    def collect(self):

        for line in result.splitlines():
            match = re.split(r'\t+', line)
            if match[1] != 'YI5j39L0by1kSGflaFJ7oy5O3ZhaAlX6HOnQIkN9FH0=':
                interface = match[0]
                publickey = match[1]
                nodata = match[2]
                endpoint = match[3].split(':')
                clientip = endpoint[0]
                clientport = endpoint[1]
                allowed_ips = match[4].split(',')
                ipv4private = allowed_ips[0]
                ipv6private = allowed_ips[1]
                handshakets = int(match[5])
                receive = int(match[6])
                sent = int(match[7])
                publickeys.append(publickey)

                handshake = GaugeMetricFamily("wireguard_latest_handshake_seconds", 'Help text', labels=['publickey','clientport'])
                handshake.add_metric([publickey,clientport], handshakets)
                yield handshake
                wg_s_b_total = GaugeMetricFamily('wireguard_sent_bytes_total', 'my_labels', labels=['publickey','interface','ipv4private','clientip'])
                wg_s_b_total.add_metric([publickey,interface,ipv4private,clientip], sent)
                yield wg_s_b_total
                wg_s_b_total = GaugeMetricFamily('wireguard_receive_bytes_total', 'my_labels', labels=['publickey','interface','ipv4private','clientip'])
                wg_s_b_total.add_metric([publickey,interface,ipv4private,clientip], receive)
                yield wg_s_b_total
                
if __name__ == '__main__':
    start_http_server(8000)
    REGISTRY.register(CustomCollector())
    while True:
        time.sleep(1)
