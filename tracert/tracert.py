import socket
from icmp import IcmpPacket
from whois import WhoisTrace
from whois_data import WhoisData


class Tracert:
    def __init__(self, host, max_ttl):
        self._host = socket.gethostbyname(host)
        self._max_ttl = max_ttl
        self.port = 80

    def create_socks(self, ttl):
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_sock.settimeout(4)
        return send_sock, recv_sock

    def do_trace(self):
        ttl = 1
        while ttl <= self._max_ttl:
            send_sock, recv_sock = self.create_socks(ttl)
            icmp_pack = IcmpPacket(8, 0)
            send_sock.sendto(bytes(icmp_pack), (self._host, self.port))
            try:
                data, address = recv_sock.recvfrom(1024)
            except socket.timeout:
                yield '*\n'
                ttl += 1
                continue
            whois_data = WhoisTrace().get_whois_data(address[0])
            yield WhoisData(address[0], whois_data)
            recv_icmp = IcmpPacket.from_bytes(data[20:])
            if recv_icmp.type == recv_icmp.code == 0:
                send_sock.close()
                recv_sock.close()
                break
            ttl += 1
            send_sock.close()
            recv_sock.close()
