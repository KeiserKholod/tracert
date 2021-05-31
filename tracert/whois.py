import socket


class WhoisTrace:
    def create_sock_whois(self, data):
        refer_ind = data.index('refer')
        first_data = data[refer_ind:].split('\n')[0].replace(' ', '').split(':')
        server_name = first_data[1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return sock, server_name

    def create_sock(self):
        timeout = 1
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        return sock

    def get_data(self, sock):
        data = b''
        current_part = sock.recv(1024)
        while current_part != b'':
            data += current_part
            current_part = sock.recv(1024)
        return data.decode().lower()

    def get_whois_data(self, address):
        sock = self.create_sock()
        whois_server_name = 'whois.iana.org'
        sock.connect((socket.gethostbyname(whois_server_name), 43))
        sock.send((address + '\r\n').encode('utf-8'))
        result = {}
        try:
            first_data = sock.recv(1024).decode()
            if 'refer' in first_data:
                whois_sock, server_name = self.create_sock_whois(first_data)
                whois_sock.connect((server_name, 43))
                whois_sock.send((address + '\r\n').encode('utf-8'))
                data = self.get_data(whois_sock)
                return self.parse_result(data, result)
        except socket.timeout:
            pass
        finally:
            sock.close()
            return result

    def parse_result(self, data, result):
        for el in ['country', 'origin', 'originas']:
            if el in data:
                ind = data.index(el)
                record = data[ind:].split('\n')[0]
                record = record.replace(' ', '').split(':')
                result[record[0]] = record[1]
        return result
