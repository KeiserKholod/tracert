import socket


class WhoisData:
    def __init__(self, address, whois_data):
        self.address = address
        self.name = ''
        try:
            self.name = socket.gethostbyaddr(address)[0]
        except socket.herror:
            pass
        self.country = ''
        self.auto_sys = ''
        if 'country' in whois_data and 'EU' not in whois_data["country"]:
            self.country = whois_data["country"]
        if 'origin' in whois_data:
            self.auto_sys = whois_data['origin']
        if 'originas' in whois_data:
            self.auto_sys = whois_data['originas']

    def __str__(self):
        result = f'{self.address}\n'
        if self.name and not self.auto_sys and not self.country:
            result += f'local\n'
        elif self.name:
            result += f'{self.name}, '
        if self.auto_sys and not self.country:
            result += f'{self.auto_sys}\n'
        elif self.auto_sys:
            result += f'{self.auto_sys}, '
        if self.country:
            result += f'{self.country}\n'
        return result
