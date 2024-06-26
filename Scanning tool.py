import nmap

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def scan_network(self):
        print(f"Starting scan on {self.target}...")
        self.scanner.scan(self.target, '1-1024')
        if not self.scanner.all_hosts():
            print("No hosts found. Please check the target IP address and network connectivity.")
            return
        for host in self.scanner.all_hosts():
            print(f'Host: {host} ({self.scanner[host].hostname()})')
            print(f'State: {self.scanner[host].state()}')
            for proto in self.scanner[host].all_protocols():
                print(f'Protocol: {proto}')
                lport = self.scanner[host][proto].keys()
                for port in lport:
                    print(f'Port: {port}\tState: {self.scanner[host][proto][port]["state"]}')

if __name__ == "__main__":
    target = '192.168.56.1'
    scanner = VulnerabilityScanner(target)
    scanner.scan_network()

