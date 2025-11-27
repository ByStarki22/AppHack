
import logging
from typing import List, Dict
import socket
import platform
import subprocess

try:
    from scapy.all import sr1, IP, ICMP
except ImportError:
    sr1 = None  # ICMP not available if scapy is not installed

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]

class FastScanType:
    def __init__(self, target_ip: str, protocol: str = "TCP", ping_sweep: bool = False, common_ports: bool = True):
        self.target_ip = target_ip
        self.protocol = protocol.upper()
        self.ping_sweep = ping_sweep
        self.common_ports = common_ports
        logging.info(f"Initializing FastScanType with IP: {target_ip}, Protocol: {self.protocol}, Ping Sweep: {ping_sweep}, Common Ports: {common_ports}")

    @staticmethod
    def get_current_ip() -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            logging.debug(f"Detected local IP: {ip}")
        except Exception as e:
            ip = "127.0.0.1"
            logging.warning(f"Could not get local IP: {e}")
        finally:
            s.close()
        return ip

    def perform_scan(self) -> dict:
        logging.info(f"Starting scan for {self.target_ip} with protocol {self.protocol}")
        result = {"target": self.target_ip, "protocol": self.protocol, "scan": {}}
        try:
            if self.ping_sweep:
                base_ip = ".".join(self.target_ip.split(".")[:3])
                result["ping_sweep"] = self.ping_sweep_network(base_ip)
            ports = COMMON_PORTS if self.common_ports else list(range(1, 1025))
            if self.protocol == "TCP":
                result["scan"] = self.scan_tcp_ports(ports)
            elif self.protocol == "UDP":
                result["scan"] = self.scan_udp_ports(ports)
            elif self.protocol == "ICMP":
                result["scan"] = self.scan_icmp()
            else:
                logging.error(f"Unknown protocol: {self.protocol}")
                result["scan"] = "Unknown protocol"
        except Exception as e:
            logging.error(f"Error during scan: {e}")
            result["error"] = str(e)
        logging.info(f"Scan completed: {result}")
        return result

    def ping_sweep_network(self, base_ip: str) -> List[str]:
        active_hosts = []
        logging.info(f"Starting ping sweep on network {base_ip}.0/24")
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            if self.icmp_ping(ip) if sr1 else self.ping_host(ip):
                logging.debug(f"Active host detected: {ip}")
                active_hosts.append(ip)
        logging.info(f"Ping sweep completed. Active hosts: {active_hosts}")
        return active_hosts

    def scan_tcp_ports(self, ports: List[int]) -> Dict[int, str]:
        results = {}
        logging.info(f"Starting TCP scan on {self.target_ip} for ports: {ports}")
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                try:
                    result = sock.connect_ex((self.target_ip, port))
                    if result == 0:
                        results[port] = "open"
                        logging.debug(f"TCP port {port} open")
                    else:
                        results[port] = "closed"
                        logging.debug(f"TCP port {port} closed")
                except Exception as e:
                    results[port] = "error"
                    logging.error(f"Error scanning TCP port {port}: {e}")
        return results

    def scan_udp_ports(self, ports: List[int]) -> Dict[int, str]:
        results = {}
        logging.info(f"Starting UDP scan on {self.target_ip} for ports: {ports}")
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                try:
                    sock.sendto(b"", (self.target_ip, port))
                    sock.recvfrom(1024)
                    results[port] = "open"
                    logging.debug(f"UDP port {port} open")
                except socket.timeout:
                    results[port] = "open|filtered"
                    logging.debug(f"UDP port {port} open|filtered (timeout)")
                except Exception as e:
                    results[port] = "closed"
                    logging.debug(f"UDP port {port} closed: {e}")
        return results

    def scan_icmp(self) -> str:
        logging.info(f"Performing ICMP scan on {self.target_ip}")
        if sr1:
            result = "alive" if self.icmp_ping(self.target_ip) else "unreachable"
        else:
            result = "alive" if self.ping_host(self.target_ip) else "unreachable"
        logging.info(f"ICMP scan result: {result}")
        return result

    @staticmethod
    def ping_host(ip: str, timeout: int = 1) -> bool:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            logging.debug(f"Pinging {ip} using system ping")
            output = subprocess.check_output(
                ["ping", param, "1", "-w", str(timeout * 1000), ip],
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            )
            result = "TTL=" in output or "ttl=" in output
            logging.debug(f"Ping to {ip} {'successful' if result else 'failed'}")
            return result
        except Exception as e:
            logging.warning(f"Ping to {ip} failed: {e}")
            return False

    @staticmethod
    def icmp_ping(ip: str, timeout: int = 1) -> bool:
        if sr1 is None:
            logging.warning("scapy is not available for ICMP ping")
            return False
        pkt = IP(dst=ip)/ICMP()
        logging.debug(f"Sending ICMP ping to {ip}")
        reply = sr1(pkt, timeout=timeout, verbose=0)
        result = reply is not None
        logging.debug(f"ICMP ping to {ip} {'received reply' if result else 'no reply'}")
        return result