import socket
import time
import threading
from scapy.all import sniff, IP, TCP, UDP
from PyQt6.QtCore import pyqtSignal, QObject


def get_hostname(ip):
    #resolve hostname from ip address
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


def identify_port(packet):
    #Identify well-known ports like HTTP, HTTPS, DNS, etc.
    if TCP in packet:
        port = packet[TCP].dport
    elif UDP in packet:
        port = packet[UDP].dport
    else:
        return "N/A"

    common_ports = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 25: "SMTP"}
    return common_ports.get(port, str(port))


class PacketSniffer(QObject):
    packet_received = pyqtSignal(str, str, str, str, str, str, str, str)  #Signal to send packet data to GUI

    def __init__(self):
        super().__init__()
        self.stop_event = threading.Event()  #Event for stopping the sniffer
        self.sniffing_thread = None  #Track the sniffing thread

    def start_sniffing(self):
        """Starts sniffing in a background thread."""
        if self.sniffing_thread and self.sniffing_thread.is_alive():
            return  # Prevent multiple threads

        self.stop_event.clear()  # Reset stop event
        self.sniffing_thread = threading.Thread(target=self.run_sniffer, daemon=True)
        self.sniffing_thread.start()

    def stop_sniffing(self):
        """Stops the sniffing process."""
        self.stop_event.set()  # Signal to stop sniffing

    def run_sniffer(self):
        """Runs the sniffer loop and stops when stop_event is set."""
        sniff(filter="ip", prn=self.process_packet, store=False, stop_filter=lambda p: self.stop_event.is_set())

    def process_packet(self, packet):
        """Processes each captured packet and sends it to the GUI."""
        if self.stop_event.is_set():
            return

        if IP in packet:
            timestamp = time.strftime("%H:%M:%S", time.localtime(packet.time))
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_host = get_hostname(src_ip)
            dst_host = get_hostname(dst_ip)
            port_info = identify_port(packet)
            proto_type = packet.sprintf("%IP.proto%")
            pkt_type = "TCP" if "TCP" in proto_type else "UDP" if "UDP" in proto_type else "OTHER"

            self.packet_received.emit(timestamp, src_ip, src_host, dst_ip, dst_host, pkt_type, proto_type, port_info)
