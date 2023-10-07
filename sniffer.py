import scapy.all as scapy
from scapy.utils import PcapWriter
from scapy.layers import http
import threading

class PacketSniffer:
    def __init__(self, interface=None, pcap_file=None, packet_handler=None, host=None):
        self.interface = interface if interface else scapy.get_working_if()
        self.pcap_file = pcap_file
        self.packet_handler = packet_handler
        self.stop_sniffing_flag = False
        self.sniff_thread = None
        self.packets = []
        self.pcap_writer = None
        self.host = host if host else scapy.get_if_addr(self.interface)

    def process_packet(self, packet):
        if self.stop_sniffing_flag:
            return
        self.packets.append(packet)
        packet_info = {}
        packet_info["time"] = packet.time
        packet_info["length"] = len(packet)
        if packet.haslayer(http.HTTPRequest) and packet.haslayer(scapy.Raw):
            http_request = ""
            try: 
                http_request = packet[scapy.Raw].load.decode()
            except:
                pass
            packet_info["type"] = "HTTPRequest"
            packet_info["src_ip"] = packet[scapy.IP].src
            packet_info["dst_ip"] = packet[scapy.IP].dst
            packet_info["http_method"] = packet[http.HTTPRequest].Method.decode()
            packet_info["host"] = packet[http.HTTPRequest].Host.decode()
            packet_info["path"] = packet[http.HTTPRequest].Path.decode()
            packet_info["color"]  = "blue"
            packet_info["info"] = http_request
            packet_info["summary"] = f"{packet_info['src_ip']} -> {packet_info['dst_ip']} {packet_info['http_method']} {packet_info['host']}{packet_info['path']}"
        elif packet.haslayer(http.HTTPResponse):
            http_response = ""
            try:
                http_response = packet[scapy.Raw].load.decode()
            except:
                pass
            packet_info["type"] = "HTTPResponse"
            packet_info["src_ip"] = packet[scapy.IP].src
            packet_info["dst_ip"] = packet[scapy.IP].dst
            packet_info["info"] = http_response
            packet_info["color"]  = "green"
            packet_info["http_status_code"] = packet[http.HTTPResponse].Status_Code.decode()
            packet_info["summary"] = f"{packet_info['src_ip']} -> {packet_info['dst_ip']} {packet_info['http_status_code']}"
        elif packet.haslayer(scapy.TCP):
            packet_info["type"] = "TCP"
            packet_info["src_ip"] = packet[scapy.IP].src
            packet_info["src_port"] = packet[scapy.TCP].sport
            packet_info["info"] = ""
            packet_info["dst_ip"] = packet[scapy.IP].dst
            packet_info["color"]  = "purple"
            packet_info["dst_port"] = packet[scapy.TCP].dport
            packet_info["summary"] = f"{packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']} {packet_info['type']}"
        elif packet.haslayer(scapy.UDP):
            packet_info["type"] = "UDP"
            packet_info["src_ip"] = packet[scapy.IP].src
            packet_info["src_port"] = packet[scapy.UDP].sport
            packet_info["info"] = ""
            packet_info["dst_ip"] = packet[scapy.IP].dst
            packet_info["color"]  = "orange"
            packet_info["dst_port"] = packet[scapy.UDP].dport
            packet_info["summary"] = f"{packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}  {packet_info['type']}"
        elif packet.haslayer(scapy.DNS):
            packet_info["type"] = "DNS"
            packet_info["src_ip"] = packet[scapy.IP].src
            packet_info["dst_ip"] = packet[scapy.IP].dst
            packet_info["info"] = ""
            packet_info["color"]  = "yellow"
            packet_info["query_names"] = [qname.qname.decode() for qname in packet[scapy.DNS].qd]
            packet_info["summary"] = f"{packet_info['src_ip']} -> {packet_info['dst_ip']} {packet_info['query_names']} {packet_info['type']}"
        elif packet.haslayer(scapy.ICMP):
            packet_info["type"] = "ICMP"
            packet_info["src_ip"] = packet[scapy.IP].src
            packet_info["dst_ip"] = packet[scapy.IP].dst
            packet_info["info"] = ""
            packet_info["color"]  = "brown"
            packet_info["summary"] = f"{packet_info['src_ip']} -> {packet_info['dst_ip']} {packet_info['type']}"
        else:
            packet_info["type"] = "Other"
            packet_info["info"] = ""
            packet_info["color"]  = "red"
            if(packet.haslayer(scapy.IP)):
                packet_info["src_ip"] = packet[scapy.IP].src
                packet_info["dst_ip"] = packet[scapy.IP].dst
                packet_info["summary"] = f"{packet_info['src_ip']} -> {packet_info['dst_ip']} {packet_info['type']}"
            else:
                packet_info["src_ip"] = "Unknown"
                packet_info["dst_ip"] = "Unknown"
                packet_info["summary"] = f"Other"
                
        
        # if packet_info["type"] != "Other":
        #     self.packets.append(packet_info)
        if self.packet_handler:
            self.packet_handler(packet_info)

    def start_sniffing(self):
        self.stop_sniffing_flag = False
        print(f"Sniffing on interface {self.interface}...")
        self.sniff_thread = threading.Thread(target=self._sniff_thread)
        self.sniff_thread.start()

    def _sniff_thread(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.process_packet, filter=f"host {self.host}",stop_filter=self._stop_filter)

    def _stop_filter(self, packets):
        return self.stop_sniffing_flag

    def stop_sniffing(self):
        self.stop_sniffing_flag = True
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join()

    def save_to_pcap(self,pcap_file):
        if pcap_file:
            self.pcap_writer = PcapWriter(pcap_file, append=True, sync=True);
            for packet in self.packets:
                self.pcap_writer.write(packet)
            self.pcap_writer.close()
            
if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.start_sniffing()
