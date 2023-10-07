import tkinter as tk
from tkinter import ttk
from collections import Counter
import time
import scapy.all as scapy

class OverviewPage:
    def __init__(self, parent_frame, packet_buffer):
        self.parent_frame = parent_frame
        self.overview_frame = tk.Frame(parent_frame)

        self.grid_frame = ttk.Frame(self.overview_frame)
        self.grid_frame.pack(side=tk.LEFT, padx=10, pady=10)

        self.packet_buffer = packet_buffer
        self.packet_start_time = None
        self.protocol_counter = Counter()
        self.source_ip_counter = Counter()
        self.destination_ip_counter = Counter()
        self.packet_size_distribution = Counter()

        # Create grid labels with borders
        self.create_grid_label(self.grid_frame, "Packet Count:")
        self.create_grid_label(self.grid_frame, "Capture Duration:")
        self.create_grid_label(self.grid_frame, "Protocol Distribution:")
        self.create_grid_label(self.grid_frame, "Top Source IP Addresses:")
        self.create_grid_label(self.grid_frame, "Top Destination IP Addresses:")
        self.create_grid_label(self.grid_frame, "Packet Size Distribution (Bytes):")

        # Add labels to display statistics
        self.packet_count_label = ttk.Label(self.grid_frame, text="0", relief="solid")
        self.packet_count_label.grid(row=0, column=1, padx=10, pady=5)

        self.capture_duration_label = ttk.Label(self.grid_frame, text="0 seconds", relief="solid")
        self.capture_duration_label.grid(row=1, column=1, padx=10, pady=5)

        self.protocol_distribution_label = ttk.Label(self.grid_frame, text="", relief="solid", wraplength=250)
        self.protocol_distribution_label.grid(row=2, column=1, padx=10, pady=5)

        self.source_ip_label = ttk.Label(self.grid_frame, text="", relief="solid", wraplength=250)
        self.source_ip_label.grid(row=3, column=1, padx=10, pady=5)

        self.destination_ip_label = ttk.Label(self.grid_frame, text="", relief="solid", wraplength=250)
        self.destination_ip_label.grid(row=4, column=1, padx=10, pady=5)

        self.packet_size_distribution_label = ttk.Label(self.grid_frame, text="", relief="solid", wraplength=250)
        self.packet_size_distribution_label.grid(row=5, column=1, padx=10, pady=5)

    def create_grid_label(self, parent, text):
        label = ttk.Label(parent, text=text, relief="solid", font=("Arial", 12, "bold"))
        label.grid(sticky="w", padx=10, pady=5)

    def update_overview(self,packet_index):
        
        self.packet_count_label.config(text=f"Packet Count: {packet_index - 1}")

        # Update capture duration
        if self.packet_start_time is None:
            self.packet_start_time = time.time()
        capture_duration = time.time() - self.packet_start_time
        self.capture_duration_label.config(text=f"Capture Duration: {int(capture_duration)} seconds")

        # Update protocol distribution
        self.protocol_counter.update([packet_info["type"] for packet_info in self.packet_buffer])
        protocol_distribution = "\n".join([f"- {protocol}: {percentage:.2f}%" for protocol, percentage in self.calculate_percentages(self.protocol_counter).items()])
        self.protocol_distribution_label.config(text=f"Protocol Distribution:\n{protocol_distribution}")

        # Update source IP addresses
        self.source_ip_counter.update([packet_info["src_ip"] for packet_info in self.packet_buffer])
        top_source_ips = self.get_top_items(self.source_ip_counter, 3)
        source_ip_text = "\n".join([f"{ip}: {count} packets" for ip, count in top_source_ips])
        self.source_ip_label.config(text=f"Top Source IP Addresses:\n{source_ip_text}")

        # Update destination IP addresses
        self.destination_ip_counter.update([packet_info["dst_ip"] for packet_info in self.packet_buffer])
        top_destination_ips = self.get_top_items(self.destination_ip_counter, 3)
        destination_ip_text = "\n".join([f"{ip}: {count} packets" for ip, count in top_destination_ips])
        self.destination_ip_label.config(text=f"Top Destination IP Addresses:\n{destination_ip_text}")

        # Update packet size distribution
        self.update_packet_size_distribution()
        packet_size_distribution = "\n".join([f"[{size_range[0]}-{size_range[1]}]: {percentage:.2f}%" for size_range, percentage in self.calculate_percentages(self.packet_size_distribution).items()])
        self.packet_size_distribution_label.config(text=f"Packet Size Distribution (Bytes):\n{packet_size_distribution}")

    def update_packet_size_distribution(self):
        packet_sizes = [len(packet_info["info"]) for packet_info in self.packet_buffer]
        size_ranges = [(0, 100), (101, 500), (501, 1000), (1001, float("inf"))]

        for size in packet_sizes:
            for size_range in size_ranges:
                if size_range[0] <= size <= size_range[1]:
                    self.packet_size_distribution[size_range] += 1
                    break

    def calculate_percentages(self, counter):
        total_count = sum(counter.values())
        return {key: (value / total_count) * 100 for key, value in counter.items()}

    def get_top_items(self, counter, n):
        return counter.most_common(n)
