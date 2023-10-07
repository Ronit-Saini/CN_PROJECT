import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
from sniffer import PacketSniffer
import threading
import scapy.all as scapy
import time
from collections import Counter


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer GUI")
        self.root.geometry("1200x600")
        self.root['background'] = "#1f1d1d"

        self.packet_index = 1
        self.packet_buffer = []
        self.update_interval = 2
        self.packet_start_time = None
        self.protocol_counter = Counter()
        self.source_ip_counter = Counter()
        self.destination_ip_counter = Counter()
        self.packet_size_distribution = Counter()
        self.interfaces = scapy.get_working_ifaces()
        self.update_lock = threading.Lock()

        self.setup_ui()
        self.sniffer_thread = None       

    def setup_ui(self):
        self.sidebar_frame = tk.Frame(self.root, bg="#1f1d1d", width=200)
        self.sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.pages = ["Packet Sniffer","Overview","Packet Injection","Help","About"]
        self.current_page = tk.StringVar(value=self.pages[0])

        self.page_buttons = []
        for page in self.pages:
            button = tk.Radiobutton(
                self.sidebar_frame,
                text=page,
                variable=self.current_page,
                value=page,
                bg="#1f1d1d",
                fg="white",
                indicatoron=0,
                selectcolor="#363535",
                command=self.switch_page
            )
            button.pack(fill=tk.X, padx=10, pady=5)
            self.page_buttons.append(button)

        self.content_frame = tk.Frame(self.root)
        self.content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.setup_packet_sniffer_page()
        self.setup_overview_page()
        self.show_packetSniffer()

        self.root.after(self.update_interval * 1000, self.update_packet_table)

    def setup_overview_page(self):
        self.overview_frame = tk.Frame(self.content_frame)

        self.grid_frame = ttk.Frame(self.overview_frame)
        self.grid_frame.pack(side=tk.LEFT, padx=10, pady=10)

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

    def setup_packet_sniffer_page(self):
        self.packet_sniffer_frame = tk.Frame(self.content_frame, bg="#1f1d1d")

        self.button_frame = tk.Frame(self.packet_sniffer_frame, bg="#423c3c")
        self.button_frame.pack(side=tk.TOP, fill=tk.X)

        self.interface_label = tk.Label(self.button_frame, text="Interface:", bg="#423c3c", fg="white")
        self.interface_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.interface_var = tk.StringVar()
        self.interface_combobox = ttk.Combobox(self.button_frame, textvariable=self.interface_var, values=self.interfaces)
        self.interface_combobox.pack(side=tk.LEFT, padx=5, pady=5)
        self.interface_combobox.set("")
        # self.interface_var = tk.StringVar()
        # self.interface_entry = tk.Entry(self.button_frame, textvariable=self.interface_var)
        # self.interface_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.host_label = tk.Label(self.button_frame, text="Host:", bg="#423c3c", fg="white")
        self.host_label.pack(side=tk.LEFT, padx=10, pady=5)

        self.host_var = tk.StringVar()
        self.host_entry = tk.Entry(self.button_frame, textvariable=self.host_var)
        self.host_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.pcap_label = tk.Label(self.button_frame, text="PCAP File:", bg="#423c3c", fg="white")
        self.pcap_label.pack(side=tk.LEFT, padx=10, pady=5)

        self.pcap_var = tk.StringVar()
        self.pcap_entry = tk.Entry(self.button_frame, textvariable=self.pcap_var)
        self.pcap_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.start_button = tk.Button(self.button_frame, text="Start Sniffing", command=self.start_sniffing,bg="#1f1d1d",
                fg="white")
        self.start_button.pack(side=tk.LEFT, padx=10, pady=5)

        self.stop_button = tk.Button(self.button_frame, text="Stop Sniffing", command=self.stop_sniffing,bg="#1f1d1d",
                fg="white")
        self.stop_button['state'] = tk.DISABLED
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.save_button = tk.Button(self.button_frame, text="Save to PCAP", command=self.save_to_pcap,bg="#1f1d1d",
                fg="white")
        self.save_button['state'] = tk.DISABLED
        self.save_button.pack(side=tk.LEFT, padx=10, pady=5)

        self.clear_button = tk.Button(self.button_frame, text="Clear Display", command=self.clear_display,bg="#1f1d1d",
                fg="white")
        self.clear_button['state'] = tk.DISABLED
        self.clear_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.packet_table_frame = tk.Frame(self.packet_sniffer_frame)
        self.packet_table_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.packet_table = ttk.Treeview(
            self.packet_table_frame, columns=("Packet Number", "Time", "Source IP", "Destination IP", "Protocol", "Length", "Info"),
            show="headings"
        )

        self.packet_table.heading("Packet Number", text="Packet Number")
        self.packet_table.heading("Time", text="Time")
        self.packet_table.heading("Source IP", text="Source IP")
        self.packet_table.heading("Destination IP", text="Destination IP")
        self.packet_table.heading("Protocol", text="Protocol")
        self.packet_table.heading("Length", text="Length")
        self.packet_table.heading("Info", text="Info")

        self.packet_table.column("Packet Number", width=100)
        self.packet_table.column("Time", width=150)
        self.packet_table.column("Source IP", width=150)
        self.packet_table.column("Destination IP", width=150)
        self.packet_table.column("Protocol", width=100)
        self.packet_table.column("Length", width=100)
        self.packet_table.column("Info", width=150)

        self.packet_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.table_scrollbar_y = ttk.Scrollbar(self.packet_table_frame, orient=tk.VERTICAL, command=self.packet_table.yview)
        self.packet_table.configure(yscrollcommand=self.table_scrollbar_y.set)
        self.table_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

    def display_packet(self, packet_info):
        with self.update_lock:
            self.update_overview()
            self.packet_buffer.append(packet_info)

    def update_packet_table(self):
        with self.update_lock:
            for packet_info in self.packet_buffer:
                color = packet_info["color"]
                self.packet_table.insert("", "end", values=(
                    self.packet_index,
                    packet_info["time"],
                    packet_info["src_ip"],
                    packet_info["dst_ip"],
                    packet_info["type"],
                    packet_info["length"],
                    packet_info["info"]
                ), tags=(color,))
                self.packet_index += 1
                self.packet_table.tag_configure(color, background=color, foreground="white")
            self.packet_buffer.clear()

        self.root.after(self.update_interval * 1000, self.update_packet_table)

    def start_sniffing(self):
        self.clear_button['state'] = tk.NORMAL
        self.stop_button['state'] = tk.NORMAL
        interface = self.interface_var.get()
        pcap_file = self.pcap_var.get()
        host = self.host_var.get()

        self.sniffer_thread = threading.Thread(target=self.run_sniffer, args=(interface, pcap_file, host))
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

    def run_sniffer(self, interface, pcap_file,host):
        self.sniffer = PacketSniffer(interface=interface, pcap_file=pcap_file, host=host, packet_handler=self.display_packet)
        self.sniffer.start_sniffing()

    def stop_sniffing(self):
        if self.sniffer_thread is not None:
            self.save_button['state'] = tk.NORMAL
            self.sniffer.stop_sniffing()
            self.sniffer_thread.join()

    def save_to_pcap(self):
        pcap_file = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if pcap_file and hasattr(self, 'sniffer'):
            self.pcap_var.set(pcap_file)
            self.sniffer.save_to_pcap(pcap_file=pcap_file)
            messagebox.showinfo("Success", "Packets saved to PCAP file!")
        else:
            messagebox.showerror("Error", "No packets to save!")

    def clear_display(self):
        self.packet_table.delete(*self.packet_table.get_children())
        self.packet_index = 1

    def update_overview(self):
        # Update packet count
        self.packet_count_label.config(text=f"Packet Count: {self.packet_index - 1}")

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

    def switch_page(self):
        selected_page = self.current_page.get()
        if selected_page == "Packet Sniffer":
            self.show_packetSniffer()
        elif selected_page == "Overview":
            self.show_overview()
        elif selected_page == "Packet Injection":
            self.show_packetInjection()
        elif selected_page == "Help":
            self.show_help()
        elif selected_page == "About":
            self.show_about()

    def show_packetSniffer(self):
        self.hide_all_frames()
        self.packet_sniffer_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    def show_overview(self):
        self.hide_all_frames()
        self.overview_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def show_packetInjection(self):
        self.hide_all_frames()
    
    def show_help(self):
        self.hide_all_frames()
    
    def show_about(self):
        self.hide_all_frames()
    
    def hide_all_frames(self):
        self.packet_sniffer_frame.pack_forget()
        self.overview_frame.pack_forget()

    

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
