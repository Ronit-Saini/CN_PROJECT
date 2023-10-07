# packetSniffer.py
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import threading
import scapy.all as scapy
from sniffer import PacketSniffer

class PacketSnifferPage:
    def __init__(self, parent_frame, interfaces,packet_index,packet_buffer,update_interval,root,display_packet,update_overview):

        self.packet_index = packet_index
        self.packet_buffer = packet_buffer
        self.update_interval = update_interval
        self.root = root
        self.display_packet = display_packet
        self.update_overview = update_overview

        self.parent_frame = parent_frame
        self.packet_sniffer_frame = tk.Frame(parent_frame, bg="#1f1d1d")

        self.button_frame = tk.Frame(self.packet_sniffer_frame, bg="#423c3c")
        self.button_frame.pack(side=tk.TOP, fill=tk.X)

        self.interface_label = tk.Label(self.button_frame, text="Interface:", bg="#423c3c", fg="white")
        self.interface_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.interface_var = tk.StringVar()
        self.interface_combobox = ttk.Combobox(self.button_frame, textvariable=self.interface_var, values=interfaces)
        self.interface_combobox.pack(side=tk.LEFT, padx=5, pady=5)
        self.interface_combobox.set("")

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

        self.start_button = tk.Button(self.button_frame, text="Start Sniffing", command=self.start_sniffing, bg="#1f1d1d", fg="white")
        self.start_button.pack(side=tk.LEFT, padx=10, pady=5)

        self.stop_button = tk.Button(self.button_frame, text="Stop Sniffing", command=self.stop_sniffing, bg="#1f1d1d", fg="white")
        self.stop_button['state'] = tk.DISABLED
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.save_button = tk.Button(self.button_frame, text="Save to PCAP", command=self.save_to_pcap, bg="#1f1d1d", fg="white")
        self.save_button['state'] = tk.DISABLED
        self.save_button.pack(side=tk.LEFT, padx=10, pady=5)

        self.clear_button = tk.Button(self.button_frame, text="Clear Display", command=self.clear_display, bg="#1f1d1d", fg="white")
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

    def update_packet_table(self):
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
        
        self.update_overview(packet_index=self.packet_index)
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

    def run_sniffer(self, interface, pcap_file, host):
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
