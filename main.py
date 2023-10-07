# main.py
import tkinter as tk
import threading
import scapy.all as scapy
from collections import Counter
from packetSniffer import PacketSnifferPage
from overview import OverviewPage

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer GUI")
        self.root.geometry("1200x600")
        self.root['background'] = "#1f1d1d"

        self.packet_index = 1
        self.packet_buffer = []
        self.update_interval = 2
        self.update_lock = threading.Lock()
        self.interfaces = scapy.get_working_ifaces()

        self.setup_ui()
        self.sniffer_thread = None       

    def setup_ui(self):
        self.sidebar_frame = tk.Frame(self.root, bg="#1f1d1d", width=200)
        self.sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.pages = ["Packet Sniffer", "Overview", "Packet Injection", "Help", "About"]
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

        self.overview_page = OverviewPage(self.content_frame,self.packet_buffer)
        self.packet_sniffer_page = PacketSnifferPage(self.content_frame, self.interfaces, 
                                                    self.packet_index, self.packet_buffer, 
                                                    self.update_interval, self.root,
                                                    self.display_packet , self.overview_page.update_overview)

        self.show_packetSniffer()

        self.root.after(self.update_interval * 1000, self.packet_sniffer_page.update_packet_table)

    def display_packet(self, packet_info):
        self.packet_buffer.append(packet_info)

    def switch_page(self):
        selected_page = self.current_page.get()
        if selected_page == "Packet Sniffer":
            self.show_packetSniffer()
        elif selected_page == "Overview":
            self.show_overview()
        elif selected_page == "Packet Injection":
            self.show_packet_injection()
        elif selected_page == "Help":
            self.show_help()
        elif selected_page == "About":
            self.show_about()
            
    def show_packetSniffer(self):
        self.hide_all_frames()
        self.packet_sniffer_page.packet_sniffer_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def show_overview(self):
        self.hide_all_frames()
        self.overview_page.overview_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def show_packet_injection(self):
        self.hide_all_frames()
        pass

    def show_help(self):
        self.hide_all_frames()
        pass

    def show_about(self):
        self.hide_all_frames()
        pass
    
    def hide_all_frames(self):
        self.packet_sniffer_page.packet_sniffer_frame.pack_forget()
        self.overview_page.overview_frame.pack_forget()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
