import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import threading

# Global variable to track if packet capture is running
capture_running = False

# Create a function to update the GUI table with packet details
def update_table(packet):
    if capture_running:
        packet_type = packet.name
        source_ip = packet[IP].src if IP in packet else None
        destination_ip = packet[IP].dst if IP in packet else None
        source_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None
        destination_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
        packet_length = len(packet)
        timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')

        # Insert a new row with packet details
        tree.insert("", "end", values=(packet_type, source_ip, destination_ip, source_port, destination_port, packet_length, timestamp))

# Create a function to start packet capture in a separate thread
def start_packet_capture():
    global capture_running
    capture_running = True

    # Disable the "Start Capture" button and enable the "Stop Capture" button
    start_capture_button.config(state="disabled")
    stop_capture_button.config(state="normal")

    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.daemon = True  # Daemonize the thread to stop it when the GUI closes
    capture_thread.start()

# Create a function to stop packet capture
def stop_packet_capture():
    global capture_running
    capture_running = False

    # Enable the "Start Capture" button and disable the "Stop Capture" button
    start_capture_button.config(state="normal")
    stop_capture_button.config(state="disabled")

    # Allow some time for existing packets to be processed, then forcefully stop packet capture
    threading.Timer(2.0, force_stop_capture).start()

# Create a function to forcefully stop packet capture
def force_stop_capture():
    sniff_process.stop()  # This will forcefully stop packet capture
    print("Sniffing stopped.")

# Create a function for packet capture
def capture_packets():
    global sniff_process
    try:
        # Start sniffing the network and store the process
        sniff_process = sniff(prn=update_table, filter="ip or tcp or udp or icmp or arp", store=0)
    except Exception as e:
        print(f"An error occurred: {e}")

# Create the main GUI window
root = tk.Tk()
root.title("NetSpy Packet Analyzer")

# Create a frame to hold the buttons
button_frame = tk.Frame(root)
button_frame.pack(side="bottom")

# Create a table to display packet details
columns = ("Packet Type", "Source IP", "Destination IP", "Source Port", "Destination Port", "Packet Length", "Timestamp")
tree = ttk.Treeview(root, columns=columns, show="headings")

# Create a vertical scrollbar for the table
vsb = ttk.Scrollbar(root, orient="vertical", command=tree.yview)
vsb.pack(side="right", fill="y")
tree.configure(yscrollcommand=vsb.set)

# Define column headings
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=100)  # Adjust column width as needed

# Pack the table
tree.pack()

# Create a button to start packet capture
start_capture_button = tk.Button(button_frame, text="Start Capture", command=start_packet_capture)
start_capture_button.pack(side="left")

# Create a button to stop packet capture
stop_capture_button = tk.Button(button_frame, text="Stop Capture", command=stop_packet_capture, state="disabled")
stop_capture_button.pack(side="left")

# Start the GUI main loop
root.mainloop()
