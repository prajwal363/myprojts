import ctypes
import scapy.all as scapy
from scapy.arch import get_windows_if_list
import sys
import os
import logging
from scapy.layers import http
from scapy.all import IP, TCP, UDP
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import pickle
import threading
from collections import defaultdict
from queue import Queue
import ipaddress
import json

class NetworkInterface:
    @staticmethod
    def get_interfaces():
        """Get list of network interfaces with error handling"""
        interfaces = []
        try:
            # Try Windows-specific method first
            interfaces = get_windows_if_list()
            if interfaces:
                return interfaces
        except:
            pass
            
        try:
            # Fallback to generic method
            interfaces = scapy.get_if_list()
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            
        return interfaces

    @staticmethod
    def validate_interface(iface):
        """Validate if interface is usable"""
        try:
            # Try to start a test capture
            test = scapy.sniff(iface=iface, count=1, timeout=1)
            return True
        except Exception as e:
            print(f"Interface validation failed: {e}")
            return False

class SmartFirewall:
    def __init__(self):
        self.setup_logging()
        self.packet_queue = Queue()
        self.stats = defaultdict(int)
        self.is_running = False
        self.interface = None

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='smart_firewall.log'
        )

    def select_interface(self):
        interfaces = NetworkInterface.get_interfaces()
        
        if not interfaces:
            print("No network interfaces found!")
            print("\nTroubleshooting steps:")
            print("1. Make sure Npcap is installed properly")
            print("2. Run the script as administrator")
            print("3. Check if your network adapters are enabled")
            sys.exit(1)

        print("\nAvailable Network Interfaces:")
        for idx, iface in enumerate(interfaces):
            if isinstance(iface, dict):  # Windows format
                name = iface.get('name', 'Unknown')
                desc = iface.get('description', 'No description')
                print(f"{idx}: {name} - {desc}")
            else:  # Unix-like format
                print(f"{idx}: {iface}")

        while True:
            try:
                choice = int(input("\nSelect interface number: "))
                if 0 <= choice < len(interfaces):
                    selected = interfaces[choice]
                    self.interface = selected.get('name', selected) if isinstance(selected, dict) else selected
                    
                    # Validate interface
                    if NetworkInterface.validate_interface(self.interface):
                        print(f"\nSuccessfully selected interface: {self.interface}")
                        return
                    else:
                        print("Selected interface is not usable. Please choose another.")
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a number.")
            except Exception as e:
                print(f"Error: {e}")

    def start_capture(self):
        """Start packet capture with error handling"""
        if not self.interface:
            print("No interface selected!")
            return

        print(f"\nStarting capture on {self.interface}...")
        try:
            # Try to start capture
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False
            )
        except Exception as e:
            print(f"\nError starting capture: {e}")
            print("\nTroubleshooting steps:")
            print("1. Make sure Npcap is installed: https://npcap.com/#download")
            print("2. Run the script as administrator")
            print("3. Try selecting a different interface")
            print("4. Check if your antivirus is blocking packet capture")
            sys.exit(1)

    def packet_callback(self, packet):
        """Process captured packets"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            # Log packet info
            logging.info(f"Packet: {src_ip} -> {dst_ip} (Proto: {proto})")
            
            # Update stats
            self.stats['total_packets'] += 1
            
            # Basic packet analysis
            if TCP in packet:
                self.stats['tcp_packets'] += 1
                dst_port = packet[TCP].dport
                if dst_port in [80, 443]:  # Web traffic
                    self.stats['web_packets'] += 1
            elif UDP in packet:
                self.stats['udp_packets'] += 1

    def show_stats(self):
        """Display current statistics"""
        print("\nPacket Statistics:")
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"TCP Packets: {self.stats['tcp_packets']}")
        print(f"UDP Packets: {self.stats['udp_packets']}")
        print(f"Web Traffic Packets: {self.stats['web_packets']}")

def check_admin():
    """Check if script is running with admin privileges"""
    try:
        return os.getuid() == 0
    except AttributeError:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() == 1
        except:
            return False

def main():
    # Check for admin privileges
    if not check_admin():
        print("This script requires administrator privileges!")
        print("Please run as administrator.")
        sys.exit(1)

    firewall = SmartFirewall()
    
    while True:
        print("\nMenu:")
        print("1. Run the program")
        print("2. Select interface")
        print("3. Start packet capture")
        print("4. Exit")
        
        choice = input("\nEnter your choice: ")
        
        if choice == '1':
            print("Initializing Smart Firewall...")
        elif choice == '2':
            firewall.select_interface()
        elif choice == '3':
            if firewall.interface:
                print("\nStarting packet capture...")
                print("Press Ctrl+C to stop and show statistics")
                try:
                    firewall.start_capture()
                except KeyboardInterrupt:
                    print("\nStopping capture...")
                    firewall.show_stats()
            else:
                print("No interface selected! Please select an interface first.")
        elif choice == '4':
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()