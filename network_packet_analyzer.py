import scapy.all as scapy

def packet_sniffing(interface):
    print(f"Sniffing packets on interface: {interface}")

    def process_packet(packet):
        if packet.haslayer(scapy.Ether) and packet.haslayer(scapy.IP):
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            packet_data = bytes(packet).hex()
            
            print("\n" + "-"*50)
            print(f"Source MAC: {src_mac}")
            print(f"Destination MAC: {dst_mac}")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            print(f"Packet Data: {packet_data}")

    try:
        scapy.sniff(iface=interface, prn=process_packet, store=False)
    except Exception as e:
        print(f"Error while sniffing packets: {e}")

def menu():
    print("\nNetwork Packet Sniffing Tool")
    print("1. Start Packet Sniffing")
    print("2. Exit")
    choice = int(input("Select an option (1-2): "))
    return choice

def main():
    while True:
        choice = menu()
        if choice == 1:
            interface = input("Enter the network interface to sniff packets on(eth0/wlan0): ")
            packet_sniffing(interface)
        elif choice == 2:
            print("Exiting the tool.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
