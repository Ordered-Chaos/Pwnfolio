#!/usr/bin/env python3

import argparse
from scapy.all import *
import socket
import ipaddress

def calculate_checksum(packet):
    """Calculate checksum for a raw packet (two's complement sum of all 16-bit words)."""
    if len(packet) % 2 == 1:  # Ensure packet length is even
        packet += b'\x00'
    checksum = 0
    for i in range(0, len(packet), 2):
        word = (packet[i] << 8) + packet[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)  # Keep it 16-bit
    return ~checksum & 0xFFFF

def calculate_udp_checksum(ip_header, udp_header, udp_payload):
    """Calculate UDP checksum with the pseudo-header."""
    pseudo_header = (
        socket.inet_aton(ip_header.src) +  # Source IP
        socket.inet_aton(ip_header.dst) +  # Destination IP
        b'\x00' +                         # Zero padding
        bytes([socket.IPPROTO_UDP]) +     # Protocol
        len(udp_header).to_bytes(2,'big') + len(udp_payload).to_bytes(2, 'big')  # UDP packet length
    )
    checksum_packet = pseudo_header + bytes(udp_header) + bytes(udp_payload)
    return calculate_checksum(checksum_packet)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Send the first UDP packet in a PCAP file to a destination through a raw socket.")
    parser.add_argument(
        "--dst-ip",
        required=False,
        help="The destination IP address to send the packet to.",
    )
    parser.add_argument(
        "--dport",
        required=False,
        type=int,
        help="The destination port to send the packet to.",
    )
    parser.add_argument(
        "--src-ip",
        required=False,
        help="The source IP address to use in the packet.",
    )
    parser.add_argument(
        "--sport",
        required=False,
        help="The sending port to use in the packet.",
    )
    parser.add_argument(
        "pcap_file",
        help="Path to the PCAP file.",
    )
    args = parser.parse_args()

    try:
        # Read the PCAP file
        packets = rdpcap(args.pcap)
    except FileNotFoundError:
        print(f"Error: The file '{args.pcap}' was not found.")
        return
    except Scapy_Exception as e:
        print(f"Error: Could not read the pcap file. Details: {e}")
        return

    # Find the first UDP packet in the PCAP file
    udp_packet = None
    for packet in packets:
        if UDP in packet:
            udp_packet = packet
            break

    if udp_packet is None:
        print("No UDP packets found in the PCAP file.")
        return

    # Create a sample packet
    src_ip = args.src_ip if args.src_ip else udp_packet[IP].src
    dst_ip = args.dst_ip if args.dst_ip else udp_packet[IP].dst
    sport = args.sport if args.sport else udp_packet[UDP].sport
    dport = args.dst_port if args.dst_port else udp_packet[UDP].dport
    payload = udp_packet[UDP].payload

    # Validate ip addresses
    ips = [src_ip, dst_ip]
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"Error: '{ip}' is not valid!")
            return
    
    #   Build the Scapy packet
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=sport, dport=dport, len=8 + len(payload))  # UDP length = header (8 bytes) + payload
    udp_payload = raw(payload)

    # Clear existing checksum fields
    del ip.chksum
    del udp.chksum

    # Calculate IP checksum
    ip_raw = raw(ip)  # Serialize IP header
    ip.chksum = calculate_checksum(ip_raw)

    # Calculate UDP checksum
    udp.chksum = calculate_udp_checksum(ip, udp, payload)

    # Serialize the full packet
    raw_packet = raw(ip / udp / payload)

    # Send the packet over a raw socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw_sock:
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            raw_sock.sendto(raw_packet, (dst_ip, 0))  # Port is included in the payload
            print(f"Packet sent to {dst_ip}:{dst_port}")
    except PermissionError:
        print("Permission error: Raw socket requires root privileges. Try running the script with sudo.")
    except Exception as e:
        print(f"An error occurred while sending the packet: {e}")
