import argparse
from scapy.all import IP, UDP, send


CHECKSUM = 12345
END_CHECKSUM = 45678


def is_valid_ip(ip: str) -> str:
    """Function to check if IP address is valid"""
    nums = ip.split(".")
    if len(nums) != 4:
        raise argparse.ArgumentTypeError("Invalid IP address")

    for num in nums:
        if not 0 <= int(num) <= 255:
            raise argparse.ArgumentTypeError("Invalid IP address")

    return ip


def send_secret(ip: str, secret: str):
    """Function to send secret UDP packets to the receiver"""
    # Send first n-1 packets
    for char in secret[:-1]:
        packet = IP(dst=ip) / UDP(dport=ord(char))
        packet[UDP].chksum = CHECKSUM
        send(packet, verbose=0)

    # Send last packet with special checksum
    packet = IP(dst=ip) / UDP(dport=ord(secret[-1]))
    packet[UDP].chksum = END_CHECKSUM
    send(packet, verbose=0)

    print(f"Secret sent to {ip}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "remote_ip", type=is_valid_ip, help="Remote IP address to send secret messages"
    )
    args = parser.parse_args()

    while True:
        secret = input("Enter the secret message to be sent ('q' to quit): ")
        if secret == "q":
            print("Program closed.")
            break

        send_secret(args.remote_ip, secret)


if __name__ == "__main__":
    main()
