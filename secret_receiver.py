from scapy.all import IP, UDP, sniff


CHECKSUM = 12345
END_CHECKSUM = 45678


def filter_packet(packet):
    """Function to filter UDP packets based on the checksum"""
    return UDP in packet and (
        packet[UDP].chksum == CHECKSUM or packet[UDP].chksum == END_CHECKSUM
    )


def process_message(packet, store: list):
    """Function to process secret message packets"""
    store.append(chr(packet[UDP].dport))

    # Print it out and clear the store once we receive the full message
    if packet[UDP].chksum == END_CHECKSUM:
        print("".join(store))
        store.clear()


def main():
    message_store = []
    sniff(lfilter=filter_packet, prn=lambda x: process_message(x, message_store))


if __name__ == "__main__":
    main()
