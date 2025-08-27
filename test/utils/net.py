import socket


def send_udp_packet(dst, port):
    print(f"Sending UDP packet to {dst}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b"", (dst, port))
        print(f"Sent UDP packet to {dst}:{port}")
    finally:
        sock.close()


def send_udp_packet_from_ip(dst, port, src_ip):
    print(f"Sending UDP packet from {src_ip} to {dst}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((src_ip, 0))
        sock.sendto(b"", (dst, port))
        print(f"Sent UDP packet from {src_ip} to {dst}:{port}")
    finally:
        sock.close()


def port_closed(dst, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((dst, port))
        return False
    except ConnectionRefusedError:
        return True
    finally:
        sock.close()


def port_filtered(dst, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((dst, port))
        return False
    except TimeoutError:
        return True
    except ConnectionRefusedError:
        return False
    finally:
        sock.close()
