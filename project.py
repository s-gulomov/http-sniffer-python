from pcapy import *
import sys
import os
import re
import warnings

warnings.filterwarnings("ignore",category=DeprecationWarning)

def get_mac_addr(pkt):
    """
    get source and destination mac address from ethernet layer
    """
    src_hex, dst_hex = ".".join(format(i) for i in pkt[:6]),".".join(format(i) for i in pkt[6:12])
    return src_hex, dst_hex


def ip_info(pkt):
    """
    get IPv and IP header length from ip layer
    :return: ip_version(int), ip_header_len(int)
    """
    ip_version, ip_header_len = list(map(int,list(format(pkt[14],'x'))))
    return ip_version, ip_header_len*4

def get_ip_addr(pkt):
    """
    get source and destination IP address
    :return: src_addr(str), dst_addr(str)
    """
    src_addr = ".".join(format(i) for i in pkt[26:26+4])
    dst_addr = ".".join(format(i) for i in pkt[26+4:26+8])
    return src_addr, dst_addr

def get_port_num(pkt, ip_header_len):
    """
    get source and destination TCP port number
    :param ip_header_len: length of the IP header
    :return:
    """
    src_port = str(int.from_bytes(pkt[14+ip_header_len: 14+ip_header_len+2], 'big'))
    dst_port = str(int.from_bytes(pkt[14+ip_header_len+2: 14+ip_header_len+2+2], 'big'))
    return src_port, dst_port


def get_tcp_header_len(pkt, ip_header_len):
    tcp_header_len = int(pkt[14+ip_header_len+12]/16) * 4
    return tcp_header_len

def get_tcp_psh_flag(pkt, ip_header_len):
    """
    get TCP PSH flag for filtering
    """
    psh_flag = int(pkt[14+ip_header_len+13] % 16) >= 8
    return psh_flag


def get_http_header(pkt,start_idx):
    """
    parse http header excluding entity body
    :param start_idx: start index of http in packet
    :return: http header in string
    """
    http_entity = "".join(chr(i) for i in pkt[start_idx:])
    return http_entity.split("\r\n\r\n")[0]


def sniff_http():
    """
    main driver of packet sniffing program
    """
    devices = findalldevs() # get list of available device
    for i, d in enumerate(devices):
        print(f"device ({i}) : {d}")

    target_device_idx = int(input("enter the device num: "))  # select target device which will be used in sniffing
    target_device = devices[target_device_idx]

    cap = open_live(target_device, 65536, 1, 0)  # initialize sniffing object with target device
    bpf = BPFProgram("tcp port http")  # set filter to tcp.port == 80
    pkt_idx = 1
    ### vars for saving video ###
    tgt_dst = ""
    video_in_byte = None
    start_saving = False
    normal_payload_len = 0
    segment_idx = 1
    content_length = 0

    while True:  # sniff packet in loop
        header, packet = cap.next()
        if not bpf.filter(packet):  # if the packet is not related with http, discard it
            continue

        src, dst = get_mac_addr(packet)  # get mac address (not required in this project)

        src_ip, dst_ip = get_ip_addr(packet)  # get source, destination ip
        ip_version,ip_header_len = ip_info(packet)  # get IP version and IP header length
        src_port, dst_port = get_port_num(packet, ip_header_len)  # get source, destination port number
        req_or_res = "Request" if dst_port == "80" else "Response"  # check if this packet is Response or Request

       
        tcp_header_len = get_tcp_header_len(packet, ip_header_len)
        http_start_idx = 14+ip_header_len+tcp_header_len
        http_header = get_http_header(packet, http_start_idx)  # get HTTP header in string
        if "HTTP" in http_header:  # print HTTP header if it exist
            print(f"{pkt_idx} {src_ip}:{src_port} {dst_ip}:{dst_port} HTTP {req_or_res}", end="\r\n")
            print(http_header, end="\r\n\r\n")
           
            pkt_idx += 1

        ### code for saving video ###
        http_start = 14 + ip_header_len + tcp_header_len
        if not start_saving:
            if "/project1.mp4" in http_header:
                tgt_dst = dst_ip
                start_saving = True
                # print(f"target dst ip : {tgt_dst}")
               
         

        elif src_ip == tgt_dst and req_or_res != "Request" and get_tcp_psh_flag(packet, ip_header_len):
            if content_length == 0 and "Content-Length" in http_header:
                content_length = int(re.findall(r"Content-Length: (\d+)", http_header)[0])
                #print(f"total content lenght : {content_length}bytes")
          
            http_in_byte = packet[http_start:]
            #print(f"http body in byte, len{len(http_in_byte)}, seg{segment_idx}")
            segment_idx += 1
            # print(http_in_byte)
            if video_in_byte == None:  #if the first packet of response packets
                video_in_byte = http_in_byte
            else:  # if rest of the packets
                video_in_byte += http_in_byte  # concat fetched bytes

         
            if content_length <= len(video_in_byte):
                http_header_end = -1
                for i, b in enumerate(video_in_byte):  # get http body index
                    if "".join([chr(j) for j in video_in_byte[i:i + 4]]) == "\r\n\r\n":  
                        http_header_end = i + 4
                        break
                video_in_byte = video_in_byte[http_header_end:]
                #print("total size : ",len(video_in_byte))
                # print("last packet fetched")
                if not os.path.exists(os.path.join(os.getcwd(), 'vid')):  # make dir \vid if it doesn't exist
                    os.mkdir("vid")

                f = open("vid/file.mp4", "wb")  # write fetched video in byte
                f.write(video_in_byte)
                start_saving = False  # end saving



if __name__ == "__main__":
    sniff_http()