'''
pcap format:
    Global header | Packet Header | Packet Data | Packet Header | Packet Data | ....
'''

'''
packet header format:
typedef struct pcaprec_hdr_s {
    guint32 ts_sec;     /* timestamp seconds */
    guint32 ts_usec;    /* timestamp microseconds */
    guint32 incl_len    /* number of octets of packet */
    guint32 orig_len    /* actual length of packet */
} pcaprec_hdr_t;
'''

with open('files.pcap', 'rb') as f:
    data = f.read()

global_header = data[:24]
data = data[24:] # remove global header

packets = list()
packet_header_field = ['ts_sec', 'ts_usec', 'incl_len', 'orig_len']

while data: 
    # read packet header
    pkt = dict()
    for i in range(4):
        pkt.update({packet_header_field[i]:\
                int.from_bytes(data[i*4:i*4+4], byteorder='little')})

    # discard packet header
    data = data[16:]

    # read packet data, need to discard first 4 bytes, dont know why...
    pkt.update({'data': data[4:pkt['orig_len']]}) 

    # discard packet data
    data = data[pkt['orig_len']:]
    pkt['incl_len'] -= 4
    pkt['orig_len'] -= 4
    packets.append(pkt)
    print(len(packets));

# Print the results
print(packets)
print()
print('packet numbers: {}'.format(len(packets)))
