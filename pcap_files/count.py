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

with open('nothing.pcap', 'rb') as f:
    data = f.read()

global_header = data[:24]
data = data[24:] # remove global header

packets = list()
packet_header_field = ['ts_sec', 'ts_usec', 'incl_len', 'orig_len']
packet_types = set()
command_type = set()
event_type = set()

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
    packet_types.add(data[4])

    if data[4] == 1:
        command_type.add(int.from_bytes(data[5:7], 'little'))
    elif data[4] == 4:
        event_type.add(data[5])


    # discard packet data
    data = data[pkt['orig_len']:]
    pkt['incl_len'] -= 4
    pkt['orig_len'] -= 4
    packets.append(pkt)

# Print the results
#print(packets)
print('packet_types {}'.format(packet_types))
print('command_types(1) {}'.format(command_type))
print('event_types(4) {}'.format(event_type))
print()
print('packet numbers: {}'.format(len(packets)))
