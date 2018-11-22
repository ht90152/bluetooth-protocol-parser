hci_command = [
        ['OCF', 'OGF', 'Length'],
        [10, 6, 8]
        ]

hci_acl_data = [
        ['Handle', 'PB_Flag', 'BC_Flag', 'Length'],
        [12, 2, 2, 16]
        ]

hci_sync_data = [
        ['Handle', 'Packet_Status', 'RFU', 'Length'],
        [12, 2, 2, 8]
        ]

hci_event = [
        ['Event', 'Length'],
        [8, 8]
        ]
# -1 means INF

header_field = [
        ['ts_sec', 'ts_usec', 'incl_len', 'orig_len', None, 'packet_type'],
        [32, 32, 32, 32, 32, 8],
        ]

data_field= {
        1: hci_command,
        2: hci_acl_data,
        3: hci_sync_data,
        4: hci_event,
        }

def parse_field(field, data):
    ret = dict()
    length = len(field[0])
    end = 0
    for i in range(length):
        if field[0][i] != None:
            ret.update({field[0][i]: data[end: end+field[1][i]]})
            ret.update({
                field[0][i]: int_from_bits(data, end, end+field[1][i])
                })
        end += field[1][i]

    data = data[int(end/8):]


    return ret, data
        
def int_from_bits(data, start, end):
   num = int.from_bytes(data, 'little') 
   return (num>>start) & ((1<<(end-start))-1)
