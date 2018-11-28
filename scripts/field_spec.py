acl_data = {
    'Length': 16,
    'Channel_ID': 16,
    'Payload': -1
}

hci_command = {
    'OCF': 10,
    'OGF': 6,
    'Length': 8
}

hci_acl_data = {
    'Handle': 12,
    'PB_Flag': 2,
    'BC_Flag': 2,
    'Length': 16,
    'acl_data': acl_data
}

hci_sync_data = {
    'Handle': 12,
    'Packet_Status': 2,
    'RFU': 2,
    'Length': 8
}

hci_event = {
    'Event': 8,
    'Length': 8
}

header_field = {
    'ts_sec': 32,
    'ts_usec': 32,
    'incl_len': 32,
    'orig_len': 32,
    None: 32,
    'packet_type': 8
}

data_field= {
    1: hci_command,
    2: hci_acl_data,
    3: hci_sync_data,
    4: hci_event,
}

def parse_field(field, data):
    ret = dict()
    end = 0
    for key, value in field.items():
        if key is None:
            pass
        elif type(value) is int:
            if value < 0:
                end8 = int(end/8)
                ret.update({
                    key: data[end8:] 
                })
            else:
                ret.update({
                    key: int_from_bits(data, end, end+value)
                })
        elif type(value) is dict:
            end8 = int(end/8)
            inner, _ = parse_field(value, data[end8: end8+ret['Length']])
            ret.update({key: inner})
            continue
        end += value 

    data = data[int(end/8):]

    return ret, data
        
def int_from_bits(data, start, end):
   num = int.from_bytes(data, 'little') 
   return (num>>start) & ((1<<(end-start))-1)
