from event_contents import event_code, event_parameters
from hci_ocf import cmd_code, cmd_parameters

acl_data = {
    'Length': 16,
    'Channel_ID': 16,
    'Payload': -1
}

hci_command = {
    'OCF': 10,
    'OGF': 6,
    'Length': 8,
    'Parameter': cmd_parameters(1)
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
    'Length': 8,
    'Parameter': event_parameters  # all event_parameter are in event_contents.py
}

header_field = {
    'ts_sec': 32,
    'ts_usec': 32,
    'incl_len': 32,
    'orig_len': 32,
    None: 32,
    'packet_type': 8
}

data_field = {
    1: hci_command,
    2: hci_acl_data,
    3: hci_sync_data,
    4: hci_event,
}


def parse_field(field, data):
    hci_type = check_push_value_count = 0
    check_cmd_count = 0
    ret = dict()
    end = 0
    for key, value in field.items():
        if key is None:
            pass
        elif type(value) is int:
            if value < 0:
                end8 = int(end / 8)
                # value < -1 -> special case and convert to decimal number
                ret.update({
                    key: data[end8:] if value > -2 else int.from_bytes(data[end8:], 'little')
                })
            else:
                tmp_hci_type = hci_type
                hci_type, typeValue = typeCode_to_typeValue(key, int_from_bits(data, end, end + value))
                if(key == 'OGF'):
                    hci_command['Parameter'] = cmd_parameters(typeValue)
                hci_type = hci_type if tmp_hci_type == 0 else tmp_hci_type  # if hci_type is changed, then restoring hci_type by tmp_value
                check_push_value_count += 1
                ret.update({
                    key: typeValue
                })
        elif type(value) is dict:
            end8 = int(end / 8)
            # guide the correct event parameter
            value = value[ret['Event']] if 'Event' in ret else value
            if('OCF' in ret and check_cmd_count == 0):
                check_cmd_count = 1
                value = value[cmd_code(ret['OGF'])[ret['OCF']]] if 'OCF' in ret else value
                hci_ocf, vlue_ocf = update_cmd(value, data, end)
                ret.update({
                    'Parameter': hci_ocf
                })
                continue
            inner, _ = parse_field(value, data[end8: end8 + ret['Length']])
            ret.update({key: inner})
            continue
        if check_push_value_count == 1: update_right_value_in_dict(field)
        end += value

    data = data[int(end / 8):]

    return ret, data


def int_from_bits(data, start, end, endian='little'):
    num = int.from_bytes(data, 'little')
    ret = (num>>start) & ((1<<(end-start))-1)
    if endian == 'big':
        return int.from_bytes(ret.to_bytes(int((ret.bit_length()+7)/8), 'big'), 'little')
    return ret

# on Case 4(event), Event code converts to Event name by its code.
# e.g, Event code : 14H (20d) > Event name: Mode Change
# You can modify name and code content,
# but it must contain event_code[pure_int] ... to get event name
# return hci_type by data_field and name
def typeCode_to_typeValue(key, pure_int):
    if key in header_field:
        return -1, pure_int
    elif key in data_field[1]:
        return 1, pure_int
    elif key in data_field[2]:
        return 2, pure_int
    elif key in data_field[3]:
        return 3, pure_int
    elif key in data_field[4]:
        return 4, event_code[pure_int]
    else:
        return 0, pure_int

def update_right_value_in_dict(data_dict):
    # get first key and value to update last parameter
    first_parmtr = [list(data_dict.keys())[0], list(data_dict.values())[0]]

    for key, value in data_dict.items():
        # -1 and -2 belong to special case, -3 and -4 belong to reserved field
        if type(value) is int and value < -4:
            value = value * -1 * first_parmtr[1]  # index 1 is first value in dict
            
def update_cmd(data_dict, data, end):
    ret = dict()
    for key, value in data_dict.items():
        if(type(value) is int and value > 0):
            if(key == 'BD_ADDR' or key == 'Link_Key'):
                ret.update({
                    key: int_from_bits(data, end, end + value*8).to_bytes(value, 'little').hex()
                })
            else:
                ret.update({
                    key: int_from_bits(data, end, end + value*8)
                })
            #print(hex(int_from_bits(data, end, end + 8)))
        end += value*8
    data = data[int(end / 8):]
    return ret, data
