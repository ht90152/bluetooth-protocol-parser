

l2cap_data = {
    'Length': 16,
    'Channel_ID': 16,
    'Choose': 'Channel_ID',
    0x0001: {
        'Code': 8,
        'Identifier': 8,
        'Length': 16,
        'Choose': 'Code',
        2: {
            'PSM': 16,
            'Src_CID': 16
        },
        3: {
            'Dst_CID': 16, # This two CIDs must be linked to their upper layer protocol by PSM of Code 0x02 
            'Src_CID': 16,  # This two CIDs must be linked to their upper layer protocol by PSM of Code 0x02
            'Result': 16,
            'Status': 16
        },
        4: {
            'Dst_CID': 16, 
            'Flags': 16,
            'Config_Opt': 32
        },
        5: {
            'Src_CID': 16,
            'Flags': 16,
            'Result': 16,
            'Config': 16,
        },
        6: {
            'Dst_CID': 16,
            'Src_CID': 16
        },
        7: {
            'Dst_CID': 16,
            'Src_CID': 16
        },
        10: {
            'InfoType': 16
        },
        11: {
            'InfoType': 16,
            'Result': 16,
            'Data': -1
        },
        'Name': {
            2: 'Con_req',
            3: 'Con_res',
            4: 'Config_req',
            5: 'Config_res',
            6: 'Discon_req',
            7: 'Discon_res',
            10: 'Info_req',
            11: 'Info_res'
        }
    },
    0x0002: {
        '2': '2',
    },
    -1: {
        'Data': -2, # This part of data will be parsed later (after getting the upper protocol)
        # -2 means reserved to parse later
    },
    'Name': {
        0x0001: 'Signaling Channel',
        0x0002: '0x0002',
        -1    : 'Dynamic allocated' # TODO: change this to correct name later
    }
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
    'acl_data': l2cap_data
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

data_field = {
    1: hci_command,
    2: hci_acl_data,
    3: hci_sync_data,
    4: hci_event,
}

sdp_field = { # TODO: this is wrong!
    'PDU': 8,
    'Transaction_ID': 16,
    'Length': 16,
    'Parameters': -1
}

avdtp_field = { 
    'Msg_type': 2,
    'Packet_type': 2,
    'Transaction': 4,
    'Choose': 'Packet_type',
    0: {
        'Signal_ID': 6,
        'RFA': 2,
        'Other_data': -1
    },
    1: {
        'NOSP': 8,
        'Signal_ID': 6,
        'RFA': 2,
    },
    2: {
    },
    3: {
    },
    'Name': {
        0: 'Single_Packet',
        1: 'Start_Packet',
        2: 'Continue_Packet',
        3: 'End_Packet'
    }
}

avctp_field = { # TODO: this might be wrong
    'IPID': 1,
    'C/R': 1,
    'Packet_type': 2,
    'Transaction': 4,
    'Profile_ID': 16,
    'Other_Data': -1
}

psm_field = {
    1: sdp_field,
    23: avctp_field,
    25: avdtp_field,
    4105: {  # This is actually not the real one, its dynamically allocated!
    }
}

dynamic_CID_table = dict()
dynamic_CID_table_name = {
    1: 'SDP',
    23: 'AVCTP',
    25: 'AVDTP',
    4105: 'no!'
}

def parse_field(field, data, cur_channel_id = None, endian='little'):
    ret = dict()
    end = 0
    for key, value in field.items():
        if key is None:
            pass
        elif key == 'Choose':
            choose = ret[value]
            if choose not in field: choose = -1

            end8 = int(end/8)
            if 'Length' not in ret:
                inner, _ = parse_field(field[choose], data[end8:], cur_channel_id)
            else:
                inner, _ = parse_field(field[choose], data[end8: end8+ret['Length']], cur_channel_id)
            ret.update(inner)

            ####### specific update for dynamic CID table #######
            if value == 'Code': # 2-side channel
                if choose == 2:
                    dynamic_CID_table[inner['Src_CID']] = inner['PSM']
                elif choose == 3:
                    dynamic_CID_table[inner['Dst_CID']] = dynamic_CID_table[inner['Src_CID']]
            #####################################################

            break
        
        elif type(value) is int:
            if value == -1: # value = -1 means retrieve all remaining data
                end8 = int(end/8)
                ret.update({
                    key: data[end8:] 
                })
            elif value == -2: # multiplexing
                end8 = int(end/8)
                op_name = dynamic_CID_table[cur_channel_id]

                inner, _ = parse_field(psm_field[op_name], data[end8:])
                ret.update({dynamic_CID_table_name[op_name]:inner})
            else:  # normal usage
                ret.update({
                    key: int_from_bits(data, end, end+value, endian)
                })
                if key == 'Channel_ID':
                    cur_channel_id = ret['Channel_ID']
        elif type(value) is dict:  
            end8 = int(end/8)
            if 'Length' not in ret:
                inner, _ = parse_field(value, data[end8:])
            else: inner, _ = parse_field(value, data[end8: end8+ret['Length']])
            ret.update({key: inner})
            continue
        end += value 

    data = data[int(end/8):]

    return ret, data

def int_from_bits(data, start, end, endian='little'):
   num = int.from_bytes(data, endian) 
   return (num>>start) & ((1<<(end-start))-1)
