from multiprocessing import Process, Manager
from Crypto.PublicKey import RSA
from tqdm import tqdm
from LEFT_trigger_core import *
from utils.zipper import is_zip_item

this_socket = socket(AF_INET, SOCK_DGRAM)
ip_addresses = []
port = 0
encrypt = False
trigger_core_process = Process()


def make_get_file_information_header(filename: str, key: bytes):
    operation_code = 0
    header = struct.pack('!B', operation_code)
    header_length = len(header + filename.encode())
    if encrypt:
        return encipher.sym_encrypt(struct.pack('!I', header_length) + header + filename.encode(), key)
    return struct.pack('!I', header_length) + header + filename.encode()


def make_get_file_block_header(filename: str, block_index: int, key: bytes):
    operation_code = 1
    header = struct.pack('!BQ', operation_code, block_index)
    header_length = len(header + filename.encode())
    if encrypt:
        return encipher.sym_encrypt(struct.pack('!I', header_length) + header + filename.encode(), key)
    return struct.pack('!I', header_length) + header + filename.encode()


def parse_file_information(msg: bytes, key: bytes):
    if encrypt:
        msg = encipher.sym_decrypt(msg, key)
    header_length_b = msg[:4]
    header_length = struct.unpack('!I', header_length_b)[0]
    header_b = msg[4:4 + header_length]
    server_operation_code = struct.unpack('!B', header_b[:1])[0]
    if server_operation_code == 0:  # get right operation code
        file_size, block_size, total_block_number = struct.unpack('!QHQ', header_b[1:])
    else:
        file_size, block_size, total_block_number = -1, -1, -1

    return file_size, block_size, total_block_number


def parse_file_block(msg: bytes, key: bytes):
    if encrypt:
        msg = encipher.sym_decrypt(msg, key)
    header_length_b = msg[:4]
    header_length = struct.unpack('!I', header_length_b)[0]
    header_b = msg[4:4 + header_length]
    server_operation_code = struct.unpack('!B', header_b[:1])[0]

    if server_operation_code == 0:  # get right block
        block_index = struct.unpack('!Q', header_b[1:])[0]
        file_block = msg[4 + header_length:]
    elif server_operation_code == 1:
        block_index, file_block = -1, None
    elif server_operation_code == 2:
        block_index, file_block = -2, None
    else:
        block_index, file_block = -3, None

    return block_index, file_block


def get_start_block_index(filename: str, block_size: int):
    item_path = os.path.join(share_dir, filename)
    if os.path.exists(item_path):
        current_size = os.path.getsize(item_path)
        print(f'current size:{current_size}')
        return math.ceil(current_size / block_size)
    return 0


def self_asymmetric_key(filename: str):
    file = os.path.join(temp_dir, filename)
    asymmetric_key = RSA.import_key(open(file).read())
    return asymmetric_key.export_key()


def get_confirmed_key_at_receiver(core_address: Tuple[str, int], save_key_peer_to_local: bool = False):
    """Steps:
        1. generate key peer which contains public key and private key
        2. send public key
        3. ack that sender get the correct public key
        4. send digital signature
        (if verify signature pass at sender side)
        5. send back packed symmetric encryption key to sender for acknowledgement
        6. get acknowledged, and unpack symmetric encryption key by private key decryption.
        7. return symmetric encryption key
    """
    if save_key_peer_to_local:
        encipher.generate_key_peer(save_key_peer_to_local)
        private_key = self_asymmetric_key('private_key.pem')
        public_key = self_asymmetric_key('public_key.pem')
    else:
        public_key, private_key = encipher.generate_key_peer()
    while True:
        this_socket.sendto(public_key, core_address)
        print('send key')
        try:
            msg = respond_working_if_request(this_socket)
            if msg is False:
                return False
        except:
            msg = ''
        if msg == public_key:
            signature = encipher.sign_signature(public_key, private_key)
            this_socket.sendto(signature, core_address)
            try:
                encrypted_key = respond_working_if_request(this_socket)
                if encrypted_key is False:
                    return False
            except:
                encrypted_key = ''
            print('received encrypted key')
            this_socket.sendto(encrypted_key, core_address)
            try:
                msg = respond_working_if_request(this_socket)
                if msg is False:
                    return False
            except:
                msg = ''
            if msg == b'3':
                return encipher.asym_decrypt(encrypted_key, private_key)


def get_last_byte(filename: str):
    """get the last byte number of a file"""
    filepath = os.path.join(share_dir, filename)
    if os.path.exists(filepath):
        return os.path.getsize(filepath)
    return 0


def start_receiver(items: List[str], core_address: Tuple[str, int]):
    print('receiver start')
    start_time = time.time()
    key = b''
    if encrypt:
        # Encryption enable
        key = get_confirmed_key_at_receiver(core_address)
        if key is False:
            return True
        print(f'key: {key} length: {len(key)}')
    server_not_have_or_broken_items = []
    for item in items:
        print(f'item name:{item}')
        item_size, block_size, total_block_number = get_item_information(item, core_address, key)
        if item_size is block_size is total_block_number is None:
            return True
        with open(log_path, 'a') as appender:
            appender.write(f'{item},{item_size},{block_size},{total_block_number}\n')
        block_index = get_start_block_index(item, block_size)
        print(f'start block index is:{block_index}')
        if item_size > 0:
            with tqdm(total=block_size * total_block_number, initial=get_last_byte(item), unit='B', desc=item,
                      unit_scale=True, unit_divisor=1024) as bar:
                with open(os.path.join(share_dir, item), 'ab') as file_io:
                    while block_index < total_block_number:
                        try:
                            this_socket.sendto(make_get_file_block_header(item, block_index, key), core_address)
                            msg, a_core_address = this_socket.recvfrom(block_size + 100)
                            if len(msg) < block_size and msg[0] in (ord('h'), ord('u')):
                                this_socket.sendto(b'w', a_core_address)
                                continue
                        except:  # time out (peer offline)
                            print('time out')
                            return True
                        block_index_from_server, file_block = parse_file_block(msg, key)
                        file_io.write(file_block)
                        block_index = block_index_from_server + 1
                        bar.update(block_size)
            item_path = os.path.join(share_dir, item)
            if is_zip_item(item_path):
                print(f'item:{item} is a zip file')
                shutil.move(item_path, os.path.join(temp_dir, item))
                Zipper(item).unzip()
            if get_item_size(item_path) == item_size:
                print('Downloaded content is completed.')
            else:
                server_not_have_or_broken_items.append(item)
                print('Downloaded content is broken.')
                remove(item)
                print(f'{item} has been removed.')
        else:
            server_not_have_or_broken_items.append(item)
            print('No such resource.')
    # notify "server" to break
    this_socket.sendto(f'</"*:{port}::break|?\\>'.encode(), core_address)
    print(f'receive time consumed:{time.time() - start_time}')
    return server_not_have_or_broken_items


def start_sender(core_address: Tuple[str, int], compressing, data: bytes = b''):
    this_socket.settimeout(6)
    print('set time out to 6s')
    # parse the data transferred from other core for item request
    print(f'data:{data}')
    try:
        key = b''
        if encrypt:
            # Encryption enable
            key = get_confirmed_key_at_sender(this_socket, core_address)
            if key is False:
                return False
            print(f'key: {key}')
        if data != b'':
            return_msg = msg_parse(data, encrypt, key, compressing)
            this_socket.sendto(return_msg, core_address)
        print('sender start')
        while True:
            msg, client_address = this_socket.recvfrom(128)
            if not encrypt and msg[0] in (ord('h'), ord('u')):
                this_socket.sendto(b'w', client_address)
                print('send working response for have request msg')
                continue
            # the end breaking protocol be constructed by all special characters with ':port::break'
            elif msg == f'</"*:{client_address[1]}::break|?\\>'.encode():
                print('received break msg')
                break
            return_msg = msg_parse(msg, encrypt, key, compressing)
            this_socket.sendto(return_msg, client_address)
    except:
        return False
    finally:
        this_socket.settimeout(3)
        return True


def get_item_information(item: str, core_address: Tuple[str, int], key: bytes):
    this_socket.sendto(make_get_file_information_header(item, key), core_address)
    print(f'core address:{core_address}')
    msg = respond_working_if_request(this_socket)
    if msg is False:
        return None, None, None
    item_size, block_size, total_block_number = parse_file_information(msg, key)
    return item_size, block_size, total_block_number


def start_updating(items: List[str], core_address: Tuple[str, int], compressing):
    print('updating start')
    start_time = time.time()
    key = b''
    if encrypt:
        # Encryption enable
        key = get_confirmed_key_at_receiver(core_address)
        if key is False:
            return True
    broken_items = []
    for item in items:
        item_size, block_size, total_block_number = get_item_information(item, core_address, key)
        if item_size is block_size is total_block_number is None:
            return True
        with open(log_path, 'a') as appender:
            appender.write(f'{item},{item_size},{block_size},{total_block_number}\n')
        item_path = store_large_item_or_dir_to_zip(item, compressing)

        # applied threshold 0.12%
        total_updating_block = math.ceil(0.0012 * total_block_number)
        total_update_size = total_updating_block * block_size
        updating_block_index = 0
        new_item_data = bytearray()
        with tqdm(total=total_update_size, initial=0, unit='B', desc=f'updating {item}', unit_scale=True,
                  unit_divisor=1024) as bar:
            while updating_block_index < total_updating_block:
                try:
                    this_socket.sendto(make_get_file_block_header(item, updating_block_index, key), core_address)
                    msg, a_core_address = this_socket.recvfrom(block_size + 100)
                    if len(msg) < block_size and msg[0] in (ord('h'), ord('u')):
                        this_socket.sendto(b'w', a_core_address)
                        continue
                except:  # time out (peer offline)
                    return True
                block_index_from_server, item_block = parse_file_block(msg, key)
                new_item_data.extend(item_block)
                updating_block_index = block_index_from_server + 1
                bar.update(block_size)
        with open(item_path, 'r+b') as file_io:
            file_io.seek(0)
            file_io.write(bytes(new_item_data))
        if is_zip_item(item_path):
            Zipper(item).unzip()
        item_path = os.path.join(share_dir, item)
        if get_item_size(item_path) == item_size:
            # goto next item transmission
            print('Downloaded content is completed.')
        else:
            broken_items.append(item)
            print('Downloaded content is broken.')
            remove(item)
            print(f'{item} has been removed.')
    # notify "server" to break
    this_socket.sendto(f'</"*:{port}::break|?\\>'.encode(), core_address)
    print(f'update time consumed:{time.time() - start_time}')
    return broken_items  # transmitted and return broken items


def create_trigger_core_process(compressing):
    # global variable port equals to init_core_port
    global trigger_core_process
    trigger_core_process = Process(target=create_trigger_core, args=(ip_addresses, port, compressing, encrypt))
    trigger_core_process.start()


def steady_state(compressing):
    print('into steady state')
    while True:
        this_socket.settimeout(None)
        # "other_core_address" might be init core or trigger core
        msg, other_core_address = this_socket.recvfrom(1 << 16)
        if compressing.value:
            this_socket.sendto(b'w', other_core_address)
            continue
        print(f'in steady state, received from {other_core_address}')
        try:
            trigger_core_process.terminate()
            trigger_core_process.join()
        except:
            pass
        process_common_response(msg, other_core_address, compressing)
        create_trigger_core_process(compressing)


def respond_have_request(data: bytes, other_core_address: Tuple[str, int], compressing):
    """There are three possible responds for have request:
        1. 'excess' means the items in local are not appeared in have request.
        2. 'same' means the items in local are same as the have request.
        3. lacking items in local would directly request from that address who send the request.
    """
    print(f'respond have request for {other_core_address}')
    data = data.decode()  # data comes from other core would become str type now.
    items_here = get_item_names()
    items_from_other = list(filter(None, data.split('|*|')))
    lacking_items = [item for item in items_from_other if item not in items_here]
    print(f'lacking_items:{lacking_items}')
    if len(lacking_items) != 0 and start_receiver(lacking_items, other_core_address):
        return False
    excess_items = [item for item in items_here if item not in items_from_other]
    print(f'excess_items:{excess_items}')
    if len(excess_items) != 0:
        this_socket.sendto(str('e' + '|*|'.join(excess_items)).encode(), other_core_address)
        print('send excess response')
        return start_sender(other_core_address, compressing)
    if not (lacking_items or excess_items):
        this_socket.sendto(b's', other_core_address)
        print('send same response')
        return True


def process_common_response(msg: bytes, other_core_address: Tuple[str, int], compressing):
    print(f'process common response for {other_core_address}')
    char = chr(msg[0])
    if char == 'h':
        return respond_have_request(msg[1:], other_core_address, compressing)
    elif char == 'u':
        return not start_updating(msg[1:].decode().split('|*|'), other_core_address, compressing)
    # other core requests file when code runs to here
    return start_sender(other_core_address, compressing, msg)


def init_main_core(ip: str, items_str: str, compressing):
    # receive 's' for responder having 'same' items.
    # receive 'w' for 'working'
    # receive 'e[]-->list' for other core 'excess' items.
    # lacking items on other host will be requested by them.
    while True:
        try:
            this_socket.sendto(str('h' + items_str).encode(), (ip, port))  # send items list to other init core
            print(f'send have request:{"h" + items_str} to ip:{ip}')
            msg, other_core_address = this_socket.recvfrom(1 << 16)
            if other_core_address[1] != port:
                this_socket.sendto(b'w', other_core_address)
                continue
            print(f'received msg from {other_core_address}')
            break
        except:
            print('time out')
            return False  # other core did not online
    print(f'msg:{msg}')
    char = chr(msg[0])
    print(f'char:{char}')

    if char in ('s', 'w'):
        return False

    # this core needs to request items from other when char == 'e'
    if char == 'e':
        print('received excess responses')
        excess_items_list = msg[1:].decode().split('|*|')
        print(f'excess_items_list:{excess_items_list}')
        start_receiver(excess_items_list, other_core_address)
        return True

    return process_common_response(msg, other_core_address, compressing)


def shutdown_recovery(broken_item: str, compressing):
    print(f'broken item:{broken_item} needs to recovery')
    items = get_item_names()
    if broken_item in items:
        items.remove(broken_item)
    items_str = '|*|'.join(items)
    success_responded = False
    while not success_responded:
        for ip in ip_addresses:
            if init_main_core(ip, items_str, compressing):
                success_responded = True
                break


def create_main_core(ip: str, init_core_port: int, encryption: bool):
    global this_socket, ip_addresses, port, encrypt
    ip_addresses = ip.split(',')
    port = init_core_port
    encrypt = encryption
    this_socket.bind(('', port))
    this_socket.settimeout(3)
    compressing = Manager().Value('b', False)
    # shutdown recovery stage
    log_items = read_log()
    if len(log_items) != 0 and get_item_size(os.path.join(share_dir, log_items[-1, 0])) != int(log_items[-1, 1]):
        shutdown_recovery(log_items[-1, 0], compressing)
    print('after break recovery')
    for ip in ip_addresses:
        items = get_item_names()
        for item in items:
            store_large_item_or_dir_to_zip(item, compressing)
        init_main_core(ip, '|*|'.join(items), compressing)
    create_trigger_core_process(compressing)
    steady_state(compressing)
