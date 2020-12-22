import math
import struct
import time
import warnings
from multiprocessing import Pool, cpu_count, Lock
from socket import *
from typing import Tuple
from numpy import loadtxt
from utils import encipher
from utils.scanner import *
from utils.zipper import Zipper

BLOCK_SIZE = 65300  # 65300 bytes


def get_item_block(filename: str, block_index: int, is_zip_file: bool = False):
    if is_zip_file:
        item_path = os.path.join(temp_dir, filename)
    else:
        item_path = os.path.join(share_dir, filename)
    with open(item_path, 'rb') as f:
        f.seek(block_index * BLOCK_SIZE)
        file_block = f.read(BLOCK_SIZE)
    return file_block


def store_large_item_or_dir_to_zip(item: str, compressing, need_update: bool = False):
    item_path = os.path.join(share_dir, item)
    # if item is a folder or single item size larger than 800MB would be zipped afterwards.
    # (800MB threshold might be replaced by sampling items to judge whether compress or not.)
    if os.path.isdir(item_path) or get_item_size(item_path) > 800 * (1 << 20):
        item_path = os.path.join(temp_dir, item)
        if need_update and os.path.exists(item_path):
            os.remove(item_path)
        if not os.path.exists(item_path) or get_item_size(item_path) == 0:
            print(f'zip {item} to local')
            compressing.value = True
            Zipper(item).zip(to_local=True)
            compressing.value = False
            print(f'complete zip {item} to local')
    return item_path


def make_return_item_information_header(filename: str, compressing):
    share_item_path = os.path.join(share_dir, filename)
    if os.path.exists(share_item_path):  # find file and return information
        item_path = store_large_item_or_dir_to_zip(filename, compressing)
        actual_item_size = get_item_size(share_item_path)
        server_operation_code = 0
        total_block_number = math.ceil(get_item_size(item_path) / BLOCK_SIZE)
        header = struct.pack('!BQHQ', server_operation_code, actual_item_size, BLOCK_SIZE, total_block_number)
    else:  # no such file
        server_operation_code = 1
        header = struct.pack('!B', server_operation_code)
    header_length = len(header)
    return struct.pack('!I', header_length) + header


def make_item_block(filename: str, block_index: int):
    item_path = os.path.join(share_dir, filename)
    if not os.path.exists(item_path):  # Check the file existence
        server_operation_code = 1
        header = struct.pack('!B', server_operation_code)
        header_length = len(header)
        return struct.pack('!I', header_length) + header

    temp_item_path = os.path.join(temp_dir, filename)
    is_zip_file = False
    if os.path.exists(temp_item_path):
        is_zip_file = True
        item_size = get_item_size(temp_item_path)
    else:
        item_size = get_item_size(item_path)
    total_block_number = math.ceil(item_size / BLOCK_SIZE)

    if block_index < total_block_number:
        file_block = get_item_block(filename, block_index, is_zip_file)
        server_operation_code = 0
        header = struct.pack('!BQ', server_operation_code, block_index)
        header_length = len(header)
        return struct.pack('!I', header_length) + header + file_block
    # block_index >= total_block_number
    server_operation_code = 2
    header = struct.pack('!B', server_operation_code)
    header_length = len(header)
    return struct.pack('!I', header_length) + header


def msg_parse(msg: bytes, encrypt: bool, the_key: bytes, compressing):
    if encrypt:
        # coming message using symmetric decryption AES
        msg = encipher.sym_decrypt(msg, the_key)
    header_length_b = msg[:4]  # get header_length package segment
    header_length = struct.unpack('!I', header_length_b)[0]  # unpack header_length package to get length of header
    header_b = msg[4:4 + header_length]  # get header and filename segment
    client_operation_code = struct.unpack('!B', header_b[:1])[0]  # unpack operation code (0 or 1 is valid)

    if client_operation_code == 0:  # get file information
        item_name = header_b[1:].decode()
        if encrypt:
            return encipher.sym_encrypt(make_return_item_information_header(item_name, compressing), the_key)
        return make_return_item_information_header(item_name, compressing)

    if client_operation_code == 1:  # get file block
        block_index_from_client = struct.unpack('!Q', header_b[1:9])[0]
        item_name = header_b[9:].decode()
        if encrypt:
            return encipher.sym_encrypt(make_item_block(item_name, block_index_from_client), the_key)
        return make_item_block(item_name, block_index_from_client)

    # Error code
    server_operation_code = 4  # seems like 400 in http protocol
    header = struct.pack('!B', server_operation_code)
    header_length = len(header)
    if encrypt:
        return encipher.sym_encrypt(struct.pack('!I', header_length) + header, the_key)
    return struct.pack('!I', header_length) + header


def respond_working_if_request(the_socket: socket):
    while True:
        try:
            msg, other_core_address = the_socket.recvfrom(1 << 16)
            if msg[0] in (ord('h'), ord('u')) and '|*|'.encode() in msg:
                the_socket.sendto(b'w', other_core_address)
            else:
                return msg
        except:  # time out (peer offline)
            return False


def get_confirmed_key_at_sender(the_socket: socket, core_address: Tuple[str, int], data: bytes = b''):
    """Steps:
        1. receive public key from receiver
        2. send to receiver for acknowledgement
        3. verify digital signature
        (if verification not raise exception: pass verification)
        4. send encrypted symmetric encryption key
        5. ack receiver get the correct packed key
        6. return symmetric encryption key
    """
    public_key = data
    the_socket.settimeout(60)
    while True:
        if data == b'':
            public_key = respond_working_if_request(the_socket)
        elif chr(data[0]) in ('s', 'e', 'w'):
            return False
        the_socket.sendto(public_key, core_address)
        print('get public key')
        try:
            msg = respond_working_if_request(the_socket)
            print('acked')
        except:
            msg = ''
        encipher.verify_signature(msg, public_key, public_key)
        the_key = encipher.get_sym_encryption_key()
        encrypted_key = encipher.asym_encrypt(the_key, public_key)
        the_socket.sendto(encrypted_key, core_address)
        print('send encrypted key')
        msg = respond_working_if_request(the_socket)
        if msg == encrypted_key:
            the_socket.sendto(b'3', core_address)
            if the_socket.getsockname()[1] == 22001:
                the_socket.settimeout(6)
            else:
                the_socket.settimeout(25)
            break
    return the_key


# numpy utilized to get conveniences/benefits of reading log
def read_log():
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        return loadtxt(log_path, dtype=str, delimiter=',', skiprows=1, ndmin=2)


def get_new_or_update_items():
    # '.' represents the update mark
    previous_items = get_item_names()
    previous_item_names_and_mtime = get_item_names_and_mtime(previous_items)
    update_items = ['.']
    while True:
        current_items = get_item_names()
        # read information from log
        log_items = read_log()
        if len(log_items) != 0:
            # log_items[:, 0] are received_items
            previous_items.extend([item for item in log_items[:, 0] if item not in previous_items])
        for item in current_items:
            if item not in previous_items:
                print(f'return items:{current_items} because of added new items')
                return current_items
        update_items.extend(
            [key for key, value in previous_item_names_and_mtime.items() if
             os.path.getmtime(os.path.join(share_dir, key)) != value])
        if len(update_items) != 1:
            print(f'return updated items:{update_items}')
            return update_items


def init_trigger_core(init_core_address: Tuple[str, int], items: str, compressing, encryption: bool):
    char = items[0]
    items_list = items[1:].split('|*|')
    lock.acquire()
    if char == 'h':
        for item in items_list:
            store_large_item_or_dir_to_zip(item, compressing)
    else:
        for update_item in items_list:
            store_large_item_or_dir_to_zip(update_item, compressing, need_update=True)
    lock.release()
    print(f'send items:{items} to {init_core_address}')
    the_key = b''
    with socket(AF_INET, SOCK_DGRAM) as server_socket:
        server_socket.settimeout(25)
        timeout_times = 0
        timeout_threshold = 2
        while timeout_times < timeout_threshold:
            try:
                server_socket.sendto(items.encode(), init_core_address)
                if encryption:
                    # Encryption enable
                    the_key = get_confirmed_key_at_sender(server_socket, init_core_address)
                    if the_key is False:
                        break
                while True:
                    msg, client_address = server_socket.recvfrom(128)
                    if msg == f'</"*:{client_address[1]}::break|?\\>'.encode():
                        return
                    elif not encryption:
                        if msg[0] == ord('w'):
                            time.sleep(6)
                            break
                        elif msg[0] in (ord('s'), ord('e')):
                            return
                    return_msg = msg_parse(msg, encryption, the_key, compressing)
                    server_socket.sendto(return_msg, init_core_address)
            except:  # time out (might be peer offline)
                if timeout_times == timeout_threshold:
                    break
                timeout_times += 1


def init_pool(pool_lock):
    global lock
    lock = pool_lock


def create_trigger_core(ip_addresses: List[str], port: int, compressing, encryption: bool):
    pool_size = len(ip_addresses)
    remain_cpu_core = cpu_count() - 2
    max_pool_size = remain_cpu_core if remain_cpu_core > 0 else 1
    lock = Lock()
    pool = Pool(pool_size if pool_size <= max_pool_size else max_pool_size, initializer=init_pool, initargs=(lock,))
    while True:
        items_list = get_new_or_update_items()
        if items_list[0] == '.':
            items = str('u' + '|*|'.join(items_list[1:]))
        else:
            items = str('h' + '|*|'.join(items_list))
        parameters = [((ip, port), items, compressing, encryption) for ip in ip_addresses]
        pool.starmap_async(init_trigger_core, parameters)
