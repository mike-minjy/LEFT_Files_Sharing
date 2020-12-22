import argparse
from os import mkdir
from os.path import exists
from utils.__init__ import log_path
from LEFT_main_core import create_main_core


def _argparse():
    """Handle the user input parameters"""
    parser = argparse.ArgumentParser(description="A parser to obtain ip and encryption.")
    parser.add_argument('--ip', action='store', required=True,
                        dest='ip', help='The IPv4 addresses of hosts. Format: --ip x.x.x.x,x.x.x.x,...(etc)')
    parser.add_argument('--encryption', action='store', default='no',
                        dest='encryption', help='The switch of encryption function. Format: --encryption yes/no')
    return parser.parse_args()


def main():
    """Initialize whole environment of the project"""
    parser = _argparse()
    encryption = False
    if parser.encryption.lower() == 'yes':
        encryption = True
    for folder in ('share', 'temp'):
        if not exists(folder):
            mkdir(folder)
    if not exists(log_path):
        with open(log_path, 'w') as writer:
            writer.write('item_name,actual_item_size,block_size,total_blocks\n')
    create_main_core(parser.ip, 22001, encryption)


if __name__ == '__main__':
    main()
