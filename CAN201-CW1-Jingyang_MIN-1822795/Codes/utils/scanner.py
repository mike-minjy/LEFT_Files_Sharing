import hashlib
import os
import shutil
from typing import List
from utils.__init__ import *


def get_item_names():
    """Get all item names in share folder."""
    return os.listdir(share_dir)


def get_item_names_and_mtime(item_names: List):
    """Obtain all modification time corresponding to each item name."""
    return {item_name: os.path.getmtime(os.path.join(share_dir, item_name)) for item_name in item_names}


def get_item_md5(item_name: str):
    """Get the MD5 of item stored in share folder.
    Notice: It is callable for file or folder."""
    start_dir = os.path.join(share_dir, item_name)
    if not os.path.exists(start_dir):
        raise FileNotFoundError(f'No such file or directory: {start_dir}')

    md5 = hashlib.md5()
    if os.path.isfile(start_dir):
        with open(start_dir, 'rb') as reader:
            md5.update(reader.read())
        return md5.hexdigest()
    # item is a folder
    # dir_path represents the directory name which is traversing now.
    # dir_names is a list which contains all sub-directory names in dir_path
    # file_names is a list which contains all file names in dir_path
    for dir_path, dir_names, file_names in os.walk(start_dir):
        for filename in file_names:
            with open(os.path.join(dir_path, filename), 'rb') as reader:
                md5.update(reader.read())
    return md5.hexdigest()


def remove(item_name: str):
    """Remove all related item from this project.
    It includes both item in share folder and corresponding zip item in temp folder."""
    item_path = os.path.join(share_dir, item_name)
    if not os.path.exists(item_path):
        raise FileNotFoundError(f'The system cannot find the file or directory specified: {item_path}')

    if os.path.isfile(item_path):
        os.remove(item_path)
    else:
        shutil.rmtree(item_path)

    # received zip file is a single item without .zip suffix
    temp_item_path = os.path.join(temp_dir, item_name)
    if os.path.exists(temp_item_path):
        os.remove(temp_item_path)


def get_item_size(item_path):
    """Get item size based on start path of it.
    This method is callable for file or directory."""
    if not os.path.exists(item_path):
        return 0

    if os.path.isfile(item_path):
        return os.path.getsize(item_path)  # item_size
    # item is a directory
    item_size = 0
    with os.scandir(item_path) as dir_list:
        for item in dir_list:
            if item.is_file():
                file_size = os.path.getsize(item.path)
                item_size += file_size
            else:  # item is a directory in sub folder
                sub_folder_size = get_item_size(item.path)  # to get item size recursively
                item_size += sub_folder_size
    return item_size
