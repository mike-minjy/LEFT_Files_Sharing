import math
import os
import zipfile
from io import BytesIO
from utils.__init__ import share_dir, temp_dir, log_path


def is_zip_item(item_path):
    """To verify whether the item is a zip item or not."""
    return zipfile.is_zipfile(item_path)


class Zipper(object):
    """Encapsulated class 'Zipper' for convenient usage in this project."""
    def __init__(self, item_name: str):
        """Select the item which requires to be compressed,
        and BytesIO holds the item which needs to be compressed into memory."""
        self.in_memory_zip = BytesIO()
        self.item_name = item_name

    def zip(self, to_local: bool = False):
        """Zip a file with contents to either local zip or in-memory zip."""
        start_dir = os.path.join(share_dir, self.item_name)

        if not os.path.exists(start_dir):
            raise FileNotFoundError(f'No such file or directory: {start_dir}')

        if to_local:
            # Get a handler to the local zip in write mode
            zf = zipfile.ZipFile(os.path.join(temp_dir, self.item_name), 'w', zipfile.ZIP_DEFLATED,
                                 allowZip64=True)
        else:
            # Get a handler to the in-memory zip in write mode
            zf = zipfile.ZipFile(self.in_memory_zip, 'w', zipfile.ZIP_DEFLATED, allowZip64=True)

        if os.path.isfile(start_dir):
            zf.write(start_dir, self.item_name)
        else:
            # dir_path represents the directory name which is traversing now.
            # dir_names is a list which contains all sub-directory names in dir_path
            # file_names is a list which contains all file names in dir_path
            for dir_path, dir_names, file_names in os.walk(start_dir):
                # ***Important*** If not replace start_dir, it will copy all items from CWD.
                file_path = dir_path.replace(start_dir, self.item_name)
                for filename in file_names:
                    zf.write(os.path.join(dir_path, filename), os.path.join(file_path, filename))
        zf.close()
        return self

    def unzip(self):
        """Unzip an item from either memory or local
        Notice: Received zip file is a single item without .zip suffix
        """
        if self.read_from_memory() == b'':
            zipfile.ZipFile(os.path.join(temp_dir, self.item_name)).extractall(share_dir)
        else:
            zipfile.ZipFile(self.in_memory_zip).extractall(share_dir)

    def read_from_memory(self):
        """Return bytes with the contents of the in-memory zip."""
        return self.in_memory_zip.getvalue()

    def write_to_file(self):
        """Write the zip to a local file.
        Notice: This method is only available for zip stored in memory.
        """
        if self.read_from_memory() == b'':
            raise OperationNotSupportException('Only invokable for zip file which has stored contents in memory.')

        with open(os.path.join(temp_dir, self.item_name), 'wb') as writer:
            writer.write(self.read_from_memory())

    def write_to_log(self, block_size: int):
        """Write the information of zip to log."""
        if self.read_from_memory() == b'':
            with open(os.path.join(temp_dir, self.item_name), 'rb') as reader:
                data = reader.read()
        else:
            data = self.read_from_memory()
        data_size = len(data)
        with open(log_path, 'a') as appender:
            # item_name,item_size,block_size,total_blocks and turn to a new line
            appender.write(f'{self.item_name},{data_size},{block_size},{math.ceil(data_size / block_size)}\n')


class OperationNotSupportException(Exception):
    """Support method (Zipper -> write_to_file) to guarantee safety operation."""
    def __init__(self, error):
        self.error = error

    def __str__(self, *args, **kwargs):
        return self.error
