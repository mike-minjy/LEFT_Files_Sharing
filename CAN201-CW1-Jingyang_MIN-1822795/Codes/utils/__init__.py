from os import curdir
from os.path import join

"""Configure relative path here
Notice: root is 'main.py'
"""
share_dir = join(curdir, 'share')
temp_dir = join(curdir, 'temp')
log_path = join(temp_dir, 'ReceivedItemsLog.csv')
