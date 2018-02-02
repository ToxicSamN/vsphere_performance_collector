import sys
from shutil import copy2



if __name__ == '__main__':

    source_file = str(sys.argv[1])
    destination_file = str(sys.argv[2])
    copy2(source_file, destination_file)


