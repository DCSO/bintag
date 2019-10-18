#!/usr/bin/env python3

# ==============================================================================
# date:      2019-09-24
# author:    alexander.rausch@dcso.de
# sharing:   TLP:GREEN
# reference: internal tooling
#
# Read Malpedia information
# This script is run with a path to a file in the Malpedia repository as
# argument. The script will print the JSON file containing meta information
# and the description to stdout.
#
# usage: % ./read_malpedia_information.py path/to/sample/in/malpedia/repo
#
# ==============================================================================

import json
import os
import sys

from os import listdir
from os.path import isfile, join

def get_json_files(directory):
    files = [ f for f in listdir(directory) if isfile(join(directory, f)) ]
    files = [ f for f in files if f.endswith(".json") ]
    return files

def walk_down(path):
    files = get_json_files(path)
    if len(files) > 0:
        return (path, files)
    new_path = os.sep.join(path.split(os.sep)[:-1])
    if new_path != "":
        return walk_down(new_path)
    return []

def read_info(path):
    # assume input some/dir/path/binary
    directory = os.path.abspath(os.sep.join(path.split(os.sep)[:-1]))
    path_files = walk_down(directory)
    json_path = path_files[0]
    files = path_files[1]
    assert(len(files) == 1)
    with open(os.path.join(json_path, files[0]), "r") as f:
        data = json.load(f)
    return data

def get_tagname(path):
    return path.split(os.sep)[-3]

def main():
    meta = read_info(sys.argv[1])
    print(json.dumps(meta))

if __name__ == "__main__":
    main()
