#!/usr/bin/env python2

# ==============================================================================
# date:      2019-09-24
# author:    alexander.rausch@dcso.de
# sharing:   TLP:GREEN
# reference: internal tooling
#
# Mnemonic histogram export script for IDA Pro
# This script is run as a plugin from IDA Pro and exports a mnemonic histgram
# as well as imported functions and the architecture bit width to a json file.
#
# usage: % ida -B -S"$(pwd)/export_mnemonics_hist.py \"$(pwd)/out.json\""
#          path/to/binary
#
# ==============================================================================

import ida_hexrays
import ida_ida
import ida_pro
import idaapi
import idautils
import idc
import json
import os
import sys
from itertools import groupby

# ==============================================================================
# constants
# ==============================================================================

CWD = os.sep.join(sys.argv[0].split(os.sep)[:-1])

# ==============================================================================
# globals
# ==============================================================================

imports = []
imports_module = ""

# ==============================================================================
# implementation
# ==============================================================================

def get_functions():
    functions = dict()
    for f_ea in idautils.Functions():
        functions[f_ea] = idc.get_name(f_ea)
    return functions

def imp_cb(ea, name, ordinal):
    global imports
    imports.append(name)
    return True

def get_imports():
    global imports, imports_module
    nimps = idaapi.get_import_module_qty()
    for i in xrange(0, nimps):
        idaapi.enum_import_names(i, imp_cb)
    return imports

def get_mnemonics(f_ea):
    mnem = []
    for ea in idautils.FuncItems(f_ea):
        mnem.append(idc.print_insn_mnem(ea))
    return mnem

def histogram(tokens):
    tokens.sort()
    return [ (key, len(list(group))) for key, group in groupby(tokens) ]

def write_result(f, msg):
    formated_msg = json.dumps(msg, sort_keys=True, indent=4, separators=(',', ': '))
    with open(f, "w+") as f:
        f.write("%s\n" % formated_msg)

# ==============================================================================
# main
# ==============================================================================

def main():
    idaapi.auto_wait()

    info = dict()

    info["arch"] = dict()
    info["arch"]["is_32bit"] = ida_ida.inf_is_32bit()
    info["arch"]["is_64bit"] = ida_ida.inf_is_64bit()

    info["imports"] = get_imports()
    functions = get_functions()

    info["histogram"] = dict()
    for f_ea in functions:
        disasm = get_mnemonics(f_ea)
        h = histogram(disasm)
        h_d = dict()
        for t in h:
            h_d[t[0]] = t[1]
        info["histogram"][functions[f_ea]] = h_d

    write_result(idc.ARGV[1], info)
    ida_pro.qexit(0)


if __name__ == "__main__":
    main()
