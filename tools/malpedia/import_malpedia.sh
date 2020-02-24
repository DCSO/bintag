#!/usr/bin/env bash

# ==============================================================================
#
# date:      2019-09-24
# author:    alexander.rausch@dcso.de
# sharing:   TLP:GREEN
# reference: internal tooling
#
# Malpedia import script
# This script builds BinTag definitions from the Malpedia repository.
#
# requirements:
#   * jq in $PATH
#   * ida and ida64 in $PATH
#
# usage: % ./import_malpedia.sh path/to/malpedia
#
# ==============================================================================

BINTAG_PATH="$HOME/.bintag"

function infomsg {
    echo -e "\e[36m\e[40m\e[1mINFO:\e[0m $1"
}

function resultmsg {
    echo -e "\e[32m\e[40m\e[1mRESULT:\e[0m $1"
}

function get_pe32 {
    pe32=(`find "$1" -type f -not -iname "*.json" -not -iname "*.txt" -not -iname "*_*" -exec file {} \; | grep "PE32 " | cut -d ':' -f 1`)
}

function get_pe32_64 {
    pe32_64=(`find "$1" -type f -not -iname "*.json" -not -iname "*.txt" -not -iname "*_*" -exec file {} \; | grep "PE32+ " | cut -d ':' -f 1`)
}

function dump_mnemonic_hist_32 {
    ida -B -S"$(pwd)/export_mnemonics_hist.py \"$2\"" $1
}

function dump_mnemonic_hist_64 {
    ida64 -B -S"$(pwd)/export_mnemonics_hist.py \"$2\"" $1
}

function build_BinTag_32 {
    malpedia_info=`./read_malpedia_information.py $1`
    common_name=`echo $malpedia_info | jq .common_name | sed 's/"//g' | sed 's/[\]//g'`
    description=`echo $malpedia_info | jq .description | sed 's/"//g' | sed 's/[\]//g'`
    name="malpedia-$common_name-$RANDOM"

    dump_mnemonic_hist_32 $1 "/tmp/$name"
    rm -f "$1.idb"
    jq ".tag = \"$name\"" "/tmp/$name" | jq ".description = \"$description\"" > "$BINTAG_PATH/tags/$name"
    rm -f "/tmp/$name"
}

function build_BinTag_64 {
    malpedia_info=`./read_malpedia_information.py $1`
    common_name=`echo $malpedia_info | jq .common_name | sed 's/"//g' | sed 's/[\]//g'`
    description=`echo $malpedia_info | jq .description | sed 's/"//g' | sed 's/[\]//g'`
    name="malpedia-$common_name-$RANDOM"

    dump_mnemonic_hist_64 $1 "/tmp/$name"
    rm -f "$1.i64"
    jq ".tag = \"$name\"" "/tmp/$name" | jq ".description = \"$description\"" > "$BINTAG_PATH/tags/$name"
    rm -f "/tmp/$name"
}

# searching all PE32 binaries in malpedia repo
get_pe32 $1
infomsg "found ${#pe32[@]} PE32 files"

# searching all PE32+ binaries in malpedia repo
get_pe32_64 $1
infomsg "found ${#pe32_64[@]} PE32+ files"

# create directory for bintags
mkdir -p $HOME/.bintag/tags

for (( i=0; i<${#pe32[@]}; i++ ))
do
    f=${pe32[$i]}
    infomsg "processing $f"
    build_BinTag_32 $f
done

for (( i=0; i<${#pe32_64[@]}; i++ ))
do
    f=${pe32_64[$i]}
    infomsg "processing $f"
    build_BinTag_64 $f
done

resultmsg "import completed!"
