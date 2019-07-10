#!/usr/bin/env bash
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

#
# Get coins from Signet Faucet
#

if [ $# -lt 1 ]; then
    >&2 echo "syntax: $0 <bitcoin-cli path> [--faucet=<faucet URL>=https://signet.bc-2.jp/claim] [<bitcoin-cli args>]"
    exit 1
fi

bcli=$1
shift

if [ "${1:0:9}" = "--faucet" ]; then
    faucet=${1:10}
    shift
else
    faucet="https://signet.bc-2.jp/claim"
fi

if ! [ -e "$bcli" ]; then
    command -v "$bcli" >/dev/null 2>&1 || { echo >&2 "error: unable to find bitcoin binary: $bcli"; exit 1; }
fi

# get address for receiving coins
addr=$($bcli "$@" getnewaddress) || exit 1

curl -X POST -d "address=$addr" $faucet
