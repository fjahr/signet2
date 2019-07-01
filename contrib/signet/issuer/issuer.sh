#!/usr/bin/env bash
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

#
# Issue blocks using a local node at a given interval.
#

if [ $# -lt 3 ]; then
    echo "syntax: $0 <idle time> <bitcoin-cli path> [<bitcoin-cli args>]" ; exit 1
fi

function log()
{
    echo "- $(date +%H:%M:%S): $*"
}

idletime=$1
shift

bcli=$1
shift

if ! [ -e "$bcli" ]; then
    which "$bcli" &> /dev/null
    if [ $? -ne 0 ]; then
        echo "error: unable to find bitcoin binary: $bcli" ; exit 1
    fi
fi

echo "- checking node status"
conns=$($bcli "$@" getconnectioncount)

if [ $? -ne 0 ]; then
    echo "node error" ; exit 1
fi

if [ $conns -lt 1 ]; then
    echo "warning: node is not connected to any other node"
fi

log "node OK with $conns connection(s)"
log "mining at maximum capacity with $idletime second delay between each block"
log "hit ^C to stop"

while true; do
    log "generating next block"
    # get address for coinbase output
    addr=$($bcli "$@" getnewaddress)
    # create an unsigned, un-PoW'd block
    unsigned=$($bcli "$@" getnewblockhex $addr)
    # sign it
    signed=$($bcli "$@" signblock $unsigned)
    # grind proof of work; this ends up broadcasting the block, if successful (akin to "generatetoaddress")
    while true; do
        blockhash=$($bcli "$@" grindblock $signed 100000000)
        if [ "$blockhash" = "false" ]; then continue; fi
        break;
    done
    if [ $? -ne 0 ]; then echo "node error; aborting" ; exit 1; fi
    log "mined block $($bcli "$@" getblockcount) $blockhash to $($bcli "$@" getconnectioncount) peer(s); idling for $idletime seconds"
    sleep $idletime
done
