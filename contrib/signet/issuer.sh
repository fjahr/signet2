#!/usr/bin/env bash
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

#
# Issue blocks using a local node at a given interval.
#

if [ $# -lt 2 ]; then
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
    command -v "$bcli" >/dev/null 2>&1 || { echo >&2 "error: unable to find bitcoin binary: $bcli"; exit 1; }
fi

echo "- checking node status"
conns=$($bcli "$@" getconnectioncount) || { echo >&2 "node error"; exit 1; }

if [ $conns -lt 1 ]; then
    echo "warning: node is not connected to any other node"
fi

log "node OK with $conns connection(s)"
log "mining at maximum capacity with $idletime second delay between each block"
log "hit ^C to stop"

while true; do
    log "generating next block"
    blockhash=$(./mkblock.sh "$bcli" "$@") || { echo "node error; aborting" ; exit 1; }
    log "mined block $($bcli "$@" getblockcount) $blockhash to $($bcli "$@" getconnectioncount) peer(s); idling for $idletime seconds"
    sleep $idletime
done
