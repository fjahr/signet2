#!/usr/bin/env bash
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

#
# Backup Issuer which will begin to issue blocks if it sees no blocks within
# a specified period of time. It will continue to make blocks until a block
# is generated from an external source (i.e. the primary issuer is back online)
#

if [ $# -lt 3 ]; then
    echo "syntax: $0 <trigger time> <idle time> <bitcoin-cli path> [<bitcoin-cli args>]" ; exit 1
fi

function log()
{
    echo "- $(date +%H:%M:%S): $*"
}

triggertime=$1
shift

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
log "hit ^C to stop"

# outer loop alternates between watching and mining
while true; do
    # inner watchdog loop
    blocks=$($bcli "$@" getblockcount)
    log "last block #$blocks; waiting up to $triggertime seconds for a new block"
    remtime=$triggertime
    while true; do
        waittime=1800
        if [ $waittime -gt $remtime ]; then waittime=$remtime; fi
        conns=$($bcli "$@" getconnectioncount)
        if [ $conns -eq 1 ]; then s=""; else s="s"; fi
        log "waiting $waittime/$remtime seconds with $conns peer$s"
        sleep $waittime
        new_blocks=$($bcli "$@" getblockcount)
        if [ $new_blocks -gt $blocks ]; then
            log "detected block count increase $blocks -> $new_blocks; resetting timer"
            remtime=$triggertime
            blocks=$new_blocks
        else
            (( remtime=remtime-waittime ))
            if [ $remtime -lt 1 ]; then break; fi
        fi
    done
    log "*** no blocks in $triggertime seconds; initiating issuance ***"
    # inner issuer loop
    while true; do
        log "generating next block"
        blockhash=$(./mkblock.sh "$bcli" "$2") || { echo "node error; aborting" ; exit 1; }
        blocks=$($bcli "$@" getblockcount)
        log "mined block $new_blocks $blockhash to $($bcli "$@" getconnectioncount) peer(s); idling for $idletime seconds"
        sleep $idletime
        new_blocks=$($bcli "$@" getblockcount)
        if [ $blocks -lt $new_blocks ]; then
            log "primary issuer appears to be back online ($blocks -> $new_blocks blocks during downtime); going back to watching"
            break
        fi
    done
done
