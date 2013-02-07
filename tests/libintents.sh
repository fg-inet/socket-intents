#!/bin/sh
# Test script for libintents
# Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>

preloadlib=""
candidatelibs=`find . -name "libintents*so*"`

for lib in $candidatelibs
do
	if [ -x "$lib" ]
		then
		preloadlib="$lib"
	fi
done

if [ "$preloadlib" = "" ]
then
	echo "Could not find any executable libintents.so"
	exit 1
fi

if [ `which socat` = "" ]
then
	echo "Could not find socat - please install it"
	exit 1
fi

pgrep socat
if [ $? = '1' ]
	then
	echo "Socat not running - starting socat..."
	socat UNIX-LISTEN:/tmp/muacc.socket,fork PIPE&
fi

echo "================================================"
echo "Testing intents library"
echo "Please report failures to theresa@net.t-labs.tu-berlin.de"
echo "================================================"

LD_PRELOAD="$preloadlib" ./testintents

killall socat
