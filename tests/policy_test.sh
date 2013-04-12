#!/bin/sh
# Test script for muacc client library with mam that has the sample policy module loaded
# Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>

running=0
ret=0

if [ "$1" = "" ]
then
	policy="policy_sample.la"
	echo "Testing Multi Access Manager with default policy $policy"
	echo "To test other policy modules, supply them as an argument to this script ($0)"
else
	policy="$1"
	echo "Testing Multi Access Manager with policy $policy"
fi

pgrep mamma
if [ $? = '1' ]
then
	echo "Multi Access Manager not running - starting mamma..."
	./mamma "$policy" >/dev/null &
else
	ps ax | grep -v grep | grep "mamma" | grep "$policy" > /dev/null
	if [ $? = '1' ]
	then
		echo "Multi Access Manager running, but wrong policy module - killing and restarting..."
		killall lt-mamma
		./mamma "$policy" >/dev/null &
	else
		running=1
	fi
fi

./test_policy_generic
ret=$?
echo "Test finished with return value $ret"

if [ "$running" = '0' ]
then
	killall lt-mamma
fi

exit "$ret"
