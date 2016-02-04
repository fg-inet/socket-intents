#!/bin/sh
# Test script for muacc client library with mam that has a policy module loaded (default: sample policy)
# Author: Theresa Enghardt <theresa@inet.tu-berlin.de>
#
### Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
### All rights reserved. This project is released under the New BSD License.


already_running=0
ret=0
MAMMA=`which mamma`

if [ "$1" = "" ]
then
	policy="policy_sample.conf"
	echo "Testing Multi Access Manager with default policy $policy"
	echo "To test other policies, supply their configuration file as an argument to this script ($0)"
else
	policy="$1"
	echo "Testing Multi Access Manager with policy $policy"
fi

if [ $MAMMA = "" ]
then
    echo "Mamma does not seem to be installed. Please invoke \"make install\"."
    exit 127
fi

pgrep mamma
if [ $? = '1' ]
then
	echo "Multi Access Manager not running - starting mamma..."
	$MAMMA "$policy" >/dev/null &
    sleep 1
else
	ps ax | grep -v grep | grep "mamma" | grep "$policy" > /dev/null
	if [ $? = '1' ]
	then
		echo "Multi Access Manager running, but with the wrong policy - killing and restarting..."
		killall mamma
		$MAMMA "$policy" >/dev/null &
	else
        echo "Mamma is already running with this policy."
		already_running=1
	fi
fi

testdir=${0%/*}
$testdir/policytest

ret=$?
echo "Test finished with return value $ret"

if [ "$already_running" = '0' ]
then
    echo "Killing Multi Access Manager..."
	killall mamma
fi

exit "$ret"
