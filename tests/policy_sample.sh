#!/bin/sh
# Test script for muacc client library with mam that has the sample policy module loaded
# Author: Theresa Enghardt <theresa@net.t-labs.tu-berlin.de>

running=0
ret=0

pgrep mamma
if [ $? = '1' ]
then
	echo "Multi Access Manager not running - starting mamma..."
	./mamma policy_sample.la &
else
	ps ax | grep -v grep | grep "mamma" | grep "policy_sample" > /dev/null
	if [ $? = '1' ]
	then
		echo "Multi Access Manager running, but wrong policy module - killing and restarting..."
		killall mamma
		./mamma policy_sample.la &
	else
		running=1
	fi
fi

./test_policy_sample
ret=$?
echo "Test finished with return value $ret"

if [ "$running" = '0' ]
then
	killall mamma
fi

exit "$ret"
