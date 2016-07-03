#!/bin/sh

while [ $# -gt 0 ]; do
	tmp=`tr -d ' \n\r' < $1`
	echo "$tmp" > $1
	shift
done
