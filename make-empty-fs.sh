#!/bin/bash
if [ -z "$1" ]; then
	echo "No valid args"
fi
echo Making in: $1
mkdir $1/bin
mkdir $1/dev
mkdir $1/opt
mkdir $1/run
mkdir $1/sys
mkdir $1/var
mkdir $1/boot
mkdir $1/etc
mkdir $1/lib
mkdir $1/proc
mkdir $1/sbin
mkdir $1/tmp
mkdir $1/home
mkdir $1/lib64
mkdir $1/mnt
mkdir $1/root
mkdir $1/srv
mkdir $1/usr
