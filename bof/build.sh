#!/bin/bash

gcc -c -fPIC -nostdlib -m64 -O2 -s $1 -o $2 && cp $2 /home/grisun0/LazyOwn/sessions

