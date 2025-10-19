#!/bin/bash

apt-get install gcc libcurl4-openssl-dev libssl-dev
gcc -rdynamic -o beacon beacon3.c aes.c cJSON.c -lcurl -lssl -lcrypto
gcc -rdynamic -o beacon_gopher gopher_beacon.c aes.c cJSON.c -lcurl -lssl -lcrypto
