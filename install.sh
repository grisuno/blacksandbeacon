#!/bin/bash

apt-get install gcc libcurl4-openssl-dev libssl-dev
gcc -o beacon beacon3.c aes.c cJSON.c -lcurl -lssl -lcrypto
