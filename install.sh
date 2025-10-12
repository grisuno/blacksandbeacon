#!/bin/bash
gcc -o beacon beacon3.c aes.c cJSON.c -lcurl -lssl -lcrypto
