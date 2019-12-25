#!/bin/bash
openssl genrsa 2048 > key.pem
openssl req -new -key key.pem | openssl x509 -days 3650 -req -signkey key.pem > cert.pem