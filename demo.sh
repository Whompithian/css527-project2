#! /bin/bash

HOST='localhost'
PORT=51836
CRYPTO='/usr/lib/python2.7/dist-packages/Crypto/__init__.py'
PROMPT="\e[0;32m${USER}@${HOSTNAME}:\e[01;34m~$ \e[0m"

if [ ! -e ${CRYPTO} ]
then
  echo "Need to install python-crypto"
  echo
  echo -e "${PROMPT}sudo apt-get install python-crypto"
  sudo apt-get install python-crypto
  echo
  echo
  echo
fi

echo "RSA key exchange in Python"
echo "Author: Brendan Sweeney"
echo "Course: CSS 527"
echo "  Date: November 4, 2014"
echo
echo
echo -e "${PROMPT}./rsa.py bob --host ${HOST} --port ${PORT} &"
sleep 1
echo -e "${PROMPT}./rsa.py alice --host ${HOST} --port ${PORT}"
sleep 1
./rsa.py bob --host ${HOST} --port ${PORT} &
sleep 1
./rsa.py alice --host ${HOST} --port ${PORT}

exit 0
