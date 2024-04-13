# Client Server AES Communication

This project is a simple client-server communication using AES encryption. Client and server communicate using a TCP connection. The client sends an encrypted message to the server, and the server decrypts the message and sends it back to the client. The client then verifies if the message is the same as the original message.

## Python Libraries Used
- socket
- random
- petlib
- os
- ast

## Overview
The folder contains two scripts, `server.py` and `client.py`. To start, run the server script followed by the client script to establish a connection.

Once connected, the client send a hello message to the server. The server on receiving the message, geenrates a random 128-bit prime (we use safe prime for this). We consider the multiplicative group of integers modulo this prime. Pick a random generator of this group and a random exponent. The server then sends the generator and the generator raised to the random exponent to the client.

The client then generates a random exponent and sends the generator raised to this exponent to the server. The server then computes the shared key as the generator raised to the product of the random exponent generated by the client and the random exponent generated by the server.

Once the shared key is established, the client encrypts a message using AES encryption and sends it to the server. The server decrypts the message and sends it back to the client. The client then verifies if the message is the same as the original message.

## Running the Scripts
1. Open two terminal windows.
2. In the first terminal window, run the server script using the command `python3 server.py`.
3. In the second terminal window, run the client script using the command `python3 client.py`.

Note that this program is designed to run only once. You will need to restart the server and client scripts to run the program again.