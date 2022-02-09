# CS 6490 Homework 3

`expo.py` is a program that efficiently exponentiates big numbers modulo n.

`dh_server.py` and `dh_client.py` are the server/client programs using TCP sockets where the client (Alice) and the server (Bob) perform a Diffie-Hellman exchange. 

To run the Diffie-Hellman exchange, first run `python3 dh_server.py` in a shell, then run `python3 dh_client.py` in a seperate shell.

The `dh_server.py` program outputs the number sent by Bob for the DH exchange (449485), and his shared key after the exchange (475269).

The `dh_client.py` program outputs the number sent by Alice for the DH exchange (179464), and her shared key after the exchange (475269).