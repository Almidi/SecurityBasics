
from Functions import *
import socket
import sys


with open("AESkey", 'r') as file:
        key =file.read()



# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('localhost', 10080)
print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)
# Listen for incoming connections
sock.listen(1)


# Wait for a connection
print  "SERVER: waiting for a connection"
connection, client_address = sock.accept()

try:
    print  "SERVER: connection from", client_address


    print("Message to send (MAX 1024 characters)")

    message = raw_input()
    dataout = AESencrypt(key,message[:1024])
    connection.sendall(dataout)
    data = connection.recv(1024)

    if data:
        print  AESdecrypt(key,data)
    else:
        print "SERVER: no more data from", client_address

finally:
    # Clean up the connection
    connection.close()