from Functions import *
import socket
import sys



with open("AESkey", 'r') as file:
        key =file.read()



# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10080)
print >>sys.stderr, 'connecting to %s port %s' % server_address
sock.connect(server_address)
try:

    datain = sock.recv(1024)
    print  AESdecrypt(key,datain)

    dataout = AESencrypt(key,"Client Says Hello")
    sock.sendall(dataout)

finally:
    print >>sys.stderr, 'closing socket'
    sock.close()