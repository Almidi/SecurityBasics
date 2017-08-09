
#import socket
#import sys

from socket import *
from ssl import *


# Create a TCP/IP socket
sock = socket(AF_INET, SOCK_STREAM)


# Bind the socket to the port
server_address = ('localhost', 10000)

print >>sys.stderr, 'starting up on %s port %s' % server_address

try:
    sock.bind(server_address)
except:
    print >>sys.stderr, 'Unable to bind socket. Please Change IP setting and try again'
    exit(-1)


# Listen for incoming connections

try :
    sock.listen(1)
except:
    print >>sys.stderr, 'Unable to read socket. Please Change IP setting and try again'
    exit(-1)


#wrap socket  ----------->  Protocol SSLv2
tls_server =  wrap_socket(sock, ssl_version=PROTOCOL_SSLv2, cert_reqs=CERT_NONE, server_side=True, keyfile='privateKey.key', certfile='certificate.crt')



#wait for connection :
while True:
    try:
        print >>sys.stderr, 'waiting for a connection'
        connection, client_address= tls_server.accept()
        break;
    except:
        print >>sys.stderr, 'Incoming Connection Failed'


print >>sys.stderr, 'connection from', client_address

length = 0

while True:

    try:
        # Receive the data retransmit it
        data = connection.recv(1024)
        length = len(data)
        print >>sys.stderr, 'received "%s"' % data

    except:
        print "Failed To Receive Data"
        print "Closing Connection"

        break
    finally:

        if (length==0):
            # Clean up the connection
            print >>sys.stderr, 'closing connection'
            connection.close()
            break