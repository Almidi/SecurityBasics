import socket
import sys
from ssl import *

# Create a TCP/IP socket
sock = socket(AF_INET, SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)

#Connect to server

try:
    sock.connect(server_address)
    print >>sys.stderr, 'connecting to %s port %s' % server_address
except:
    print >>sys.stderr, 'Connection failed to %s port %s' % server_address
    exit (-1)

#Wrap socket ---------> SSLv2

try:
    tls_client =  wrap_socket(sock, ssl_version=PROTOCOL_SSLv2, cert_reqs=CERT_REQUIRED,ca_certs= 'certificate.crt', server_side=False)
except:
    print >>sys.stderr, 'SSL Authentication Failed'
    exit(-1)

length = 0

while True :

    try:
        # Send data
        message = raw_input("Message to be sent :")
        if (len(message)!=0):
            print >>sys.stderr, 'sending "%s"' % message

        try :
            tls_client.sendall(message)
            length = len(message)
        except:
            print >>sys.stderr, 'Connection To Server Lost'
            exit (-1)


    finally:
        if (length==0):
            # Clean up the connection
            print >>sys.stderr, 'closing socket'
            sock.close()
            exit(0)