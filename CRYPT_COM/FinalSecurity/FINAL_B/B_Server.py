
from Functions import *
import socket
import sys


def Corruption():
    print >>sys.stderr,"\n\nData Corruption Occured -> MESSAGE INTEGRITY ERROR"
    print >>sys.stderr,"Please Check Your Connection And The Security Of Your Network\n\n "
def ConnErr():
    print >>sys.stderr,"\n\nConnection Problem Occured"
    print >>sys.stderr,"Please Check Your Connection And The Security Of Your Network\n\n "

PORT = 10080


AESKey = os.urandom(32)


# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to the port
server_address = ('localhost', PORT)
print >>sys.stderr, 'SERVER: starting up on %s port %s' % server_address

try:
    sock.bind(server_address)
    # Listen for incoming connections
    sock.listen(1)
    # Wait for a connection
    print  "SERVER: waiting for a connection"
    connection, client_address = sock.accept()
except socket.error :
    ConnErr()
    exit(1)


err = 0

try:
    print  "SERVER: connection from", client_address

    #get the desired plan
    datain = connection.recv(1024)
    i = datain.find("0(")
    datain = datain[i+1:]
    func = RSAdecrypt(datain,"Sprivate","Spublic")

#-------------------------------------------------------------------------------SYMMETRIC-------------------------------
    if (func == '1'):
        print "SERVER: Client Will Use Symmetric Cryptography"
        # Encrypt the key and send it
        dataout = RSAencrypt(AESKey,"Cpublic")
        connection.sendall(dataout)
        # Get chunks of the final AEScyphertext
        message = ""
        while True:
            datain = connection.recv(512)
            if datain:
                # Unpad data packet
                i = datain.find("(")
                datain = datain[i+1:]
                # Decrypt the packet and add it to the final AEScyphertext
                message = message + AESdecrypt(AESKey,datain)
            else:
                print "SERVER: no more data from", client_address
                break
        # Decrypt the final AEScypher
        print  "CLIENT: \"",message,"\""

#--------------------------------------------------------------------------------ASYMMETRIC-----------------------------
    elif (func == '2'):
        print "SERVER: Client Will Use Asymmetric Cryptography"
        message = ""
        while True:
           datain = connection.recv(1024)
           if datain:
               # Unpad data packet
               i = datain.find("0(")
               datain = datain[i+1:]
               # Decrypt the packet and add it to the final AEScyphertext
               message = message + RSAdecrypt(datain,"Sprivate","Spublic")
           else:
               print "SERVER: no more data from", client_address
               break
        # Decrypt the final AEScypher
        print  "CLIENT: \"",message,"\""

#-------------------------------------------------------------------------------ASYMMETRIC + SYMMETRIC -----------------
    elif (func == '3'):
        print "SERVER: Client Will Use Asymmetric and Symmetric Cryptography Combined"
        # Encrypt the key and send it
        dataout = RSAencrypt(AESKey,"Cpublic")
        connection.sendall(dataout)
        # Get chunks of the final AEScyphertext
        AEScrypted = ""
        while True:
            datain = connection.recv(1024)
            if datain:
                # Unpad data packet
                i = datain.find("0(")
                datain = datain[i+1:]
                # Decrypt the packet and add it to the final AEScyphertext
                AEScrypted =AEScrypted + RSAdecrypt(datain,"Sprivate","Spublic")
            else:
                print "SERVER: no more data from", client_address
                break
        # Decrypt the final AEScypher
        print  "CLIENT: \"",AESdecrypt(AESKey, AEScrypted),"\""
    else :
        print "SERVER: Client Terminated The Connection"
#------------------------------------------------------------------------------------EXCEPTIONS-------------------------

#Ecxeption For Corrupted Data Packets
except Corrupted as e :
    print e.value
    Corruption()
    err = 1

except ValueError as e:
    Corruption()
    err = 1
#Exception For Connection Error
except socket.error :
    ConnErr()
    exit(1)

finally:
    # Clean up the connection
    print "\nSERVER: Closing Connection"
    connection.close()
    exit(err)