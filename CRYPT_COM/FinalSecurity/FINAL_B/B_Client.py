from Functions import *
import socket
import sys

def Corruption():
    print >>sys.stderr,"\n\nData Corruption Occured"
    print >>sys.stderr,"Please Check Your Connection And The Security Of Your Network\n\n "
def ConnErr():
    print >>sys.stderr,"\n\nConnection Problem Occured"
    print >>sys.stderr,"Please Check Your Connection And The Security Of Your Network\n\n "


PORT = 10080

#-------------------------------------------------------------------------Connection Establishment----------------------
try :
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the port where the server is listening
    server_address = ('localhost', PORT)
    print >>sys.stderr, 'CLIENT: connecting to %s port %s' % server_address
    sock.connect(server_address)
except socket.error :
    ConnErr()
    exit(1)


#-------------------------------------------------------------------------------Method Menu-----------------------------
print "CLIENT: 1) Use Symmetric Cryptography"
print "CLIENT: 2) Use Asymmetric Cryptography"
print "CLIENT: 3) Use Asymmetric and Symmetric Cryptography Combined"
print "CLIENT: Any other -> Exit"
func = raw_input("\nCLIENT: Option :")

#exchange prefered method with server
try:
    dataout = RSAencrypt(func[:1],"Spublic")
    dataout = dataout.zfill(1024)
    sock.sendall(dataout)
#-------------------------------------------------------------------------------SYMMETRIC-------------------------------

    if (func == '1'):
        # Receive AES Key
        datain = sock.recv(1024)
        AESKey = RSAdecrypt(datain,"Cprivate","Cpublic")
        # Get Message
        message = raw_input("\nCLIENT: Please enter message :")

        # Send Encrypted Message Chunks
        while len(message) :
            chunk = message[:32]
            # Encrypt Chunk
            dataout =AESencrypt(AESKey,chunk)
            # Pad Dataout
            dataout = '0(' + dataout
            dataout = dataout.zfill(512)
            sock.sendall(dataout)
            # Remove sent chunk from message
            message = message[32:]
#--------------------------------------------------------------------------------ASYMMETRIC-----------------------------

    elif (func == '2'):
        # Get Message
        message = raw_input("\nCLIENT: Please enter message :")
        # Send Encrypted Message Chunks
        while len(message) :
            chunk = message[:32]
            # Encrypt Chunk
            dataout =RSAencrypt(chunk,"Spublic")
            # Pad Dataout
            dataout = dataout.zfill(1024)
            sock.sendall(dataout)
            # Remove sent chunk from message
            message = message[32:]

#-------------------------------------------------------------------------------ASYMMETRIC + SYMMETRIC -----------------

    elif (func == '3'):

        datain = sock.recv(1024)
        AESKey = RSAdecrypt(datain,"Cprivate","Cpublic")
        # Get Message
        message = raw_input("\nCLIENT: Please enter message :")
        # Encrypt Message With SYMMETRIC
        AEScrypted = AESencrypt(AESKey,message)
        # Send Encrypted Message Chunks
        while len(AEScrypted) :
            chunk = AEScrypted[:32]
            # Encrypt Chunk With ASYMMETRIC
            dataout =RSAencrypt(chunk,"Spublic")
            # Pad Dataout
            dataout = dataout.zfill(1024)
            sock.sendall(dataout)
            # Remove sent chunk from message
            AEScrypted = AEScrypted[32:]
#------------------------------------------------------------------------------------EXCEPTIONS-------------------------

except Corrupted as e:
    print >>sys.stderr, e.value
    Corruption()

except ValueError as e:
    Corruption()
    err = 1

except socket.error:
    ConnErr()
    exit(1)

finally:
    print 'CLIENT: closing socket'
    sock.close()