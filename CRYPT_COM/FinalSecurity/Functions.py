
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib
from Crypto import Random
import ast
import os



class Corrupted(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)



def pad(s, BLOCK_SIZE=32):
    p = s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
    return (p)

def unpad(s):
    return s[0:-ord(s[-1])]

def Digest(m):
    h = hashlib.sha512()
    h.update(m)

    return (h.digest())



def AESencrypt(password, plaintext):
    BLOCK_SIZE = 16
    MODE = AES.MODE_ECB
    iv = os.urandom(BLOCK_SIZE)

    plainlength = format(len(plaintext), '4')

    paddedPlaintext = pad(plaintext + str(plainlength) +str(Digest(password)))

    paddedPass = pad(password)
    paddedPass = paddedPass[0:32]


    cipherSpec = AES.new(paddedPass, MODE, iv)
    ciphertext = cipherSpec.encrypt(paddedPlaintext)

    ciphertext = ciphertext + iv

    return ciphertext.encode("hex")

def AESdecrypt(password, ciphertext,term=0):
    BLOCK_SIZE = 16
    MODE = AES.MODE_ECB

    decodedCiphertext = ciphertext.decode("hex")

    startIv = len(decodedCiphertext) - BLOCK_SIZE

    data, iv = decodedCiphertext[:startIv], decodedCiphertext[startIv:]

    paddedPass = pad(password)
    paddedPass = paddedPass[0:32]
    cipherSpec = AES.new(paddedPass, MODE, iv)
    plaintextWithPadding = cipherSpec.decrypt(data)
    plaintextfull = unpad(plaintextWithPadding)
    startLen = len(plaintextfull) - 4 - 64
    startDigest = len(plaintextfull) - 64


    plaintext = plaintextWithPadding[:startLen]
    plainlength = plaintextWithPadding[startLen:startDigest]
    Dig = plaintextWithPadding[startDigest:startDigest+64]                              #CHECK FOR PADDING PROBLEMS



    if (len(plaintext) != int(plainlength)):
        print "ERROR"
        raise Corrupted("Length Check Error")
    if (str(Digest(password)) != str(Dig)):
        print "ERROR"
        raise Corrupted("Hash Check Error")

    return plaintext



def RSAgenerate(public , private):
    KEY_LENGTH = 2048  # Key size (in bits)
    random_gen = Random.new().read

    keypair = RSA.generate(KEY_LENGTH, random_gen)

    with open(public, 'w') as public_file:
        public_file.write(keypair.publickey().exportKey())
    with open(private, 'w') as private_file:
        private_file.write(keypair.exportKey())

def RSAencrypt(plaintext, filename):

    with open(filename, 'r') as public_file:
        read = public_file.read()

    keyPub = RSA.importKey(read)
    plainlength = format(len(plaintext), '4')

    plaintextfull = str(plaintext) + str(plainlength) + str(Digest(keyPub.exportKey()))
    ciphertext = keyPub.encrypt(plaintextfull, 32)

    return str(ciphertext)

def RSAdecrypt(ciphertext, private, public):

    tuple_data = ast.literal_eval(ciphertext)                                    #convert to TUPEL


                                                 #Read Keys from files
    with open(private, 'r') as private_file:
        read = private_file.read()               #
    keyPriv = RSA.importKey(read)                #
                                                 #
    with open(public, 'r') as public_file:
        read = public_file.read()                #
    keyPub = RSA.importKey(read)                 #


    plaintext = keyPriv.decrypt(tuple_data)     #DECRYPT



    startLen = len(plaintext) - 4 - 64           #Separate plaintext
    startDigest = len(plaintext) - 64            #
    data = plaintext[:startLen]                  #
    datalength = plaintext[startLen:startDigest] #
    Dig = plaintext[startDigest:]                #




    if (len(data) != int(datalength)):
        print "ERROR"
        raise Corrupted("Length Check Error")
    if (str(Digest(keyPub.exportKey())) != Dig):
        print "ERROR"
        raise Corrupted("Hash Check Error")

    return data


#RSAgenerate("Cpublic","Cprivate")
#RSAgenerate("Spublic","Sprivate")

