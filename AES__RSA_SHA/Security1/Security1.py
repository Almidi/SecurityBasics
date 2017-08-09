
from os import chmod

import os, random, struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA


def encrypt_file(key, in_filename, out_filename=None):
    chunksize=64 * 1024

    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None):
    chunksize=24 * 1024
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)


def hash_file(in_filename, out_filename=None):
    if not out_filename:
        out_filename = in_filename + '.enc'

    with open(in_filename, 'r') as infile:
        with open(out_filename, 'w') as outfile:

            pre_hash = infile.read()

            post_hash=SHA256.new()

            post_hash.update(pre_hash)

            outfile.write(post_hash.hexdigest())


def sign_files_create():

    key = RSA.generate(2048)

    with open("private.key", 'wb') as content_file:
        chmod("private.key", 0600)
        content_file.write(key.exportKey())
    pubkey = key.publickey()
    print key
    print key.publickey()

    with open("public.key", 'wb') as content_file:
        content_file.write(pubkey.exportKey())


def sign_files(key_filename, sign_filename):

    with open(key_filename) as key_file:
        private_key = RSA.importKey(key_file)
    public_key = private_key.publickey()
    with open(sign_filename) as seed_file:
        plaintext = seed_file.read()
    hash = SHA256.new(plaintext)
    signer = PKCS1_PSS.new(private_key)
    signature =  signer.sign(hash)
    with open("signature", 'wb') as signature_file:
        signature_file.write(signature)


def check_signature(key_filename, sign_filename, plaintext):

    with open(plaintext) as plaintext_file:
        plaintext = plaintext_file.read()
    with open(sign_filename, 'rb') as signature_file:
        signature = signature_file.read()
    with open(key_filename) as public_key_file:
        public_key = RSA.importKey(public_key_file)
    #print signature

    hash = SHA256.new(plaintext)
    print hash.hexdigest()
    verifier = PKCS1_PSS.new(public_key)
    if verifier.verify(hash, signature):
         print "The signature is authentic."
    else:
         print "The signature is not authentic."

def main():

    print "In case you dont have a private and a public key, a pair of them can be auto generated :"
    optionr = raw_input('Create Signature Key Files ? (y/n): ')

    if optionr== "y" :
        sign_files_create()


    while True :
        print '--------Main Menu :--------\n'
        print 'Options :\n'
        print '1) Encrypt File'
        print '2) Decrypt File'
        print '3) Hash File'
        print '4) Sign File'
        print '5) Check File Signature'
        print '6) Exit \n'
        option = input('Select Option : ')

        if (option == 6):
            print "GG WP"

            break

        if (option == 1):


            filename = raw_input('Enter Filename : ')

            while True :
                key = raw_input('Enter Key : ')
                if len(key) == 16 :
                    break
                print 'Ender a 16 byte key'

            #key = hashlib.sha256(key).digest()
            encrypt_file(key ,filename,"AESencrypted.txt")

        if (option == 2):

            filename = raw_input('Enter Filename : ')

            while True :
                key = raw_input('Enter Key : ')
                if len(key) == 16 :
                    break
                print 'Ender a 16 byte key'

            decrypt_file(key, filename,"AESdencrypted.txt")


        if (option == 3):

            filename = raw_input('Enter Filename : ')
            hash_file(filename,"hashed.txt")

        if (option == 4):

            key = raw_input('Enter Private Key Filename : ')
            plain = raw_input('Enter Filename To Be Signed : ')
            sign_files(key,plain)

        if (option == 5):

            key = raw_input('Enter Public Key Filename : ')
            signature = raw_input('Enter Signature Filename: ')
            plain = raw_input('Enter Usnigned Filename To Check: ')


            check_signature(key,signature,plain)


main()