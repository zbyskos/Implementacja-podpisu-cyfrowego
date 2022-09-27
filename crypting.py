
from __future__ import barry_as_FLUFL
from fileinput import filename
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import RNG

import random

def generateAndSign(fileName):
    data = RNG.randomGen()
    def getRandomData(numberOfBytes):
        
        random_bytes = b''
        while len(random_bytes) < numberOfBytes:
                element = random.choice(data)
                random_bytes += element
        return random_bytes

    key = RSA.generate(2048,getRandomData);

    privateKey = key.export_key()
    publicKey = key.public_key();

    with open("privateKey"+"_"+fileName+".pem","wb") as out:
        out.write(privateKey)

    with open("publicKey"+"_"+fileName+".pem","wb") as out:
        out.write(publicKey.export_key("PEM"))

    message = open(fileName,"rb").read()
    hash = SHA256.new(message)
    signer = PKCS115_SigScheme(key);
    signature = signer.sign(hash)
    with open("signature_"+fileName+".pem","wb") as out:
        out.write(signature)
        print("===================================")
        print ( "Generated!")
        print("===================================")

def verifySign(fileName,signature,pubKey): 
    message2 = open(fileName,"rb").read()
    hash2 = SHA256.new(message2)
    publKey = RSA.import_key(open(pubKey,"rb").read());
    verifier = PKCS115_SigScheme(publKey)

    try:
        verifier.verify(hash2,open(signature,"rb").read());
        print("===================================")
        print ( "The signature is valid")
        print("===================================")
    except:
        print("===================================")
        print ( "The signature is not valid")  
        print("===================================")


while(1):
    print("1. Generate keys and sign file");
    print("2. Vildate file sign")
    print("3. Exit ")
    option = input("Choose your option:")
    match option:
        case '1':
            fileName = input("Enter the name (with extension) of the file you want to sign. File must be in the same folder as script: ")
            generateAndSign(fileName)
        case '2':
            fileName = input("Enter the name (with extension) of the file you want verify sign. File must be in the same folder as script: ")
            signature = input("Enter the name of signature file. File must be in the same folder as script: ")
            pubKey = input("Enter the name of public key file. File must be in the same folder as script: ")
            verifySign(fileName,signature,pubKey)
        case '3':
            break

