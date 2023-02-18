import rsa
import time
import struct
import struct
import base64
import hashlib
import run 
from pyfiglet import figlet_format
from termcolor import colored

# Generate the keys
def generate_keys(public_filepath,private_filepath):
    (pub_key, priv_key) = rsa.newkeys(512)
    with open(public_filepath+'.pem', 'wb') as p:
        p.write(pub_key.save_pkcs1('PEM'))
    with open(private_filepath+'.pem', 'wb') as p:
        p.write(priv_key.save_pkcs1('PEM'))
    return pub_key, priv_key

def loadPublicKey(public_filepath):
    with open(public_filepath, 'rb') as pu:
        publicKey = rsa.PublicKey.load_pkcs1(pu.read())
    return publicKey

def loadPrivateKey(private_filepath):
    with open(private_filepath, 'rb') as pr:
        privateKey = rsa.PrivateKey.load_pkcs1(pr.read())
    return  privateKey

def encrypt_file(old_file_path,new_file_path, pub_key, chunk_size=10):
    with open(old_file_path, 'rb') as f:
        plaintext = f.read()
    encrypted = []
    start_time = time.time()
    for i in range(0, len(plaintext), chunk_size):
        chunk = plaintext[i:i+chunk_size]
        encrypted.append(rsa.encrypt(chunk, pub_key))
    end_time = time.time()
    timeInMill = (end_time - start_time) * 1000
    print("The algorithm took", format(timeInMill, '.2f'), "milliseconds to encrypt the file")
    with open(new_file_path, 'wb') as f:
        for c in encrypted:
            f.write(struct.pack('!I', len(c)))
            f.write(c)
    with open(new_file_path, 'rb') as f:
        ciphertext = f.read()
    with open(new_file_path, 'wb') as f:
        f.write(base64.b64encode(ciphertext))
    f.close()  
    return encrypted, new_file_path

def decrypt_file(old_file_path,new_file_path, priv_key):
    with open(old_file_path, 'rb') as f:
        ciphertext = base64.b64decode(f.read())
        encrypted = []
        while True:
            chunk_len_bytes = ciphertext[:4]
            ciphertext = ciphertext[4:]
            if len(chunk_len_bytes) == 0:
                break
            chunk_len = struct.unpack('!I', chunk_len_bytes)[0]
            encrypted.append(ciphertext[:chunk_len])
            ciphertext = ciphertext[chunk_len:]
    decrypted = b''
    start_time = time.time()
    for chunk in encrypted:
        decrypted += rsa.decrypt(chunk, priv_key)
    end_time = time.time()
    timeInMill = (end_time - start_time) * 1000
    print("The algorithm took", format(timeInMill, '.2f') ,"milliseconds to decrypt the file")
    with open(new_file_path, 'wb') as f:
        f.write(decrypted)
    f.close()

    return decrypted,new_file_path

def sign(file_name, new_file_path, private_key):
    with open(file_name, 'rb') as f:
        file_data = f.read()
    file_hash = hashlib.sha256(file_data).digest()
    signature = rsa.sign(file_hash, private_key, 'SHA-256')
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    with open(new_file_path , 'w') as f:
        f.write(signature_b64)
    return signature_b64, new_file_path

def verify(filename, signature_file,public_key):
    with open(filename, 'rb') as f:
        file_data = f.read()
    file_hash = hashlib.sha256(file_data).digest()
    with open(signature_file , 'rb') as f:
        signature = f.read()
    signature_bytes = base64.b64decode(signature)
    try:
        rsa.verify(file_hash, signature_bytes, public_key)
        print("Signature is valid")
    except:
        print("Signature is not valid")


#######################################################################################################################

is_generator = False
pub_key_generated = ""
pri_key_generated = ""
def choice_generate_key():
    global is_generator
    global pub_key_generated
    global pri_key_generated
    print("Okay, we will generate a public key and a private key for you. Please be careful not to share your private key.")
    print("Before we generate your keys, pick a name for your public key and a name for your private key")
    while True:
        pub_filepath = input("Please enter a file name for your public key (we will save your key with the '.pem' extension): ")
        if pub_filepath:
            print(colored("Great! Now please enter the file name for your private key.", "green"))
            while True:
                priv_filepath = input("Enter the file path for your private key: ")
                if priv_filepath:
                    print(colored("We will generate your keys now! Please wait a few seconds.", "blue"))
                    pub_key, priv_key = generate_keys(pub_filepath,priv_filepath)
                    print(colored(f"Your Public key saved successfully in: {pub_filepath}.pem", "green"))
                    print(colored(f"Your Private key saved successfully in: {priv_filepath}.pem", "green"))
                    is_generator = True
                    pub_key_generated = pub_filepath+".pem"
                    pri_key_generated = priv_filepath+".pem"
                    check = input ("Do you want another service? [y,n] ")
                    if(check == "n"):
                        exit()
                    elif(check == "y"):
                        break
                    else:
                        print(colored("Incorrect choice. Returning to the menu.", "red"))
                        break
                else:
                    print(colored("Plaese enter your file name for the private key", "yellow"))
            break
        else:
            print(colored("Plaese enter your file name for the public key", "yellow"))

def choice_encryption():
    global is_generator
    global pub_key_generated
    global pri_key_generated
    print("Before we encrypt the file, we would like you to provide us with some information")
    while True:
        if(not is_generator):
            have_key = input("Do you have a public and private key? [y,n] ")
            if have_key == "y":
                while True:
                    file_path = input("Enter the file path you want to encrypt: ")
                    if file_path:
                        while True:
                            pub_filepath = input("Enter the file path for your public key: ")
                            if pub_filepath:
                                while True:
                                    new_filepath = input("What do you want the name of the encrypted file to be? For example, 'encrypted_file.txt': ")
                                    if new_filepath:
                                        print(colored("We will encrypt your file now! Please wait a few seconds.", "blue"))
                                        try:  
                                            pub_key = loadPublicKey(pub_filepath)
                                            encrypted_message, encrypted_file_path = encrypt_file(file_path, new_filepath,pub_key)
                                            print(colored(f"The encrypted file is saved as: {encrypted_file_path}", "green"))
                                            break 
                                        except:
                                            print(colored("Something went wrong. Please check your key and your file, and try again.", "red"))
                                            break
                                    else:
                                        print(colored("Please enter the encrypted file name", "yellow"))
                                break 
                            else:
                                print(colored("Plaese enter your file name for the public key", "yellow"))
                        check = input ("Do you want another service? [y,n] ")
                        if(check == "n"):
                            exit()
                        elif(check == "y"):
                            break
                        else:
                            print(colored("Incorrect choice. Returning to the menu.", "red"))
                            break 
                    else:
                        print(colored("Plaese enter your file path you want to encrypt", "yellow"))
                break 
            elif have_key == "n":
                choice_generate_key()
                break
            else:
                print(colored("Incorrect choice. Returning to the menu.", "red"))
        else:
            key_question = input("Would you like to use a previously generated keys? [y,n] ")
            if key_question == "y":
                while True:
                    file_path = input("Enter the file path you want to encrypt: ")
                    if file_path:
                        while True:
                            new_filepath = input("What do you want the name of the encrypted file to be? For example, 'encrypted_file.txt': ")
                            if new_filepath:
                                print(colored("We will encrypt your file now! Please wait a few seconds.", "blue"))
                                try:  
                                    pub_key = loadPublicKey(pub_key_generated)
                                    encrypted_message, encrypted_file_path = encrypt_file(file_path, new_filepath,pub_key)
                                    print(colored(f"The encrypted file is saved as: {encrypted_file_path}", "green"))
                                except:
                                    print(colored("Something went wrong. Please check your key and your file, and try again.", "red"))
                            else:
                                print(colored("Please enter the encrypted file name", "yellow"))
                            check = input ("Do you want another service? [y,n] ")
                            if(check == "n"):
                                exit()
                            elif(check == "y"):
                                break 
                            else:
                                print(colored("Incorrect choice. Returning to the menu.", "red"))
                                break 
                        break 
                    else:
                        print(colored("Plaese enter your file path you want to encrypt", "yellow"))
                break
            elif key_question == "n":
                    is_generator = False
            else:
                print(colored("Incorrect choice. Returning to the menu.", "red"))
                break

def choice_decryption():
    print("Before we decrypt the file, we would like you to provide us with some information")
    while True:
        file_path = input("Enter the file path you want to decrypt: ")
        if file_path:
            while True:
                priv_filepath = input("Enter the file path for your private key: ")
                if priv_filepath:
                    while True:
                        new_filepath = input("What do you want the name of the decrypted file to be? For example, 'decrypted_file.txt': ")
                        if new_filepath:
                            print(colored("We will decrypt your file now! Please wait a few seconds.", "blue"))
                            try: 
                                priv_key = loadPrivateKey(priv_filepath)
                                decrypt_message,decrypted_file_path = decrypt_file(file_path,new_filepath, priv_key)
                                print(colored(f"The decrypted file is saved as: {decrypted_file_path}", "green"))
                            except:
                                print(colored("Something went wrong. Please check your key and your file, and try again.", "red"))
                            check = input ("Do you want another service? [y,n] ")
                            if(check == "n"):
                                exit()
                            elif(check == "y"):
                                break
                            else:
                                print(colored("Incorrect choice. Returning to the menu.", "red"))
                                break
                        else:
                            print(colored("Please enter the decrypted file name :)", "yellow"))
                    break
                else:
                    print(colored("Plaese enter your file name for the private key :)", "yellow"))
            break 
        else:
            print(colored("Plaese enter your file path you want to decrypt :)", "yellow"))

def choice_sign():
    print("Before we sign the file, we would like you to provide us with some information")
    while True:
        file_path = input("Enter the file path you want to sign: ")
        if file_path:
            while True:
                priv_filepath = input("Enter the file path for your private key: ")
                if priv_filepath:
                    while True:
                        new_filepath = input("What do you want the name of the signed file to be? For example, 'signed_file.txt': ")
                        if new_filepath:
                            print(colored("We will signed your file now! Please wait a few seconds.", "blue"))
                            try:  
                                priv_key = loadPrivateKey(priv_filepath)
                                signiture, Signed_file_path = sign(file_path,new_filepath, priv_key)
                                print(colored(f"The signed file is saved as: {Signed_file_path}", "green"))
                            except:
                                print(colored("Something went wrong. Please check your key and your file, and try again.", "red"))
                            check = input ("Do you want another service? [y,n] ")
                            if(check == "n"):
                                exit()
                            elif(check == "y"):
                                break
                            else:
                                print(colored("Incorrect choice. Returning to the menu.", "red"))
                                break
                        else:
                            print(colored("Please enter the signed file name :)", "yellow"))
                    break 
                else:
                    print(colored("Plaese enter your file name for the private key :)", "yellow"))
            break
        else:
            print(colored("Plaese enter your file path you want to sign :)", "yellow"))

def choice_verify():
    print("Before we verify the file, we would like you to provide us with some information")
    while True:
        file_path = input("Enter the file path you want to verify: ")
        if file_path:
            while True:
                Signed_file_path = input("Enter the file path that has been signed to verify: ")
                if Signed_file_path:
                    while True:
                        pub_filepath = input("Enter the file path for your public key: ")
                        if pub_filepath:
                            print(colored("We will verify your file now! Please wait a few seconds.", "blue"))
                            try:  
                                pub_key = loadPublicKey(pub_filepath)
                                verify(file_path,Signed_file_path, pub_key)
                            except:
                                print(colored("Something went wrong. Please check your key and your file, and try again.", "red"))
                            check = input ("Do you want another service? [y,n] ")
                            if(check == "n"):
                                exit()
                            elif(check == "y"):
                                break
                            else:
                                print(colored("Incorrect choice. Returning to the menu.", "red"))
                                break
                        else:
                            print(colored("Plaese enter your file name for the public key :)", "yellow"))
                    break 
                else:
                    print(colored("Plaese enter the file path that has been signed to verify :)", "yellow"))
            break 
        else:
            print(colored("Plaese enter your file path you want to verify :)", "yellow"))


def main():
    print( figlet_format('RSA', font="starwars")) 
    while True:
        print("---------------------------------------------------------------")
        print("Welcome to our RSA Algorithm, let us help you:")
        print("Enter '1' if you want to generate key between you and your friend: ")
        print("Enter '2' if you want to encrypt your file:")
        print("Enter '3' if you want to decrypt your file: ")
        print("press '4' if you want to sign your file:")
        print("press '5' if you want to verify your file: ")
        print("Enter '6' if you want to back to the previous menu: ")
        print("Enter '0' if you want to exit: ")
        choice = input("Your choice: ")   
        if choice == "1":
            choice_generate_key()
        elif choice == "2":
            choice_encryption()
        elif choice == "3":
            choice_decryption()
        elif choice == "4":
            choice_sign()
        elif choice == "5":
            choice_verify()
        elif choice == "6":
            run.main()
        elif choice == "0":
            exit()
        else:
            print(colored("Wrong choice. Please enter the number from the following choices:", "red"))