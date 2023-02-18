from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
import time
import secrets
import run
from pyfiglet import figlet_format
from termcolor import colored
import base64
import string


def generate_readable_aes_key(length):
    """Generate a random, readable AES key with the specified length"""
    alphabet = string.ascii_letters + string.digits
    gkey = ''.join(secrets.choice(alphabet) for i in range(length))
    return gkey.encode()

def generate_aes_key():
    """Generate a 128-bit AES key"""
    gkey = secrets.token_bytes(32)
    return gkey

def encrypt(plain_text,aesKey):
    if len(aesKey) != 32:
        aesKey = pad(aesKey, AES.block_size)
    cipher = AES.new(aesKey, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plain_text, AES.block_size))
    iv = b64encode(cipher.iv).decode("UTF-8")
    ciphertext = b64encode(ciphertext).decode("UTF-8")
    return iv + ciphertext

def decrypt(data,aesKey, length):
    if len(aesKey) != 32:
        aesKey = pad(aesKey, AES.block_size)
    iv = data[:24]
    iv = b64decode(iv)
    ciphertext = data[24:length]
    ciphertext = b64decode(ciphertext)
    cipher = AES.new(aesKey, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted,AES.block_size)
    return decrypted

def decryptFile(file_path, keyShared, dec_filepath):
    start_time = time.time()
    with open(file_path, 'rb') as f:
        data = f.read()
    with open(keyShared, "rb") as f:
        key = f.read()
    length = len(data)
    decrypted_data = decrypt(data, key, length)
    end_time = time.time()
    with open(dec_filepath, 'wb') as f:
        f.write(decrypted_data)
    print("The algorithm took", format((end_time - start_time)*1000, '.2f')  ,"milliseconds to decrypt the file")
    return file_path[:-4]

def encryptFile(file_path, keyShared, enc_filepath):
    start_time = time.time()
    with open(file_path, 'rb') as f:
        data = f.read()
    with open(keyShared, "rb") as f:
        key = f.read()
    encrypted_data = encrypt(data, key)
    end_time = time.time()
    with open(enc_filepath, 'wb') as f:
        f.write(encrypted_data.encode("utf-8"))
        # f.write(base64.b64encode(encrypted_data))
    print("The algorithm took", format((end_time - start_time)*1000, '.2f')  ,"milliseconds to encrypt the file")
    return enc_filepath


#######################################################################################################################

is_generator = False
key_generated = ""
def choice_generate_key():
    global is_generator
    global key_generated
    print("Okay, we will generate a key for you. Please be careful not to share your key!")
    print("Before we generate your key, pick a name for your key")
    while True:
        key_path = input("Please enter a file name for your key (we will save your key with the '.pem' extension): ")
        if key_path:
            print(colored("We will generate your key now! Please wait a few seconds.", "blue"))
            newKey = generate_readable_aes_key(32)
            with open(key_path+".pem", 'wb') as f:
                f.write(newKey)
                print(colored(f"Your key saved successfully in: {key_path}.pem", "green"))
                is_generator = True
                key_generated = key_path+".pem"
            check = input ("Do you want another service? [y,n] ")
            if(check == "n"):
                exit()
            elif(check == "y"):
                break
            else:
                print(colored("Incorrect choice. Returning to the menu.", "red"))
                break
        else:
            print(colored("Plaese enter your file name for the key", "yellow"))

def choice_encryption():
    global is_generator
    global key_generated
    print("Before we encrypt the file, we would like you to provide us with some information")
    while True:
        if(not is_generator):
            have_key = input("Do you have a key? [y,n] ")
            if have_key == "y":
                while True:
                    file_path = input("Enter the file path you want to encrypt: ")
                    if file_path:
                        while True:
                            key = input("Please enter the path for the key you wish to use for encryption: ")
                            if key:
                                while True:
                                    enc_filepath = input("What do you want the name of the encrypted file to be? For example, 'encrypted_file.txt': ")
                                    if enc_filepath:
                                        print(colored("We will encrypt your file now! Please wait a few seconds.", "blue"))
                                        try:
                                            encryptFile(file_path, key, enc_filepath)
                                            print(colored(f"The encrypted file is saved as: {enc_filepath}", "green"))
                                            break
                                        except:
                                            print(colored("Something went wrong. Please check your key and your file, and try again.", "red"))
                                            break
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
                                print(colored("Plaese enter your file name for the key", "yellow"))
                        break 
                    else:
                        print(colored("Please enter the file path you want to encrypt.", "yellow"))
                break 
            elif have_key == "n":
                choice_generate_key()
                break
            else:
                print(colored("Incorrect choice. Returning to the menu.", "red"))
                break
        else:
            key_question = input("Would you like to use a previously generated key? [y,n] ")
            if key_question == "y":
                while True:
                    file_path = input("Enter the file path you want to encrypt: ")
                    if file_path:
                        try:
                            with open(key_generated, 'rb') as f:
                                data = f.read()
                            while True:
                                enc_filepath = input("What do you want the name of the encrypted file to be? For example, 'encrypted_file.txt': ")
                                if enc_filepath:
                                    print(colored("We will encrypt your file now! Please wait a few seconds.", "blue"))
                                    try:
                                        encryptFile(file_path, key_generated, enc_filepath)
                                        print(colored(f"The encrypted file is saved as: {enc_filepath}", "green"))
                                        break
                                    except:
                                        print(colored("Something went wrong. Please check your key and your file, and try again.", "red"))
                                        break
                                else:
                                    print(colored("Please enter the encrypted file name", "yellow"))
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
                        break 
                    else:
                        print(colored("Please enter the file path you want to encrypt.", "yellow"))
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
                key = input("Please enter the path for the key you wish to use for decryption: ")
                if key:
                    while True:
                        dec_filepath = input("What do you want the name of the decrypted file to be? For example, 'decrypted_file.txt': ")
                        if dec_filepath:
                            print(colored("We will decrypt your file now! Please wait a few seconds.", "blue"))
                            try:
                                decryptFile(file_path, key, dec_filepath)
                                print(colored(f"The decrypted file is saved as: {dec_filepath}", "green"))
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
                    print(colored("Plaese enter your file name for the key :)", "yellow"))
            break 
        else:
            print(colored("Plaese enter your file path you want to decrypt :)", "yellow"))


def main():
    print( figlet_format('AES', font="starwars"))
    while True:
        print("---------------------------------------------------------------")
        print("Welcome to our AES Algorithm, let us help you: ")
        print("Enter '1' if you want to generate key between you and your friend: ")
        print("Enter '2' if you want to encrypt your file: ")
        print("Enter '3' if you want to decrypt your file: ")
        print("Enter '4' if you want to back to the previous menu: ")
        print("Enter '0' if you want to exit: ")
        choice = input("Your choice: ")
        if(choice == "1"):
            choice_generate_key()
        elif choice == "2":
            choice_encryption()
        elif choice == "3":
            choice_decryption()
        elif choice == "4":
            run.main()
        elif choice == "0":
            exit()
        else:
            print(colored("Wrong choice. Please enter the number from the following choices:", "red"))

