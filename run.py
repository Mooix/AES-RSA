import RSA
import AES
from pyfiglet import figlet_format
import pyfiglet
from termcolor import colored
def main():
    while True:
        print("------------------------------------------------------------------")
        print("|                    Welcome to our program!                     |")
        print("| We provide two algorithms for encryption and decryption        |")
        print("| Also we can generate a key for you!                            |")
        print("| Which Algorithm you want to use?                               |")
        print("|                 Enter '1' if you want to use AES               |")
        print("|                 Enter '2' if you want to use RSA               |")
        print("|                 Enter '0' if you want to Exit                  |")
        print("------------------------------------------------------------------")
        choice = input("Your choice: ")
        print("------------------------------------------------------------------")
        if choice == "1":
            AES.main()
        elif choice == "2":
            RSA.main()
        elif choice == "0":
            exit()
        else:
            print(colored("Wrong choice. Please enter the number from the following choices:", "red"))

if __name__ == "__main__":
    main()