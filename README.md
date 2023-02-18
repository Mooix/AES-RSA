# AES-RSA
This repository contains an implementation of the AES-RSA encryption and decryption algorithms. Also Generate keys.

# Libraries

- <b>AES</b>: The Advanced Encryption Standard (AES) is a symmetric-key encryption algorithm designed to provide strong encryption and confidentiality of data.
It operates on fixed block sizes of 128 bits and uses a variable-length key of 128, 192, or 256 bits. Since AES algorithm is a symmetric key cipher, the same key is used for both encryption and decryption.
To implement AES in our program we used Crypto.Cipher library that provide encryption and decryption using various modes of operation such as Electronic Codebook (ECB), Cipher Block Chaining (CBC), and Galois Counter Mode (GCM). 
We used the Cipher Block Chaining (CBC) mode for our AES encryption and decryption, which operates as shown in the figure below.

![alt CBC_Mode](cbc_encryption.png)
 
In CBC mode, each plaintext block is XORed with the previous ciphertext block before encryption. 
The first plaintext block is XORed with a random initialization vector (IV) before encryption. 
The ciphertext output from each block is used as the input for the next block in the encryption process. 
This helps to make the encryption more secure and to avoid repeating patterns in the ciphertext.
During decryption, the ciphertext block is decrypted and then XORed with the previous ciphertext block to recover the original plaintext. 
The IV is used to decrypt the first block of ciphertext.

- RSA: we used this used for implementing RSA encryption and decryption. 
It provides functions for generating RSA key pairs, encrypting, and decrypting data using RSA, signing and verifying data using RSA, and more.

- Struct: This library has been used for working with binary data in Python. 
It provides functions for packing and unpacking data into and from the binary format, which can be useful for working with file formats.

- Hashlib: we used this library for generating hash values for data. It helps us with verifying the message. 
A hash value is a fixed-length string of characters that represents the input data and can be used for verifying the integrity of the data or ensuring that two sets of data are identical.

- Pyfiglet: is a Python library that allows us to create ASCII art from text using various fonts. 
It is a simple and easy-to-use tool for generating stylish and eye- catching headers, banners, or logos in the terminal. 
The library has a wide range of font styles, making it easy to create various text-based designs, and supports both horizontal and vertical layouts.

- Termcolor: is a Python library that allows us to add colors and text formatting to the output in the terminal.

- Base64:
  - B64encode:is afunction that takes binary data as input and encodes it into a Base64 encoded string. 
    The output is a string that contains only ASCII characters. The function also supports adding padding characters to the output to ensure that the length of the output string is a multiple of four.
  - B64decode: is a function that takes a Base46 encoded string as input and decodes it back into the original binary data, and the output is a bytes object.
  
- Time: is a Python library that allows us to calculate time, we used it to calculate the time of encryption and decryption for each algorithm.

- Crypto.Util.Padding: is a python library that provides padding functions to add or remove the padding from byte strings.
  - Pad: it is used to add padding to a byte string. It takes two arguments: the byte string to be padded and the block size in bytes. 
    The function returns a new byte string with the appropriate padding added to the input data. 
    The padding is based on the PKCS7 standard, which adds a number of bytes equal to the number of bytes required to make the input data a multiple of the block size.
  - Unpad: it is used to remove the padding from a byte string. 
    It takes two arguments: the byte string from which padding is to be removed and the block size in bytes. 
    The function returns a new byte string with the padding removed.
    
- Secrets: is a Python library we used it in AES to generate cryptographically secure random numbers suitable for generating secret keys.
