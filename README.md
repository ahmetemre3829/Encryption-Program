# About the Project
## First Look
This project is a Python application that allows users to securely encrypt and decrypt their files. The program encrypts files using the XChaCha20-Poly1305 encryption algorithm and derives a 256-bit long key with the argon2 KDF algorithm. It also offers SHA-256 hash calculation to verify the integrity of the files.

## Features
* File Encryption:
Encrypts the user's selected file and saves the encrypted file with the .enc extension.
* File Decryption: Decrypts the encrypted file selected by the user.
* File Integrity Verification: Calculates and compares SHA-256 hash values of files.
* Chunk Size Setting: Ability to set the chunk size in MB to be used during operations.
* Random Key Generation: Allows the user to generate a random key of a specific length.
* Send message to producer: Allows you to provide feedback to the producer.

## Requirements
The following Python libraries are needed for this program to work:

* nacl: PyNaCl library, required for the XChaCha20-Poly1305 encryption algorithm.
* tkinter: Required for GUI components and file selection operations.
* colorama: Used for color output in the terminal.
* hashlib: Required for SHA-256 hash calculation.
* argon2: Required for argon2 KDF algorithm.
* msvcrt: Used for keyboard input control (only works on Windows systems). Also, Python 3.8 or higher must be installed.

## Installation
You can use the following commands to install the required libraries:

pip install pynacl, pip install colorama, pip install argon2-cffi ...

## Usage
The program can be run through the terminal. When run, it offers the user several options:

* Encrypt:
Selects the file to be encrypted and encrypts it.
* Decrypt:
Decrypts the encrypted file.
* Set Chunk Size:
Sets the chunk size to be used for encryption and decryption.
* File Integrity Verify: Calculates and compares SHA-256 hash values of files.
* How It Works:
Explains how the program works.
* Producer: Provides information about the producer of the program.
* Send message to producer:
Allows you to leave feedback to the producer.
* Exit:
Exits the program.

* Key Generation:
The program requests an encryption key from the user. The user can generate a random key of a certain length by entering the /generate key[x] command. For example, the command /generatekey16 generates a key 16 characters long.

* Chunk Size Setting:
The user can set the chunk size in MB. By default, the chunk size is set to 2 MB for encryption and decryption operations.

* File Integrity Verification: To verify file integrity, the user can calculate the SHA-256 hash value of the file and then compare this value. This feature is useful for checking if files have been modified.

## Example Usage
Encryption Run the program and select the encryption option by pressing "1". Select the file to be encrypted. Enter the encryption key (or generate a random key using the /generate key[x] command). When the encryption process is complete, the encrypted file is saved in the same directory with the .enc extension. Decryption Run the program and select the decryption option by pressing the "2" key. Select the file to be decrypted. Enter the decryption key. When the decryption process is complete, the decrypted file is saved in the same directory.

## License
This project is licensed under the MIT license. See the LICENSE file for details.
