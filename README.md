# Gontko Security Password Manager
Password manager as a personal project to get better in coding and understanding cryptography.

# Features
* Encryption/Decryption for passwords storage (AES256)
  * combination of a master password, secret.key file and salt
* Master key stored as a hash (SHA256) 
  * combination of master password, master_secret.key file and salt
* Password generator 
* Password strength meter
* Check if password has been pwned
* GUI

# Installation
1. Clone the repository to your computer via `git clone https://github.com/filipgontko/Password-Manager.git`
2. Run `pip install -r requirements.txt`

# Run 
Run the `main.py` script in the project directory.
```sh
$ python main.py
```
**_NOTE:_** Do not share **secret.key**, **master_secret.key**, **master_key_salt.bin** and **pwdmngrdb.db** as they contain sensitive 
information.

# Author
* [Filip Gontko](https://github.com/filipgontko)