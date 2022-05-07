# Gontko Security Password Manager
Password manager as a personal project to get better in coding and understanding cryptography.

# Features
* Encryption/Decryption for passwords storage (AES-256)
  * combination of a master password, secret key and salt
* Master key stored as a hash (SHA-256) 
  * combination of master password, master secret key, username of currently logged-in user on a computer and salt
* Password generator 
* Password strength meter
* Check if password has been pwned
* GUI

# Installation
1. Download and install [Python 3](https://www.python.org/) if you don't have it installed already.
   1. WINDOWS: On the installation screen, check the option to automatically set path (to use pip).
   2. UNIX: `sudo apt -y install python3-pip` to install pip3.
2. Clone the repository to your computer via `git clone https://github.com/filipgontko/Gontko-Security-Password-Manager.git` or download it as a ZIP file from `https://github.com/filipgontko/Gontko-Security-Password-Manager`
3. Change you current working directory the downloaded file and run `pip3 install -r requirements.txt`

# Run 
Run the `main.py` script in the project directory via command line (Run with the alias you chose for python3)
```sh
$ python main.py
```
or double click the `main.py` script.

**_NOTE:_** Do not share **master_key_salt.bin**, **chacha20_key.bin** and **pwdmngrdb.db** as they contain sensitive 
information.

# Author
* [Filip Gontko](https://github.com/filipgontko)
