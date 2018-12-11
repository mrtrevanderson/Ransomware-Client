# CSULB CECS378 Lab

https://tradlab.me

## File Encryption
Using Python [Cryptography](https://cryptography.io/en/latest/hazmat/primitives/), these modules encrypt and decrypt a message or file.

File contents are encrypted with AES-256 in CBC mode and a randomly generated key. The encryption and HMAC keys are encrypted with RSA. Along with the ciphertext of the file contents, they are stored on the disk and the original file is removed.  

### Try it out
Grab the executables from the [releases](https://github.com/adriancampos/CECS378-Lab/releases/latest) page.

Create a folder called dangerzone. Place some files in there. Please don't place anything important inside; it might not make it out.

encrypt.exe generates a public/private keypair, encrypts files (recursively) within ./dangerzone.

decrypt.exe reads the public/private keypair, decrypts files (recursively) within ./dangerzone.


### Building the executables
`pyinstaller --onefile decrypt.py` and `pyinstaller --onefile encrypt.py` generate executables in ./dist/


## File Encryption with a RESTful server
`networkencrypt.py` and `networkdecrypt.py` are similar to `encrypt.py` and `decrypt.py`, but they rely on an [external server](https://github.com/adriancampos/CECS378-Ransomware-Server) to store the private key.

As soon as the keys are generated, networkencrypt posts the public and private keys to the server in PEM format, encoded in base64. If the post is successful, the private key is deleted from the victim machine.

Without the private key, the files cannot be decrypted. To retrieve it from the server, `networkdecrypt.py` reads the public key from the disk and uses it to query the server. If it's given a successful response, it saves it to a file and decrypts.

Be sure to update `NETWORK_HOST` in `constants.py` to match your server.

TODO: Add an app key