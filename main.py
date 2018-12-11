import argparse
from fileutils import *


def test():
    ensure_rsa_keys_exists()

    TEST_FILE = "data/filetoencrypt.txt"
    TEST_JSON = TEST_FILE + ".json"

    # Reads the test file, encrypts (but doesn't delete) it.
    encrypt_file(TEST_FILE, TEST_JSON)

    # Reads the encrypted json file, decrypts (but doesn't delete) it.
    decrypt_file(TEST_JSON, TEST_FILE + "_output.txt")

    # For now, just remove one of these to see it work. I'll eventually add command line args to select
    encrypt_all_files(constants.ROOT_FOLDER)
    decrypt_all_files(constants.ROOT_FOLDER)


def ui():
    parser = argparse.ArgumentParser(description='TRAD\'s File Encryption.')  # TODO: Finish the description

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action="store_true",
                       help='Encrypt the specified file(s)')

    group.add_argument('-d', '--decrypt', action="store_true",
                       help='Decrypt the specified files')

    parser.add_argument('path', type=lambda x: verify_path(parser, x), default=constants.ROOT_FOLDER,
                        help='either a single file or the root directory to traverse (default: "' + constants.ROOT_FOLDER + '")')

    parser.add_argument('--key-private', default=constants.RSA_PRIVATEKEY_FILEPATH,
                        help='Path of private RSA key. If one doesn\'t exist here it will be created. (default: "' + constants.RSA_PRIVATEKEY_FILEPATH + '")')
    parser.add_argument('--key-public', default=constants.RSA_PUBLICKEY_FILEPATH,
                        help='Path of public RSA key. If one doesn\'t exist here it will be created. (default: "' + constants.RSA_PUBLICKEY_FILEPATH + '")')

    args = parser.parse_args()

    # Set up arguments
    rootdir = args.path
    constants.RSA_PRIVATEKEY_FILEPATH = args.key_private  # TODO I shouldn't be changing constants. Need to rework methods to include an optional parameter
    constants.RSA_PUBLICKEY_FILEPATH = args.key_public

    # Perform encryption/decryption
    ensure_rsa_keys_exists()

    if path.isdir(rootdir):
        if args.encrypt:
            encrypt_all_files(rootdir=rootdir)
        if args.decrypt:
            decrypt_all_files(rootdir=rootdir)
    else:  # TODO: Finish single file encryption/decryption
        if args.encrypt:
            encrypt_file()
        if args.decrypt:
            decrypt_file()


def verify_path(parser, arg):
    if not path.exists(arg):
        parser.error("The path %s does not exist" % arg)
    else:
        return path.abspath(arg)

ui()
