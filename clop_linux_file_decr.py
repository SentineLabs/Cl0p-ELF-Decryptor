"""
Author:             @Tera0017/@SentinelOne
Description:        Clop-Linux ransomware variant files decryption.
Link:               https://s1.ai/Clop-ELF
Execution help:     $ python3 clop_linux_file_decr.py --help
"""
import argparse
import glob
import os.path
import struct
from arc4 import ARC4


def parse_arguments() -> argparse.Namespace:
    """
    Parses commandline parameters if any.
    @return: returns parse_args() result -> argparse.Namespace
    """
    description = """Python3 script which decrypts files encrypted by flawed Cl0p ELF variant.
    More info regarding Cl0p ELF variant and how decryptor was created at https://s1.ai/Clop-ELF
    """
    print('=' * 40)
    print('SentinelOne Cl0p ELF variant Decryptor.\nAuthor: @Tera0017/@SentinelOne\nLink: https://s1.ai/Clop-ELF')
    print('=' * 40)
    parser = argparse.ArgumentParser(
                        prog='clop_linux_file_decr.py',
                        description=description,
                        epilog='author:@Tera0017/@SentinelOne')

    parser.add_argument('--elfile', default=None, help='ELF Cl0p Binary, is used to retrieve "RC4 master key" else default is used for decryption.')
    parser.add_argument('--keys', default=None, help='File containing result of "$ find / -name *.$cl0p_extension -print 2>/dev/null > cl0p_keys.txt". Run with sudo if needed.')
    parser.add_argument('--rc4key', default=None, help='RC4 master key for decryption of clop key files. If --elf is provided script will dynamically retrieve it.')
    return parser.parse_args()


def message(msg: str) -> None:
    """
    @param msg: message to print
    @return: None
    """
    print(f'* {msg}')


class ClopELFDecryptor:
    def __init__(self, filepath=None, clop_find_file=None, rc4_master_key=None):
        """
        @param filepath: str, filepath of cl0p elf variant ransomware found in encrypted machine.
        @param clop_find_file: str, filepath containing result of "$ find / -name *.$cl0p_extension -print 2>/dev/null > clop_keys.txt"
        @param rc4_master_key: str, rc4 master key is not extracted well from cl0p elf binary.
        """
        # if elf sample does not exist tries with observed key.
        self.elfdata = open(filepath, 'rb').read() if filepath is not None else None
        # result of "$ find / -name *.$cl0p_extension -print 2>/dev/null > clop_keys.txt" containing clop keys
        self.clop_keys_file = clop_find_file
        self.rc4_master_key = rc4_master_key
        # clop filekeys extension.
        self.clop_ext = ".C_I_0P"
        # RC4 generated key size.
        self.rc4_gen_key_size = 0x75

    def get_rc4_master_key(self) -> bytes:
        """
        Retrieves RC4 master key from ELF binary. If elf is not found returns default observed key.
        @return: bytes, RC4 master key.
        """
        if self.rc4_master_key is not None:
            message('User provided RC4 master key')
            return self.rc4_master_key
        elif self.elfdata is None:
            message('Retrieved previous observed RC4 key.')
            # observed RC4 master key
            return b'Jfkdskfku2ir32y7432uroduw8y7318i9018urewfdsZ2Oaifwuieh~~cudsffdsd'
        # dirty way to retrieve master key.
        f = b'/root'
        idx = self.elfdata.find(f) + len(f) + 1
        return self.elfdata[idx: idx + 100].lstrip(b'\x00').split(b'\x00')[0]

    def get_clop_keys(self) -> list:
        """
        Based on the filekeys clop extension retrieves all the encrypted files from the machine.
        * If you need to speed up process add specific folders where encryption took place.
        * Or pass result of "$ find / -name *.$cl0p_extension -print 2>/dev/null > clop_keys.txt"
        as argument to "--keys".
        @return: list, encrypted filepaths
        """
        if self.clop_keys_file is not None:
            # get clop keys "$ find / -name *.$cl0p_extension -print 2>/dev/null > clop_keys.txt"
            with open(self.clop_keys_file, 'r') as hfile:
                lines = hfile.readlines()
            return [l.strip() for l in lines if l.strip()]

        # enumerate all folders and find clop extension files.
        message(f'Searching for encrypted file extension {self.clop_ext}.')
        message('This operation will take several minutes...')
        message('To speed up process prefer to use "--keys", parameter.')
        return glob.glob(f'/**/*{self.clop_ext}', recursive=True)

    def decrypt(self) -> None:
        """
        Main function decrypts Clop-ELF encrypted files.
        @return: None
        """
        message('Starting decryption process.')
        #   1. Retrieve RC4 "master-key".
        rc4_master_key = self.get_rc4_master_key()
        message(f'RC4 Master Key: "{rc4_master_key}"')
        #   2. Read all $filename.$clop_extension.
        file_keys = self.get_clop_keys()
        message(f'Encrypted Files: {len(file_keys)}')
        for file_key in file_keys:
            message(f'File: {file_key}')
            with open(file_key, 'rb') as hfile:
                file_key_data = hfile.read()
            #   3. Decrypt with RC4 using the RC4 "master-key", the generated RC4 key.
            cipher = ARC4(rc4_master_key)
            file_rc4_key = cipher.decrypt(file_key_data)[:self.rc4_gen_key_size]
            # getting encrypted file size (if file is written again after encryption then
            # encrypted_file_size != file_size
            size_off = 0x75 + 0x58 + 0x8 + 0x4 + 0x4
            try:
                encr_file_size = struct.unpack('Q', file_key_data[size_off: size_off + 0x8])[0]
            except struct.error:
                message(f'[ERROR] Clop key file seems corrupted: {file_key}')
                continue
            encr_file = file_key.replace(self.clop_ext, '')
            # decrypted files have extension '.decrypted_by_S1', once validated can delete and replace encrypted.
            decr_file = file_key.replace(self.clop_ext, '.decrypted_by_S1')
            if os.path.isfile(encr_file):
                with open(encr_file, 'rb') as hfile:
                    encr_file_data = hfile.read()
            else:
                message(f'[ERROR] Unable to find encrypted file: {encr_file}')
                continue
            #   4. Decrypt $filename with RC4 using the generated RC4 key.
            cipher = ARC4(file_rc4_key)
            decrypted_file_data = cipher.decrypt(encr_file_data[:encr_file_size]) + encr_file_data[encr_file_size:]
            #   5. Write decrypted to $filename.
            with open(decr_file, 'wb') as hfile:
                hfile.write(decrypted_file_data)
            message(f'Decrypted: {decr_file}')


if __name__ == '__main__':
    # parsing command line arguments for the decryptor. Use --help for more information
    parsed = parse_arguments()
    ClopELFDecryptor(parsed.elfile, parsed.keys, parsed.rc4key).decrypt()