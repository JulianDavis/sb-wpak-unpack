#!/usr/bin/env python3

import blowfish
from pathlib import Path
import argparse
import zipfile

BLOWFISH_KEY = b'\x85\x71\x40\x3C\x14\x50\x0B\x52\x73\x2D\x10\x08\x63\x59\x5B\xAA'
BLOWFISH_IV_LEN = 8
BLOWFISH_CIPHER = blowfish.Cipher(BLOWFISH_KEY)

def unzip(src_file, dest_dir):
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(src_file, 'r') as zip_file:
        zip_file.extractall(dest_dir)

def decrypt_dir(dir):
    for file in dir.iterdir():
        if file.suffix == '.zip' or file.suffix == '.txt':
            print(f'File "{file}" is a zip or txt file')
            continue

        plaintext = decrypt_file(file)
        with open(file, 'w', encoding='utf-8') as f:
            f.write(plaintext)
        print(f'Unpacked: "{file}"')

def decrypt_file(filepath):
    with open(filepath, 'rb') as encrypted:
        ciphertext = encrypted.read()

        # Decrypt first 8-bytes with zero IV
        first_block = b''.join(BLOWFISH_CIPHER.decrypt_cfb(
            ciphertext[:BLOWFISH_IV_LEN],
            b'\x00' * BLOWFISH_IV_LEN
        ))

        # Decrypt remainder using first 8 bytes of ciphertext as IV
        remainder = b''.join(BLOWFISH_CIPHER.decrypt_cfb(
            ciphertext[BLOWFISH_IV_LEN:],
            ciphertext[:BLOWFISH_IV_LEN]
        ))

        try:
            return (first_block + remainder).decode('utf-8')
        except UnicodeDecodeError:
            print(f'Failed to decrypt "{filepath}"')
            return ''

def main():
    parser = argparse.ArgumentParser(
        description='Decrypt WPAK files associated with the game Shadowbane'
    )
    parser.add_argument(
        'filepath',
        type=str,
        help='Filepath of the WPAK file to unpack'
    )
    parser.add_argument(
        '-o',
        '--output_dir',
        type=str,
        default=None,
        help='Optional output directory. Defaults to same directory as WPAK file if not specified.'
    )
    args = parser.parse_args()

    wpak_file = Path(args.filepath)
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        out_dir = wpak_file.with_suffix('')

    unzip(wpak_file, out_dir)
    decrypt_dir(out_dir)

if __name__ == "__main__":
    main()
