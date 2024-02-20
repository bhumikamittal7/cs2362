import argparse
from pprint import pprint

import utils
from quipster import Quipster

def save_plaintext_to_file(output_path, decrypted_text):
    """Save decrypted plaintext to a file."""
    print("Saving plaintext to {}".format(output_path))
    with open(output_path, 'w') as file:
        file.write(decrypted_text)

def main(args):
    if args.ciphertext_path is not None:
        cipher = utils.load_file(args.ciphertext_path)
        plaintext = 'Plaintext not provided'
    elif args.plaintext_path is not None:
        plaintext = utils.load_file(args.plaintext_path)
        cipher = utils.generate_cipher(plaintext)
    else:
        raise Exception('Must specify either --ciphertext_path or --plaintext_path')

    # Instantiate and fit the Quipster substitution cipher solver
    cryptanalyzer = Quipster(
        args.num_trials,
        args.num_swaps,
        args.converge_swaps
    )
    key = cryptanalyzer.fit(cipher)
    decrypted = cryptanalyzer.decode(cipher)

    print("\nPlaintext:\n")
    pprint(plaintext)
    
    utils.print_stdout(cipher, decrypted, key, cryptanalyzer.vocabulary)

    help_the_algorithm = input('\nWould you like to manually help the algorithm? (y/n) ').lower()

    if help_the_algorithm == 'y':
        cryptanalyzer = utils.user_interaction(cryptanalyzer, cipher)
    
    decrypted = cryptanalyzer.decode(cipher)
    utils.print_stdout(cipher, decrypted, cryptanalyzer.key, cryptanalyzer.vocabulary)
    
    save_plaintext_to_file(args.output, decrypted)
