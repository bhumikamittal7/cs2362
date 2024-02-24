import json
import string
import random
import math
from tqdm import tqdm
import utils

DICTIONARY_PATH = './data/moby_dick_dictionary.json'


class Quipster:
    def __init__(self, num_trials=15, num_swaps=10**4, converge_swaps=2):
        self.num_trials = num_trials
        self.num_swaps = num_swaps
        self.converge_swaps = converge_swaps

        self.vocabulary = list(string.ascii_lowercase)
        self.key = self.vocabulary.copy()

        self.corpus = self.load_corpus(path=DICTIONARY_PATH)

    def load_corpus(self, path):
        """Load frequencies of common words and bigrams from Moby Dick"""
        with open(path, 'r') as f:
            return json.load(f)

    def score(self, candidate):
        """Score is a running sum of frequencies of phrases/bigrams occurring
        in the corpus which appear in the decrypted cipher"""
        score = sum(candidate.count(k) * self.corpus[k] for k in self.corpus)
        return score

    def fit(self, cipher):
        """Main cryptanalysis loop"""
        ciphertext = cipher
        cipher = utils.preprocess(cipher, self.vocabulary)

        convergence_count = 0
        best_score = -math.inf

        for i in range(self.num_trials):
            print('Trial {}/{}'.format(i, self.num_trials))

            key = self.vocabulary.copy() if convergence_count < 10 else utils.swap(self.key, n=self.converge_swaps*2)
            trial_convergence_count = 0
            best_trial_score = -math.inf

            for j in tqdm(range(self.num_swaps)):
                new_key = utils.swap(key, n=self.converge_swaps) if trial_convergence_count < 100 else utils.swap(key, n=self.converge_swaps*3)
                candidate = utils.transform(cipher, new_key, self.vocabulary)
                score = self.score(candidate)

                if score > best_trial_score:
                    key, best_trial_score = new_key, score
                else:
                    trial_convergence_count += 1

            if best_trial_score > best_score:
                self.key, best_score = key.copy(), best_trial_score
            else:
                convergence_count += 1

            print('\nBest Score {}'.format(best_score))
            plaintext = self.decode(ciphertext)
            print('Current Decryption \n {}'.format(plaintext))

        return key

    def decode(self, cipher):
        """Transform cipher text given the fitted model"""
        cipher = cipher.lower()
        return utils.transform(cipher, self.key, self.vocabulary)
