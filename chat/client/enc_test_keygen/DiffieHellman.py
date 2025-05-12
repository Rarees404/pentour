import hashlib
from typing import Tuple
import os


class DiffieHellman:
    def __init__(self):
        # RFC 3526 - 2048-bit MODP Group (Group 14) -> our references to where the prime modulus p was taken from
        # prime modulus = p
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        # generator = g
        self.g = 2

    def generate_shared_key(self, private_key: int, public_key: int) -> bytes:
        shared_secret = pow(public_key, private_key, self.p)
        return self._derive_key_from_secret(shared_secret)

    def generate_public_key(self, private_key: int) -> int:
        return pow(self.g, private_key, self.p)

    def _derive_key_from_secret(self, shared_secret: int) -> bytes:
        #Convert shared secret to encryption key using SHA256
        shared_secret_bytes = shared_secret.to_bytes(
            (shared_secret.bit_length() + 7) // 8, byteorder='big'
        )
        return hashlib.sha256(shared_secret_bytes).digest()

    @staticmethod
    def generate_private_key(bit_length: int = 256) -> int:
        return int.from_bytes(os.urandom(bit_length // 8), byteorder='big')
