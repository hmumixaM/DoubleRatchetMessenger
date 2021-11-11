import os
import pickle
import string
import datetime
import time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization, padding, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, EllipticCurvePrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Certificate:
    def __init__(self, name: string, public_key):
        self.name: string = name
        self.invalid_before: datetime = None
        self.invalid_after: datetime = None
        self.public_key = public_key
        self.serial_number: int = -1


def el_gamal_enc(pk: EllipticCurvePublicKey, plaintext: bytes, associated_data: bytes) -> (bytes, bytes):
    private_parameter = ec.generate_private_key(ec.SECP256R1())
    public_parameter = private_parameter.public_key()
    shared = private_parameter.exchange(ec.ECDH(), pk)
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_parameter.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    digest.update(shared)
    key = digest.finalize()
    
    aesgcm = AESGCM(key)
    padder = padding.PKCS7(2040).padder()
    padded_plaintext = padder.update(plaintext)
    padded_plaintext += padder.finalize()
    iv = os.urandom(16)
    ciphertext = aesgcm.encrypt(nonce=iv, data=padded_plaintext, associated_data=associated_data)
    
    return public_parameter, iv, ciphertext, associated_data


def el_gamal_dec(sk: EllipticCurvePrivateKey, public_parameter: EllipticCurvePublicKey, iv: bytes,
                 ciphertext: bytes, associated_data: bytes) -> str:
    shared = sk.exchange(ec.ECDH(), public_parameter)
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_parameter.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    digest.update(shared)
    key = digest.finalize()
    
    aesgcm = AESGCM(key)
    padded_plaintext = aesgcm.decrypt(nonce=iv, data=ciphertext, associated_data=associated_data)
    unpadder = padding.PKCS7(2040).unpadder()
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()
    return plaintext.decode('utf-8')


class MessengerServer:
    def __init__(self, server_signing_key: EllipticCurvePrivateKey, server_decryption_key: EllipticCurvePrivateKey):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key
    
    def decryptReport(self, ct):
        return el_gamal_dec(self.server_decryption_key, public_parameter=ct[0], iv=ct[1],
                            ciphertext=ct[2], associated_data=ct[3])
    
    def signCert(self, cert: Certificate) -> bytes:
        cert.invalid_before = datetime.datetime.utcnow()
        cert.invalid_after = datetime.datetime.utcnow() + datetime.timedelta(days=10)
        cert.serial_number = x509.random_serial_number()
        signature = self.server_signing_key.sign(pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))
        return signature


class MessengerClient:
    def __init__(self, name: str, server_signing_pk: EllipticCurvePublicKey,
                 server_encryption_pk: EllipticCurvePublicKey):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.sk = ec.generate_private_key(ec.SECP256R1())
        self.pk = self.sk.public_key()
        self.conns = {}
        self.certs = {}
    
    def generateCertificate(self):
        return Certificate(self.name, self.pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
    
    def receiveCertificate(self, certificate: Certificate, signature: bytes):
        self.server_signing_pk.verify(signature, pickle.dumps(certificate), ec.ECDSA(hashes.SHA256()))
        self.certs[certificate.name] = (certificate, signature)
    
    def sendMessage(self, name, message):
        if name not in self.conns:
            self.conns[name] = Connection(name, self.sk, self.pk, self.certs[name][0].public_key)
        return self.conns[name].sendMessage(message)
    
    def receiveMessage(self, name, header, ciphertext):
        if name not in self.conns:
            self.conns[name] = Connection(name, self.sk, self.pk, self.certs[name][0].public_key)
        return self.conns[name].receiveMessage(header, ciphertext)
    
    def report(self, name, message):
        data = f'Reporter: {self.name}, Reported: {name}, Timestamp: {time.time()}\nMessage: {message}'
        ciphertext = el_gamal_enc(self.server_encryption_pk, data.encode('utf-8'), self.name.encode('utf-8'))
        return data, ciphertext


class Connection:
    def __init__(self, name, sk: EllipticCurvePrivateKey, pk: EllipticCurvePublicKey, initial_peer_pk: bytes):
        self.people = name
        self.sk: EllipticCurvePrivateKey = sk
        self.pk: bytes = pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.peer_pk: bytes = initial_peer_pk
        self.rk: bytes = bytes([0]) * 80
        self.send_ck: bytes = b''
        self.send_iv: bytes = b''
        self.receive_ck: bytes = b''
        self.receive_iv: bytes = b''
    
    def generate_DH(self) -> (EllipticCurvePrivateKey, EllipticCurvePublicKey):
        sk = ec.generate_private_key(ec.SECP256R1())
        return sk, sk.public_key()
    
    def DH(self, sk: EllipticCurvePrivateKey, peer_pk: EllipticCurvePublicKey) -> bytes:
        return sk.exchange(ec.ECDH(), peer_pk)
    
    def KDF_root(self, root_key: bytes, dh_out: bytes) -> (bytes, bytes, bytes):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=80,
            salt=root_key,
            info=b'Root Ratchet').derive(dh_out)
        enc_key = derived_key[:32]
        auth_key = derived_key[32:64]
        iv = derived_key[64:]
        return enc_key, auth_key, iv
    
    def KDF_chain(self, chain_key: bytes) -> (bytes, bytes):
        h = hmac.HMAC(chain_key, hashes.SHA256())
        h.update(b'chain_key')
        chain_key = h.finalize()
        h = hmac.HMAC(chain_key, hashes.SHA256())
        h.update(b'message_key')
        message_key = h.finalize()
        return chain_key, message_key
    
    def encrypt(self, mk: bytes, iv: bytes, plaintext: str, associated_data: bytes) -> bytes:
        aesgcm = AESGCM(mk)
        padder = padding.PKCS7(2040).padder()
        padded_plaintext = padder.update(plaintext.encode('utf-8'))
        padded_plaintext += padder.finalize()
        ciphertext = aesgcm.encrypt(nonce=iv, data=padded_plaintext, associated_data=associated_data)
        return ciphertext
    
    def decrypt(self, mk: bytes, iv: bytes, ciphertext: bytes, associated_data: bytes) -> str:
        aesgcm = AESGCM(mk)
        padded_plaintext = aesgcm.decrypt(nonce=iv, data=ciphertext, associated_data=associated_data)
        unpadder = padding.PKCS7(2040).unpadder()
        plaintext = unpadder.update(padded_plaintext)
        plaintext += unpadder.finalize()
        return plaintext.decode('utf-8')
    
    class Header:
        def __init__(self, pk: bytes, timestamp: float):
            self.pk = pk
            self.timestamp = timestamp
    
    def DHRatchet(self, header: Header) -> None:
        self.peer_pk = header.pk
        peer_pk = serialization.load_pem_public_key(self.peer_pk)
        self.rk, self.receive_ck, self.receive_iv = self.KDF_root(self.rk, self.DH(self.sk, peer_pk))
        new_sk, new_pk = self.generate_DH()
        self.rk, self.send_ck, self.send_iv = self.KDF_root(self.rk, self.DH(new_sk, peer_pk))
        self.pk = new_pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.sk = new_sk
    
    def receiveMessage(self, header: Header, ct: bytes) -> str or None:
        if header.pk != self.peer_pk or len(self.receive_ck) != 32:
            self.DHRatchet(header)
        self.receive_ck, message_key = self.KDF_chain(self.receive_ck)
        try:
            plaintext = self.decrypt(message_key, self.receive_iv, ct, pi  ckle.dumps(header))
        except Exception:
            return None
        self.receive_iv = (int.from_bytes(self.receive_iv, 'big') + 1).to_bytes(16, 'big')
        return plaintext
    
    def sendMessage(self, text: str) -> (Header, bytes):
        if len(self.send_ck) != 32:
            peer_pk = serialization.load_pem_public_key(self.peer_pk)
            self.rk, self.send_ck, self.send_iv = self.KDF_root(self.rk, self.DH(self.sk, peer_pk))
        self.send_ck, message_key = self.KDF_chain(self.send_ck)
        header = self.Header(self.pk, time.time())
        ciphertext = self.encrypt(message_key, self.send_iv, text, pickle.dumps(header))
        self.send_iv = (int.from_bytes(self.send_iv, 'big') + 1).to_bytes(16, 'big')
        return header, ciphertext
