import logging

import base58
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALGORITHM = "EdDSA"


def __verify_key_ed25519_b58_to_pem(verify_key_b58):
  # TODO: Handle exceptions

  # Get Ed25519PublicKey object
  ver_key_bytes = bytes(verify_key_b58, "ascii")
  ver_key_raw = base58.b58decode(ver_key_bytes)
  ed25519_pk = Ed25519PublicKey.from_public_bytes(ver_key_raw)

  # Use cryptography library to get key in PEM format
  ver_key_pem_bytes = ed25519_pk.public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
  ver_key_pem = ver_key_pem_bytes.decode("ascii")

  return ver_key_pem


def verify_jwt_with_b58_ed25519(jwt_credential, ver_key_b58):
  ver_key_pem = __verify_key_ed25519_b58_to_pem(ver_key_b58)
  try:
    return jwt.decode(jwt_credential, ver_key_pem, algorithms=[ALGORITHM])
  except jwt.exceptions.InvalidSignatureError:
    logging.info('Signature verification failed')
  except jwt.exceptions.ExpiredSignatureError:
    logging.info('Invalid Credential: Credential is expired')
  except jwt.exceptions.InvalidIssuedAtError:
    logging.info('Invalid Credential: Credential issuance date is in the future.')
  except jwt.exceptions.ImmatureSignatureError:
    logging.info('Invalid Credential: Credential nbf date is in the future')
  except jwt.exceptions.InvalidKeyError as err:
    logging.info('Invalid Format of Public Key.')
  except jwt.exceptions.InvalidAlgorithmError:
    logging.info('Credential Proof Algorithm not supported')
  except jwt.exceptions.InvalidTokenError as err:
    logging.info(err)
  return None
