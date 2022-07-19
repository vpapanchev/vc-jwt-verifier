import logging
import jwt
from vc_jwt_verifier.verification.methods import ed25519
from vc_jwt_verifier.did import resolver, parser

# Currently, the supported crypto algorithms are hard-coded.
# In the future this should be refactored to allow for easier extendability of supported methods.
# Supported JWT algorithms: EdDSA
# Supported Verification Method Types: Ed25519VerificationKey2018
# Supported Verification Method Properties: publicKeyBase58


def verify_jwt_credential(credential_encoded):
  """ Verifies the cryptographic proofs of a JWT credential or presentation """

  try:
    payload = jwt.decode(credential_encoded, options={"verify_signature": False})
    header = jwt.get_unverified_header(credential_encoded)
  except jwt.exceptions.InvalidTokenError:
    logging.info('Invalid JWT token: Cannot decode')
    return None, 'Invalid JWT token: Cannot decode'

  if 'alg' not in header:
    logging.info('Invalid JWT Token: Missing alg header.')
    return None, 'Invalid JWT Token: Missing alg header.'
  algorithm = header['alg']
  # Supported JWT algorithms: EdDSA
  if algorithm not in ["EdDSA"]:
    logging.info(f'Invalid JWT Token: Unsupported JWT algorithm: {algorithm}')
    return None, f'Invalid JWT Token: Unsupported JWT algorithm: {algorithm}'

  if 'iss' not in payload:
    logging.info('Invalid JWT Token: Missing iss field.')
    return None, 'Invalid JWT Token: Missing iss field.'

  issuer = payload['iss']
  if isinstance(issuer, dict):
    if 'id' not in issuer:
      logging.info('Invalid JWT Token: Could not parse Issuer ID')
      return None, 'Invalid JWT Token: Could not parse Issuer ID'
    issuer = issuer['id']

  if not issuer.startswith('did'):
    logging.info('Invalid JWT Token: Issuer is not a DID')
    return None, 'Invalid JWT Token: Issuer is not a DID'

  issuer_did_doc = resolver.resolve_did(issuer)
  if not issuer_did_doc:
    return None, 'Could not resolve Issuer DID'

  verification_methods = []
  kid = None
  if 'kid' in header:
    kid = header['kid']
  if kid:
    specified_ver_method = parser.get_verification_method(issuer_did_doc, kid)
    if specified_ver_method:
      verification_methods.append(specified_ver_method)
  else:
    verification_methods = parser.get_all_verification_methods(issuer_did_doc)

  # Supported Verification Method Types: Ed25519VerificationKey2018
  # Supported Verification Method Properties: publicKeyBase58
  for verification_method in verification_methods:
    if "type" in verification_method and verification_method["type"] == 'Ed25519VerificationKey2018':
      if 'publicKeyBase58' in verification_method:
        result = ed25519.verify_jwt_with_b58_ed25519(credential_encoded, verification_method['publicKeyBase58'])
        if result:
          return result, ''

  return None, 'Unsupported Issuer Verification Method Types'
