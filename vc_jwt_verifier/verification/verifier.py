import logging
import jwt
from vc_jwt_verifier.verification.methods import ed25519
from vc_jwt_verifier.did import resolver, parser

# Currently, the supported crypto algorithms are hard-coded.
# In the future this should be refactored to allow for easier extendability of supported methods.
# Supported JWT algorithms: EdDSA
# Supported Verification Method Types: Ed25519VerificationKey2018
# Supported Verification Method Properties: publicKeyBase58
SUPPORTED_JWT_ALGS = ["EdDSA"]
VERIFY_METHOD_TYPE_ED25519 = 'Ed25519VerificationKey2018'
VERIFY_METHOD_PROPERTY_PKB58 = 'publicKeyBase58'


def verify_jwt_credential(credential_encoded):
  """ Verifies the cryptographic proofs of a JWT VC/VP """

  try:
    payload = jwt.decode(credential_encoded, options={"verify_signature": False})
    header = jwt.get_unverified_header(credential_encoded)
  except jwt.exceptions.InvalidTokenError:
    logging.info('Invalid JWT token: Cannot decode')
    return None, 'Invalid JWT token: Cannot decode'

  # Get JWT Signature Algorithm
  if 'alg' not in header:
    return None, 'Invalid JWT Token: Missing alg header.'
  algorithm = header['alg']
  # Supported JWT algorithms: EdDSA
  if algorithm not in SUPPORTED_JWT_ALGS:
    logging.info(f'Invalid JWT Token: Unsupported JWT algorithm: {algorithm}')
    return None, f'Invalid JWT Token: Unsupported JWT algorithm: {algorithm}'

  # Get IssuerDID
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

  # Resolve Issuer DID
  issuer_did_doc = resolver.resolve_did(issuer, log_time=True)
  if not issuer_did_doc:
    return None, 'Could not resolve Issuer DID'

  verification_result = __verify_jwt_with_issuer_did_doc(credential_encoded, header, issuer_did_doc)
  if verification_result:
    return verification_result, ''
  return None, 'Unsuccessful verification: Invalid signature or unsupported issuer verification method'


def verify_jwt_with_resolved_did(jwt_data):
  """ Verifies the cryptographic proof of a JWT VC/VP with an already resolved issuer DID """

  header = jwt_data["header"]
  if 'alg' not in header:
    return None, 'Invalid JWT Token: Missing alg header.'
  algorithm = header['alg']
  # Supported JWT algorithms: EdDSA
  if algorithm not in ["EdDSA"]:
    return None, f'Invalid JWT Token: Unsupported JWT algorithm: {algorithm}'

  issuer_did_doc = jwt_data["issuer_did_doc"]
  if not issuer_did_doc:
    return None, 'Could not resolve Issuer DID'

  verification_result = __verify_jwt_with_issuer_did_doc(jwt_data["jwt"], header, issuer_did_doc)
  if verification_result:
    return verification_result, ''
  return None, 'Unsuccessful verification: Invalid signature or unsupported issuer verification method'


def __verify_jwt_with_issuer_did_doc(credential_encoded, jwt_header, issuer_did_doc):
  verification_methods = []
  kid = None
  if 'kid' in jwt_header:
    kid = jwt_header['kid']
  if kid:
    specified_ver_method = parser.get_verification_method(issuer_did_doc, kid)
    if specified_ver_method:
      verification_methods.append(specified_ver_method)
  else:
    verification_methods = parser.get_all_verification_methods(issuer_did_doc)

  for verification_method in verification_methods:
    if "type" in verification_method and verification_method["type"] == VERIFY_METHOD_TYPE_ED25519:
      if VERIFY_METHOD_PROPERTY_PKB58 in verification_method:
        result = ed25519.verify_jwt_with_b58_ed25519(
          credential_encoded, verification_method[VERIFY_METHOD_PROPERTY_PKB58])
        if result:
          return result
