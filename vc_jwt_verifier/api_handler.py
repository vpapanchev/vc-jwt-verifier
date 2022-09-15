from vc_jwt_verifier.verification import verifier
from vc_jwt_verifier.validation import validator
from vc_jwt_verifier.translation import translator
from vc_jwt_verifier.jwt import jwt_utils
from vc_jwt_verifier.did import resolver


def handle_verify_vc(jwt_vc):
  decoded_jwt_payload, error_msg = verifier.verify_jwt_credential(jwt_vc)
  if not decoded_jwt_payload:
    return __generate_error_response(error_msg)

  is_valid, error_msg = validator.validate_jwt_vc_payload(decoded_jwt_payload)
  if not is_valid:
    return __generate_error_response(error_msg)

  w3c_payload = translator.translate_jwt_vc_to_w3c_vc(jwt_vc, decoded_jwt_payload)
  return __generate_success_response({
    'payload': decoded_jwt_payload,
    'issuer': w3c_payload['issuer'],
    'jwt': jwt_vc,
    'verifiableCredential': w3c_payload
  })


def handle_verify_vp(jwt_vp, verify_included_credentials=False):
  # Verify the proof of the VP
  decoded_jwt_payload, error_msg = verifier.verify_jwt_credential(jwt_vp)
  if not decoded_jwt_payload:
    return __generate_error_response(error_msg)

  # Validate top-level structure of the VP content
  is_valid, error_msg = validator.validate_jwt_vp_payload(decoded_jwt_payload)
  if not is_valid:
    return __generate_error_response(error_msg)

  # Gather the included JWT credentials in the VP
  included_credentials = []
  if isinstance(decoded_jwt_payload['vp']['verifiableCredential'], list):
    included_credentials.extend(decoded_jwt_payload['vp']['verifiableCredential'])
  else:
    included_credentials.append(decoded_jwt_payload['vp']['verifiableCredential'])

  if verify_included_credentials:
    # This assumes that all included credentials are JWT-credentials

    # Verify and translate each included JWT credential
    translated_credentials = []
    for included_jwt_vc in included_credentials:
      verification_data = handle_verify_vc(included_jwt_vc)
      if not verification_data['valid']:
        error_msg = verification_data['error']
        return __generate_error_response(f"Verification of one of the included credentials failed with: {error_msg}")
      translated_credentials.append(verification_data['data']['verifiableCredential'])
    included_credentials = translated_credentials

  # Translate the JWT VP to W3C format
  w3c_vp_payload = translator.translate_jwt_vp_to_w3c_vp(jwt_vp, decoded_jwt_payload, included_credentials)

  nonce = None,
  if 'nonce' in w3c_vp_payload:
    nonce = w3c_vp_payload['nonce']
  elif 'nonce' in decoded_jwt_payload:
    nonce = decoded_jwt_payload['nonce']

  domain = None
  if 'domain' in w3c_vp_payload:
    domain = w3c_vp_payload['domain']
  elif 'domain' in decoded_jwt_payload:
    domain = decoded_jwt_payload['domain']

  return __generate_success_response({
    'payload': decoded_jwt_payload,
    'holder': decoded_jwt_payload['iss'],
    'jwt': jwt_vp,
    'verifiablePresentation': w3c_vp_payload,
    'challenge': {
      'nonce': nonce,
      'domain': domain
    }
  })


def verify_complete_vp(jwt_vp):
  """
  Verifies, validates and translates a Verifiable Presentation (VP) expressed as a JSON Web Token (JWT).
  The VCs included in the presentation are also verified and translated to the W3C Data Model for VCs.
  All necessary DIDs are resolved in parallel using the resolver.resolve_multiple_dids function.
  """


  # Get VP issuer
  presentation_jwt_payload = jwt_utils.get_jwt_payload(jwt_vp)
  presentation_jwt_header = jwt_utils.get_jwt_header(jwt_vp)
  if not presentation_jwt_payload or not presentation_jwt_header:
    return __generate_error_response("Invalid JWT: Could not decode token")

  holder_did = __get_issuer_did_of_jwt(presentation_jwt_payload)
  if not holder_did:
    return __generate_error_response("Invalid JWT: Could not find issuer DID")

  # Validate top-level structure of the VP content
  is_valid, error_msg = validator.validate_jwt_vp_payload(presentation_jwt_payload)
  if not is_valid:
    return __generate_error_response(f"Validation of the VP failed: {error_msg}")

  # DID -> DID Document
  dids_data = {
    holder_did: None
  }

  presentation_data = {
    "jwt": jwt_vp,
    "payload": presentation_jwt_payload,
    "header": presentation_jwt_header,
    "issuer": holder_did,
    "issuer_did_doc": None,
    "w3c_payload": None
  }

  all_credentials_data = []

  presentation_vc_jwts = __extract_included_vcs_in_vp(presentation_jwt_payload)
  for credential_jwt in presentation_vc_jwts:
    # Get decoded payload
    credential_jwt_payload = jwt_utils.get_jwt_payload(credential_jwt)
    credential_jwt_header = jwt_utils.get_jwt_header(credential_jwt)
    if not credential_jwt_payload or not credential_jwt_header:
      return __generate_error_response("Invalid VC: One of the included VCs is not a valid JWT")

    # Validate VC payload
    is_valid, error_msg = validator.validate_jwt_vc_payload(credential_jwt_payload)
    if not is_valid:
      return __generate_error_response(
        "Invalid VC: Invalid payload for one of the included JWT VCs: {}".format(error_msg))

    # Get the issuerDID of this VC
    issuer_did = __get_issuer_did_of_jwt(credential_jwt_payload)
    if not issuer_did:
      return __generate_error_response("Invalid VC: Could not parse issuer DID for one of the included VCs")

    all_credentials_data.append({
      "jwt": credential_jwt,
      "payload": credential_jwt_payload,
      "header": credential_jwt_header,
      "issuer": issuer_did,
      "issuer_did_doc": None,
      "w3c_payload": None
    })
    if issuer_did not in dids_data:
      dids_data[issuer_did] = None

  # Resolve all DIDs
  error_msg = resolver.resolve_multiple_dids(dids_data)
  if error_msg:
    return __generate_error_response(error_msg)

  # Update DID Documents in the VP and VCs data structures
  presentation_data['issuer_did_doc'] = dids_data[presentation_data['issuer']]
  for credential_data in all_credentials_data:
    credential_data['issuer_did_doc'] = dids_data[credential_data['issuer']]

  # Verify and translate all VCs
  result_credentials = []
  translated_credentials = []
  for credential_data in all_credentials_data:
    decoded_vc_payload, error_msg = verifier.verify_jwt_with_resolved_did(credential_data)
    if not decoded_vc_payload:
      return __generate_error_response(f"VC Verification failed: {error_msg}")

    credential_data['w3c_payload'] = translator.translate_jwt_vc_to_w3c_vc(credential_data['jwt'], decoded_vc_payload)
    result_credentials.append({
      'payload': decoded_vc_payload,
      'issuer': credential_data['issuer'],
      'jwt': credential_data["jwt"],
      'verifiableCredential': credential_data["w3c_payload"]
    })
    translated_credentials.append(credential_data["w3c_payload"])

  # Verify and translate the VP
  decoded_vp_payload, error_msg = verifier.verify_jwt_with_resolved_did(presentation_data)
  if not decoded_vp_payload:
    return __generate_error_response(error_msg)
  w3c_vp_payload = translator.translate_jwt_vp_to_w3c_vp(
    presentation_data["jwt"], decoded_vp_payload, translated_credentials)

  nonce = None,
  if 'nonce' in w3c_vp_payload:
    nonce = w3c_vp_payload['nonce']
  elif 'nonce' in decoded_vp_payload:
    nonce = decoded_vp_payload['nonce']
  domain = None
  if 'domain' in w3c_vp_payload:
    domain = w3c_vp_payload['domain']
  elif 'domain' in decoded_vp_payload:
    domain = decoded_vp_payload['domain']

  return __generate_success_response({
    'payload': decoded_vp_payload,
    'holder': presentation_data["issuer"],
    'jwt': presentation_data["jwt"],
    'verifiablePresentation': w3c_vp_payload,
    'challenge': {
      'nonce': nonce,
      'domain': domain
    }
  })


def __extract_included_vcs_in_vp(vp_payload):
  jwt_vcs = []
  if isinstance(vp_payload['vp']['verifiableCredential'], list):
    jwt_vcs.extend(vp_payload['vp']['verifiableCredential'])
  else:
    jwt_vcs.append(vp_payload['vp']['verifiableCredential'])
  return jwt_vcs


def __get_issuer_did_of_jwt(jwt_payload):
  issuer_did = jwt_utils.get_jwt_issuer_id(jwt_payload)
  if not issuer_did or not issuer_did.startswith('did'):
    return None
  return issuer_did


def __generate_error_response(error_msg):
  return {
    'valid': False,
    'error': error_msg,
    'data': None
  }


def __generate_success_response(response_data):
  return {
    'valid': True,
    'error': None,
    'data': response_data
  }
