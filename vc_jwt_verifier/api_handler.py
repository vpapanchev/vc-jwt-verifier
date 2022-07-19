from vc_jwt_verifier.verification import verifier
from vc_jwt_verifier.validation import validator
from vc_jwt_verifier.translation import translator


def handle_verify_vc(jwt_vc):
  decoded_jwt_payload, error_msg = verifier.verify_jwt_credential(jwt_vc)
  if not decoded_jwt_payload:
    return {
      'valid': False,
      'error': error_msg,
      'data': None
    }

  is_valid, error_msg = validator.validate_jwt_vc_payload(decoded_jwt_payload)
  if not is_valid:
    return {
      'valid': False,
      'error': error_msg,
      'data': None
    }

  w3c_payload = translator.translate_jwt_vc_to_w3c_vc(jwt_vc, decoded_jwt_payload)
  return {
    'valid': True,
    'error': "",
    'data': {
      'payload': decoded_jwt_payload,
      'issuer': w3c_payload['issuer'],
      'jwt': jwt_vc,
      'verifiableCredential': w3c_payload
    }
  }


def handle_verify_vp(jwt_vp, verify_included_credentials=False):
  # Verify the proof of the VP
  decoded_jwt_payload, error_msg = verifier.verify_jwt_credential(jwt_vp)
  if not decoded_jwt_payload:
    return {
      'valid': False,
      'error': error_msg,
      'data': None
    }

  # Validate top-level structure of the VP content
  is_valid, error_msg = validator.validate_jwt_vp_payload(decoded_jwt_payload)
  if not is_valid:
    return {
      'valid': False,
      'error': error_msg,
      'data': None
    }

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
        return {
          'valid': False,
          'error': f"Verification of one of the included credentials failed with: {error_msg}",
          'data': None
        }
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

  return {
    'valid': True,
    'error': "",
    'data': {
      'payload': decoded_jwt_payload,
      'holder': decoded_jwt_payload['iss'],
      'jwt': jwt_vp,
      'verifiablePresentation': w3c_vp_payload,
      'challenge': {
        'nonce': nonce,
        'domain': domain
      }
    }
  }
