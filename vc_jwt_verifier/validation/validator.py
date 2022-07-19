FIELD_MISSING = "Missing required field: {}"


def validate_jwt_vc_payload(jwt_vc_payload):
  """
  Validates the content of a W3C-compliant VC in JWT encoding.
  Required fields: iss, nbf, vc, vc:credentialSubject

  :param jwt_vc_payload: the payload of the JWT vc
  :return: (is_valid, error_message)
  """
  if 'vc' not in jwt_vc_payload:
    return False, FIELD_MISSING.format('vc')
  vc_payload = jwt_vc_payload['vc']
  if 'credentialSubject' not in vc_payload:
    return False, FIELD_MISSING.format('credentialSubject')
  if not isinstance(vc_payload, dict):
    return False, "Invalid field: vc is not a JSON object"
  if 'iss' not in jwt_vc_payload:
    return False, FIELD_MISSING.format('iss')
  if 'nbf' not in jwt_vc_payload:
    return False, FIELD_MISSING.format('nbf')

  return True, ""


def validate_jwt_vp_payload(jwt_vp_payload):
  """
  Validates the content of a W3C-compliant VP in JWT encoding.
  Required fields: iss, vp, vp:type, vp:verifiableCredential

  :param jwt_vp_payload: the payload of the JWT vp
  :return: (is_valid, error_message)
  """
  if 'vp' not in jwt_vp_payload:
    return False, FIELD_MISSING.format('vp')
  vp_payload = jwt_vp_payload['vp']
  if 'type' not in vp_payload:
    return False, FIELD_MISSING.format('vp:type')
  if 'verifiableCredential' not in vp_payload:
    return False, FIELD_MISSING.format('vp:verifiableCredential')
  if 'iss' not in jwt_vp_payload:
    return False, FIELD_MISSING.format('iss')

  return True, ""
