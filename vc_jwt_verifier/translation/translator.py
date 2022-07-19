import datetime


def jwt_date_to_w3c(jwt_numeric_date):
  """
  Translates the JWT-formatted datetime timestamp to date/timeSevenPropertyModel

  See https://www.w3.org/TR/xmlschema11-2/#dateTime

  :param jwt_numeric_date: datetime object in JWT syntax: NumericDate
  :return: the same datetime in date/timeSevenPropertyModel syntax
  """
  date = datetime.datetime.fromtimestamp(jwt_numeric_date)
  return date.isoformat()


def translate_jwt_vc_to_w3c_vc(jwt_encoded, jwt_payload):
  """
  Translates a W3C-compliant credential in JWT encoding to W3C Format.
  Assumes a validated jwt_payload with existing iss, vc, vc:credentialSubject fields.
  Also adds the encoded jwt as the unregistered JwtProof2020 proof to the W3C credential.

  For the translation see: https://www.w3.org/TR/vc-data-model/#jwt-decoding

  :param jwt_encoded: the complete JWT encoding of header, payload and signature
  :param jwt_payload: the decoded (and validated) payload
  :return: Verifiable Credential in W3C format
  """

  w3c_payload = {}
  # Copy vc payload
  for key, value in jwt_payload['vc'].items():
    w3c_payload[key] = value

  # expiration date
  if 'exp' in jwt_payload:
    w3c_payload['expirationDate'] = jwt_date_to_w3c(jwt_payload['exp'])

  # issuer
  w3c_payload['issuer'] = jwt_payload['iss']

  # issuance date
  if 'nbf' in jwt_payload:
    w3c_payload['issuanceDate'] = jwt_date_to_w3c(jwt_payload['nbf'])

  # Credential Subject ID
  if 'sub' in jwt_payload:
    w3c_payload['credentialSubject']['id'] = jwt_payload['sub']

  # Credential ID
  if 'jti' in jwt_payload:
    w3c_payload['id'] = jwt_payload['jti']

  # Add the encoded jwt as an artificial proof
  w3c_payload['proof'] = {
    'type': "JwtProof2020",
    'jwt': jwt_encoded
  }

  return w3c_payload


def translate_jwt_vp_to_w3c_vp(jwt_encoded, jwt_payload, included_credentials):
  """
  Translates a W3C-compliant VP in JWT encoding to W3C Format.
  The included credentials in this VP (which are JWTs) are substituted with the given translated_credentials.
  Assumes a validated jwt_payload of a VP with existing iss, vp, vp:verifiableCredential fields.
  Also adds the encoded jwt as the unregistered JwtProof2020 proof to the W3C credential.

  For the translation see: https://www.w3.org/TR/vc-data-model/#jwt-decoding

  :param jwt_encoded: the complete JWT encoding of header, payload and signature
  :param jwt_payload: the decoded (and validated) payload
  :param included_credentials: The credentials to be included in this VP (either verified and translated or not)
  :return: Verifiable Presentation in W3C format
  """

  w3c_payload = {}
  # Copy vc payload
  for key, value in jwt_payload['vp'].items():
    w3c_payload[key] = value
  # Substitute the JWT credentials with their translations in W3C format
  w3c_payload['verifiableCredential'] = included_credentials

  # iss -> Holder
  w3c_payload['holder'] = jwt_payload['iss']

  # Credential ID
  if 'jti' in jwt_payload:
    w3c_payload['id'] = jwt_payload['jti']

  # Add the encoded jwt as an artificial proof
  w3c_payload['proof'] = {
    'type': "JwtProof2020",
    'jwt': jwt_encoded
  }

  return w3c_payload
