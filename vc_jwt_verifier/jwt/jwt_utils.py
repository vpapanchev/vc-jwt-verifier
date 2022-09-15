import logging
import jwt


def get_jwt_payload(token):
  try:
    return jwt.decode(token, options={"verify_signature": False})
  except jwt.exceptions.InvalidTokenError:
    return None


def get_jwt_header(token):
  try:
    return jwt.get_unverified_header(token)
  except jwt.exceptions.InvalidTokenError:
    return None


def get_jwt_issuer_id(jwt_payload):
  issuer = jwt_payload['iss']
  if isinstance(issuer, dict):
    if 'id' not in issuer:
      logging.info('Invalid JWT Token: Could not parse Issuer ID')
      return None, 'Invalid JWT Token: Could not parse Issuer ID'
    issuer = issuer['id']
  return issuer
