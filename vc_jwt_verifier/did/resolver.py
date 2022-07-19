""" Resolves a DID to its DID Document using the configured Resolver API """

import requests
import logging
from multiprocessing import Lock

from vc_jwt_verifier import utils

RESOLVER_CONFIG = utils.load_component_configuration('resolver')
RESOLVER_HOST = RESOLVER_CONFIG['host']
RESOLVER_PORT = RESOLVER_CONFIG['port']
RESOLVER_API = RESOLVER_CONFIG['api']

lock = Lock()


def resolve_did(did):
  import time
  start = time.time()
  api = RESOLVER_API.format(did=did)
  url = f'http://{RESOLVER_HOST}:{RESOLVER_PORT}{api}'
  try:
    response = requests.get(url, timeout=20)
  except requests.exceptions.RequestException as requests_error:
    logging.warning(f'Resolving DID: {did} -> RequestsException: {str(requests_error)}')
    return None
  response_data = response.json()
  if 'didDocument' not in response_data:
    logging.warning("Unexpected result from Resolver: Result does not contain didDocument")
    return None
  document = response_data['didDocument']
  if not document:
    logging.info(f'DID {did} could not be resolved.')
    return None
  else:
    # Only log performance for successful resolutions
    # log vcjwt_resolve_did,<did>,<time>
    logging.info(f'vcjwt_resolve_did,{did},{time.time() - start}')
  return document
