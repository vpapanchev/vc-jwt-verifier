""" Resolves a DID to its DID Document using the configured Resolver API """

import requests
import logging
import time
from multiprocessing import Pool

from vc_jwt_verifier import utils

RESOLVER_CONFIG = utils.load_component_configuration('resolver')
RESOLVER_HOST = RESOLVER_CONFIG['host']
RESOLVER_PORT = RESOLVER_CONFIG['port']
RESOLVER_API = RESOLVER_CONFIG['api']

MULTIPROCESSING_CONFIG = utils.load_component_configuration('multiprocessing')
NUM_PROCESSES = MULTIPROCESSING_CONFIG['num_processes']


def resolve_did(did, log_time=False):
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
    logging.warning("Unexpected result from Resolver: Result does not contain a didDocument")
    return None
  document = response_data['didDocument']
  if not document:
    logging.info(f'DID {did} could not be resolved.')
    return None
  elif log_times:
    # Only log performance for successful resolutions
    # log vcjwt_resolve_did,<did>,<time>
    logging.info(f'vcjwt_resolve_did,{did},{time.time() - start}')
  return document


def resolve_multiple_dids(dids_data, log_time=False):
  """
  Resolves multiple DIDs in parallel.
  The provided dictionary (dids_data) is populated with the resolved DID Documents.
    dids_data == {did: did_document}
  If a DID cannot be resolved, the method returns an error message. Otherwise, None.
  """
  start = time.time()
  # resolve the DIDs in parallel
  with Pool(NUM_PROCESSES) as p:
    result = p.map(lambda x : (x, resolve_did(x)), list(dids_data.keys()))

  for did, did_document in result:
    if not did_document:
      return f"Could not resolve DID: {did}"
    dids_data[did] = did_document

  if log_time:
    # log vcjwt_resolve_multiple_did,<time>,<dids>
    logging.info(f'vcjwt_resolve_multiple_did,{time.time() - start},{list(dids_data.keys())}')
