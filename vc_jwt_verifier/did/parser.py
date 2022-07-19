""" Parses a DID Document """


def get_verification_method(did_document, ver_method_id):
  if 'verificationMethod' not in did_document:
    return None
  for verification_method in did_document['verificationMethod']:
    if 'id' in verification_method:
      if verification_method['id'] == ver_method_id:
        return verification_method
  return None


def get_all_verification_methods(did_document):
  if 'verificationMethod' not in did_document:
    return []
  return did_document['verificationMethod']

