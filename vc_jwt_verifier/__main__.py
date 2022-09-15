# -*- coding: utf-8 -*-

"""Main module."""

import logging
from flask import request
from flask_httpauth import HTTPBasicAuth
from vc_jwt_verifier import app_configurer, utils, constants, api_handler


flask_app = app_configurer.initialize_flask_app(__name__)
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username, password):
  auth_config = utils.load_component_configuration('authorization')
  if username == auth_config['username'] and password == auth_config['password']:
    logging.info(f'Successful Authorization with username: {username}')
    return True
  else:
    logging.info(f'Unsuccessful Authorization when using internal API.')
    return False


@flask_app.route('/-system/liveness')
def check_system_liveness():
  return 'ok', constants.HTTP_SUCCESS_STATUS


@flask_app.route(constants.API_VERIFY_VC, methods=['GET'])
def verify_vc():

  if request.method == 'GET':
    vc_jwt = request.args.get('jwt')
    if not vc_jwt:
      return utils.generate_err_resp('Invalid Request: Missing jwt parameter', constants.HTTP_BAD_REQUEST)

    response = api_handler.handle_verify_vc(vc_jwt)
    return response, constants.HTTP_SUCCESS_STATUS

  return utils.generate_err_resp('Invalid Request Method', constants.HTTP_NOT_FOUND)


@flask_app.route(constants.API_VERIFY_VP, methods=['GET'])
def verify_vp():

  if request.method == 'GET':
    vp_jwt = request.args.get('jwt')
    if not vp_jwt:
      return utils.generate_err_resp('Invalid Request: Missing jwt parameter', constants.HTTP_BAD_REQUEST)

    verify_included_credentials = request.args.get('verify_vcs')
    if not verify_included_credentials or verify_included_credentials == 'false':
      response = api_handler.handle_verify_vp(vp_jwt, verify_included_credentials=False)
    elif verify_included_credentials == 'true':
      response = api_handler.verify_complete_vp(vp_jwt)
    else:
      return utils.generate_err_resp('Invalid Request: Invalid verify_vcs parameter', constants.HTTP_BAD_REQUEST)
    return response, constants.HTTP_SUCCESS_STATUS

  return utils.generate_err_resp('Invalid Request Method', constants.HTTP_NOT_FOUND)


if __name__ == '__main__':
  server_config = utils.load_component_configuration('server')
  flask_app.run(debug=server_config['debug'], port=server_config['port'], host=server_config['host'])
