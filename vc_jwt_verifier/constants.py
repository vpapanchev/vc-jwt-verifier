import os
import re

# General service-wide constants
SERVICE_NAME = "vc_jwt_verifier"
LOGGING_CNF_PATH_ENV_VAR = 'LOGGING_CNF_PATH'
CONFIG_FILE_PATH_ENV_VARIABLE = 'CONFIG_PATH'
PROJECT_DIRECTORY = os.path.dirname(__file__)

# Configuration structure
CONF_SERVICES_NAME = "services"

# API Endpoints
API_VERIFY_VC = '/verify/vc/'
API_VERIFY_VP = '/verify/vp/'

# Regexes
VALID_COMPONENT_NAME_REGEX = re.compile('[a-z_]+')

# Messages
LOG_CNF_NO_SERVICES = 'Invalid configuration - No services defined'
LOG_CNF_UNAVAIL_SERVICE = f'Invalid configuration - The service configuration ({SERVICE_NAME}) is missing.'
LOG_CNF_COMPONENT_MISSING = 'Unavailable component configuration: %s. ' \
                            'Provide its configuration in the config.yml.'
LOG_INVALID_COMP_NAME = 'Invalid component name: %s. Component names have the following pattern: %s'
LOG_YAML_PARSE_FAIL = 'YAML file {} could not be parsed - {}'

# HTTP STATUS CODES
HTTP_SUCCESS_STATUS = 200
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_INTERNAL_ERROR = 500
