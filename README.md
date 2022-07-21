### Parent project

This project was developed as a Microservice in the design of an [Interoperable SSI-based Access Control System](https://github.com/vpapanchev/ssi-acs).

# Python Verifier for JWT Verifiable Credentials

## Description

The project implements a Python Flask API for verification of [JSON-LD Verifiable Credentials expressed as JSON Web Tokens (JWTs)](https://www.w3.org/TR/vc-data-model/#json-web-token).

The Verifier provides two HTTP APIs: 
- GET `/verify/vc/?jwt={jwt_vc}` - Verification of a Verifiable Credential (VC) provided as a JWT.
- GET `/verify/vp/?verify_vcs={true/false}&jwt={jwt_vp}` - Verification of a Verifiable Presentation (VP) provided as a JWT. The boolean query parameter `verify_vcs` specifies whether the VCs included in the VP should also be verifier or not.

As part of the verification, the DIDs of the issuers and holders of the credentials are resolved using the configured DID Resolver. The usage of the [DIF Universal Resolver](https://github.com/decentralized-identity/universal-resolver) is preferred, however, any resolver service which implements the same API can be used.

The Verification results also include the payloads of the presentation and/or credentials translated to the W3C Data Format as specified in the [specification](https://www.w3.org/TR/vc-data-model/#jwt-encoding).

## How to run locally

1. Open the configuration file (/vc_jwt_verifier/config/config.yml) and configure the server host, server port and DID resolver.
2. Create and activate a new virtual environment:\
`python3 -m venv ./venv`\
`source venv/bin/activate`
3. Install the project requirements\
`pip3 install -r requirements_dev.txt`
4. Start the Verifier API by running \
`python3 -m vc_jwt_verifier`

## How to run using Docker

1. Open the configuration file (/vc_jwt_verifier/config/config.yml) and configure the server host, server port and DID resolver.
2. Run \
`docker build -f docker/Dockerfile --tag vc-jwt-verifier-image .`\
`docker run -p <port>:<port> --env API_PORT=<port> --name=vc-jwt-verifier vc-jwt-verifier-image:latest`
3. To see the logs of the container:\
`docker logs vc-jwt-verifier`
4. To stop the container:\
`docker stop vc-jwt-verifier`

## Verification Results

HTTP Response Format of `/verify/vc/?jwt={jwt_vc}` API:
```json
{
  "valid": "<True/False - indicates whether the verification was successful>",
  "error": "<Error-Message - the reason for an unsuccessful verification>",
  "data": {
    "payload": "<the decoded payload of the JWT>",
    "issuer": "<DID of issuer of the credential = w3c_payload['issuer']>",
    "jwt": "<The original JWT as provided to the API>",
    "verifiableCredential": "<the VC translated to W3C Format>"
  }
}
```

HTTP Response Format of `/verify/vp/?verify_vcs={true/false}&jwt={jwt_vp}` API:
```json
{
  "valid": "<True/False - indicates whether the verification was successful>",
  "error": "<Error-Message - the reason for an unsuccessful verification>",
  "data": {
    "payload": "<the decoded payload of the JWT>",
    "holder": "<DID of Holder of the VP> = decoded_jwt_payload['iss']",
    "jwt": "<The VP JWT as provided to the API>",
    "verifiablePresentation": "<the VP translated to W3C Format>",
    "challenge": {
      "nonce": "<the nonce included in the VP>",
      "domain": "<the domain included in the VP>"
    }
  }
}
```

If the included credentials should also be verified, the W3C payload of the VP includes the included VCs also translated to the W3C Data Format. Note that, if the verification of a single credentials fails (or if some of the included credentials are not JSON-LD JWTs), the verification of the VP is regarded as unsuccessful. 

## Supported Algorithms

Currently, the following JWT algorithms and DID verification methods are supported:\
JWT Algorithms:
- EdDSA

DID Verification Methods:
- Ed25519VerificationKey2018 encoded in publicKeyBase58 format

## Project status

The project was created as a prototype used for evaluating purposes and might not be actively supported in the future.
