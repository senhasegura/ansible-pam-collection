#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from ansible.module_utils.basic import AnsibleModule, env_fallback

from ansible_collections.senhasegura.pam.plugins.module_utils.iso import authenticate, iso_request

__metaclass__ = type

DOCUMENTATION = r'''
---
module: senhasegura_credential_info
short_description: Module for get information about credentials in senhasegura PAM
author:
  - Lucas Fraga (@lfraga)
description:
    - Authenticates in senhasegura PAM to get credentials
notes:
    - Check mode not supported

options:
    system_url:
        type: str
        description:
            - senhasegura's environment URL used for authentication, SENHASEGURA_URL environment variable may also be used
    client_id:
        type: str
        description:
            - A2A OAuth2 client_id, SENHASEGURA_CLIENT_ID environment variable may also be used
    client_secret:
        type: str
        description:
            - A2A OAuth2 client_secret, SENHASEGURA_CLIENT_SECRET environment variable may also be used
    identifier:
        type: str
        description:
            - The credential identifier to get information
    id_credential:
        type: str
        description:
            - The credential ID to get information
    validate_certs:
        description:
            - Whether to validate or not the HTTPS certificate
        type: bool
'''

EXAMPLES = r'''
- name: Get informations about credential with identifier 'example_credential'
  senhasegura.pam.senhasegura_credential_info:
    identifier: example_credential
  register: senhasegura_example_credential

- name: Get informations about credential with id_credential '9172'
  senhasegura.pam.senhasegura_credential_info:
    id_credential: 9172
  register: senhasegura_9172_credential

'''

RETURN = r'''
changed:
    description: Whether there was a change done.
    type: bool
    returned: always
senhasegura:
    description: Dictionary containing result properties.
    returned: always
    type: dict
    sample:
        credential:
            description: credentials properties, based on senhasegura informations
            type: complex
            returned: success
status_code:
    description: Result HTTP Status code
    returned: always
    type: int
    sample: 200
'''


def credential_info(module, authentication_token):

    params = module.params

    url = params["system_url"] + '/iso/pam/credential/'

    if params['id_credential'] is not None:
        url += '{}?credential={}'.format(params['id_credential'], params['id_credential'])
    elif params['identifier'] is not None:
        url += '{}?credential={}'.format(params['identifier'], params['identifier'])

    headers = {'Content-Type': 'application/json',
               "Authorization": 'Bearer {}'.format(authentication_token)}


    r = iso_request(module, url, method="GET", headers=headers, required_http_code=[200])

    result = r.json()
    return (True, result, r.status_code)


def main():
    module_args = dict(
        system_url        = dict(type='str', required=True, fallback=(env_fallback, ['SENHASEGURA_URL'])),
        client_id         = dict(type='str', no_log=True, required=True, fallback=(env_fallback, ['SENHASEGURA_CLIENT_ID'])),
        client_secret     = dict(type='str', no_log=True, required=True, fallback=(env_fallback, ['SENHASEGURA_CLIENT_SECRET'])),
        id_credential     = dict(type='int'),
        identifier        = dict(type='str'),
        validate_certs    = dict(type='bool', default=True)
    )


    mutually_exclusive = [
        ["id_credential", "identifier"]
    ]

    module = AnsibleModule(
        argument_spec       = module_args,
        mutually_exclusive  = mutually_exclusive,
        supports_check_mode = False
    )

    authentication_token = authenticate(module)

    (changed, result, status_code) = credential_info(module, authentication_token)

    module.exit_json(
        changed=changed,
        senhasegura=result,
        status_code=status_code)


if __name__ == '__main__':
    main()
