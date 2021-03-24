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
module: senhasegura_credential
short_description: Module for management credentials in senhasegura PAM
author:
  - Lucas Fraga (@lfraga)
  - James Miranda (@jameswpm)
description:
    - Authenticates in senhasegura PAM to manage credentials
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
    state:
        description:
            - Whether the credential should exist or not,
        type: str
        choices: [ absent, present ]
        default: present
    identifier:
        required: true
        type: str
        description:
            - credential identifier for management
    device_hostname:
        type: str
        description:
            - Device hostname to link credential
            - Required when state is present
    device_address:
        type: str
        description:
            - Device address to link credential
            - Required when state is present
    type:
        description:
            - Type of credential
            - Required when state is present
        type: str
        choices: [ Local User, Local administrator, Domain user ]
        default: Local User
    username:
        type: str
        description:
            - Credential username
            - Required when state is present
    password:
        description:
            - Credential password
            - This password must meet the password policy requirements
        type: str
    domain:
        description:
            - Domain name, It needs to be previously registered in senhasegura
        type: str
    tags:
        description:
            - Credential tags
        type: list
    additional_info:
        description:
            - Credential additional information
        type: str
    parent_credential:
        description:
            - Parent credential numeric identifier
        type: int
    validate_certs:
        description:
            - Whether to validate or not the HTTPS certificate
        type: boolean
'''

EXAMPLES = r'''
- name: Ensure credential 'ansible' in device 'example-001'
  senhasegura.pam.senhasegura_credential:
    state: present
    identifier: example_credential
    device_hostname: example-001
    device_address: 192.168.10.10
    type: Local user
    username: ansible
    password: your_secret_password
    tags:
      - ansible
      - example
    additional_info: 'Created by Ansible'

- name: Ensure domain credential
  senhasegura.pam.senhasegura_credential:
    state: present
    identifier: domain_credential
    device_hostname: example-002
    device_address: 192.168.10.20
    type: Domain user
    username: ansible
    password: your_secret_password
    domain: CORP
    tags:
      - domain

- name: Inactivate credential with identifier 'domain_credential'
  senhasegura.pam.senhasegura_credential:
    state: absent
    identifier: domain_credential

'''

RETURN = r'''
changed:
    description: Whether there was a change done.
    type: bool
    returned: always
senhasegura_credential:
    description: Dictionary containing result properties.
    returned: always
    type: dict
    sample:
        result:
            description: credentials properties, based on senhasegura informations
            type: complex
            returned: success
status_code:
    description: Result HTTP Status code
    returned: always
    type: int
    sample: 200
'''


def ensure_credential(module, authentication_token):
    """
        Make the request to save the credential, it is possible that will be created
        or edited if a valid identifier or pair username with ip is sent
    """

    params = module.params

    # Required parameters
    payload = {
        "ip": params["device_address"],
        "hostname": params["device_hostname"],
        "type": params["type"],
        "username": params["username"],
        "identifier": params["identifier"]
    }


    url = params['system_url'] + '/iso/pam/credential'

    headers = {"Authorization": 'Bearer {}'.format(authentication_token)}

    # Optional parameters
    if params['password']:
        payload['content'] = params['password']

    if params['domain']:
        payload['domain'] = params['domain']

    if params['tags'] is not None:
        payload['tags'] = ','.join(params['tags'])

    if params['additional_info']:
        payload['additional'] = params['additional_info']

    if params['parent_credential']:
        payload['parent_password'] = params['parent_credential']


    r = iso_request(module, url, method="POST", headers=headers, data=payload, required_http_code=[200, 201])

    # Check idempotency
    result = {"result": r.json()}

    if "changed" in result["result"]["response"]:
        if result["result"]["response"]["changed"] == "true":
            changed = True
        else:
            changed = False
    else:
        changed = True

    return (changed, result, r.status_code)


def ensure_absent_credential(module, authentication_token):
    """
        Performs the request to delete the credential
        In deletion, the credential to remove can be fetched by id, identifier or
        pair username with ip
    """
    params = module.params

    url = params['system_url'] + '/iso/pam/credential/{}'.format(params['identifier'])

    payload = {
        "identifier": params["identifier"]
    }

    headers = {'Content-Type': 'application/json',
               "Authorization": 'Bearer {}'.format(authentication_token)}


    r = iso_request(module, url, method="DELETE", headers=headers, data=payload, required_http_code=[200,201,400])

    # Check idempotency status
    if r.status_code == 400:
        changed = False
    else:
        changed = True

    result = {"result": r.json()}
    return (changed, result, r.status_code)


def main():
    module_args = dict(
        system_url        = dict(type='str', required=True, fallback=(env_fallback, ['SENHASEGURA_URL'])),
        client_id         = dict(type='str', no_log=True, required=True, fallback=(env_fallback, ['SENHASEGURA_CLIENT_ID'])),
        client_secret     = dict(type='str', no_log=True, required=True, fallback=(env_fallback, ['SENHASEGURA_CLIENT_SECRET'])),
        state             = dict(type='str', default='present', choices=['absent', 'present']),
        identifier        = dict(type='str'),
        device_hostname   = dict(type='str'),
        device_address    = dict(type='str'),
        type              = dict(type='str', default='Local User', choices=['Local User', 'Local administrator', 'Domain user']),
        username          = dict(type='str'),
        password          = dict(type='str', no_log=True),
        domain            = dict(type='str'),
        tags              = dict(type='list'),
        additional_info   = dict(type='str'),
        parent_credential = dict(type='int'),
        validate_certs    = dict(type='bool', default=True)
    )


    required_if = [
        ["state", "present", ["device_address", "device_hostname", "type", "username", "identifier"]],
        ["state", "absent", ["identifier"]]
    ]

    module = AnsibleModule(
        argument_spec       = module_args,
        required_if         = required_if,
        supports_check_mode = False
    )

    authentication_token = authenticate(module)

    if (module.params['state'] == "present"):
        (changed, result, status_code) = ensure_credential(module, authentication_token)

    elif (module.params['state'] == "absent"):
        (changed, result, status_code) = ensure_absent_credential(module, authentication_token)

    module.exit_json(
        changed=changed,
        senhasegura_credential=result,
        status_code=status_code)


if __name__ == '__main__':
    main()
