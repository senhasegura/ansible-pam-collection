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
module: senhasegura_device
short_description: Module for management devices in senhasegura PAM
author:
  - Lucas Fraga (@lfraga)
description:
    - Authenticates in senhasegura PAM to manage devices
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
            - Whether the device should exist or not,
        type: str
        choices: [ absent, present ]
        default: present
    hostname:
        required: true
        type: str
        description:
            - Hostname of device
    address:
        required: true
        type: str
        description: IP or DNS
    type:
        description:
            - Type of device, if non-existent, will be created.
            - Required when state is present
        type: str
    vendor:
        description:
            - Vendor of device, if non-existent, will be created.
            - Required when state is present
        type: str
    model:
        description:
            - Model of device, if non-existent, will be created.
            - Required when state is present
        type: str
    site:
        description:
            - Site of device.
            - Required when state is present
        type: str
    domain:
        description:
            - The device domain.
        type: str
    connectivities:
        description:
            - The connectivity protocols on device in format <Protocol>:<Port>
            - Example 'SSH:22'
        type: list
    tags:
        description:
            - The device tags.
        type: list
    validate_certs:
        description:
            - Whether to validate or not the HTTPS certificate
        type: boolean
'''

EXAMPLES = r'''
- name: Absent example-001 device
  senhasegura.pam.senhasegura_device:
    state: absent
    hostname: example-001
    address: 192.168.10.10


- name: Ensure example-002 device
  senhasegura.pam.senhasegura_device:
    state: present
    hostname: example-002
    address: 192.168.10.20
    type: Server
    vendor: Red Hat
    model: Red Hat Enterprise Linux
    site: Cloud
    connectivities: ['SSH:22', 'HTTPS:443']
    tags: ['rhel', 'cloud']

- name: Ensure windows-001 device
  senhasegura.pam.senhasegura_device:
    state: present
    hostname: windows-001
    address: 192.168.10.30
    type: Server
    vendor: Microsoft
    model: Windows Server
    site: On-premises
    connectivities: ['RDP:3389']
    tags: ['windows', 'domain']
    domain: CORP

'''

RETURN = r'''
changed:
    description: Whether there was a change done.
    type: bool
    returned: always
senhasegura_device:
    description: Dictionary containing result properties.
    returned: always
    type: dict
    sample:
        result:
            description: device properties, based on senhasegura informations
            type: complex
            returned: success
status_code:
    description: Result HTTP Status code
    returned: always
    type: int
    sample: 200
'''


def ensure_device(module, authentication_token):
    params = module.params

    headers = {"Authorization": 'Bearer {}'.format(authentication_token)}

    url = params['system_url'] + '/iso/pam/device'

    payload = {
        "ip": params["address"],
        "hostname": params["hostname"],
        "type": params["type"],
        "vendor": params["vendor"],
        "model": params["model"],
        "site": params["site"]
    }

    if params['domain'] is not None:
        payload['device_domain'] = params['domain']

    if params['tags'] is not None:
        payload['device_tags'] = ','.join(params['tags'])

    if params["connectivities"] is not None:
        payload['connectivities'] = ','.join(params["connectivities"])

    r = iso_request(module, url, method="POST", headers=headers,
                    data=payload, required_http_code=[200, 201])

    result = {"result": r.json()}

    # Check idempotency
    if "changed" in result["result"]["response"]:
        if result["result"]["response"]["changed"] == "true":
            changed = True
        else:
            changed = False
    else:
        changed = True

    return (changed, result, r.status_code)


def ensure_absent_device(module, authentication_token):
    params = module.params

    url = params['system_url'] + '/iso/pam/device'
    headers = {"Authorization": 'Bearer {}'.format(authentication_token)}

    payload = {}

    url += '/{}'.format(params['hostname'])
    payload['device'] = params['hostname']

    r = iso_request(module, url, method="DELETE", headers=headers,
                    data=payload, required_http_code=[200, 400, 404])

    if r.status_code == 400:
        # Device deactivated or not found
        changed = False
    elif r.status_code == 200:
        # Device deactivated
        changed = True

    result = {"result": r.json()}
    return (changed, result, r.status_code)


def main():

    module_args = dict(
        system_url=dict(type='str', required=True, fallback=(env_fallback, ['SENHASEGURA_URL'])),
        client_id=dict(type='str', no_log=True, required=True, fallback=(env_fallback, ['SENHASEGURA_CLIENT_ID'])),
        client_secret=dict(type='str', no_log=True, required=True, fallback=(env_fallback, ['SENHASEGURA_CLIENT_SECRET'])),
        state=dict(type='str', default='present',
                   choices=['absent', 'present']),
        hostname=dict(type='str'),
        address=dict(type='str'),
        type=dict(type='str'),
        vendor=dict(type='str'),
        model=dict(type='str'),
        site=dict(type='str'),
        domain=dict(type='str'),
        tags=dict(type='list'),
        connectivities=dict(type='list'),
        validate_certs=dict(type='bool', default=True)
    )

    required_if = [
        ["state", "present", ["address", "hostname", "site", "model", "vendor", "type"]],
        ["state", "absent", ["address", "hostname"]]
    ]

    module = AnsibleModule(
        argument_spec=module_args,
        required_if=required_if,
        supports_check_mode=False
    )

    authentication_token = authenticate(module)

    if (module.params['state'] == "present"):
        (changed, result, status_code) = ensure_device(
            module, authentication_token)

    elif (module.params['state'] == "absent"):
        (changed, result, status_code) = ensure_absent_device(
            module, authentication_token)

    module.exit_json(
        changed=changed,
        senhasegura_device=result,
        status_code=status_code)


if __name__ == '__main__':
    main()
