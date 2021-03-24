#!/usr/bin/python
# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
from ansible.module_utils._text import to_text
from ansible.module_utils.six.moves import http_client as httplib
from ansible.module_utils.six.moves.urllib.error import HTTPError

import requests
import json

__metaclass__ = type

def authenticate(module):
	"""
		Perform the Oauth2 authentication at senhasegura
		server to get the token for execute main actions
	"""

	url = '{}/iso/oauth2/token'.format(module.params["system_url"])

	data = {
		'grant_type': 'client_credentials',
		'client_id': module.params["client_id"],
		'client_secret': module.params["client_secret"]
	}


	try:

		resp = requests.post(url, data=data, verify=module.params["validate_certs"])

		if resp.json()['access_token'] is None:
			module.fail_json(
				msg="Could not authenticate with the server, check your credentials"
			)

		return resp.json()['access_token']

	except (HTTPError, httplib.HTTPException) as http_exception:

		module.fail_json(
			msg=("Could not authenticate with the server, check your credentials."
				 "Please validate parameters provided."
				 "\n*** end_point=%s\n ==> %s" % (url, to_text(http_exception))),
			payload=data,
			status_code=http_exception.code)

	except Exception as unknown_exception:

		module.fail_json(
			msg=("Error while performing OAuth2 authentication."
				 "\n*** end_point=%s\n%s" % (url, to_text(unknown_exception))),
			payload=data,
			status_code=-1)




def iso_request(module, url, method="GET", data={}, headers={}, required_http_code=[200]):

	try:
		if method == "POST":
			resp = requests.post(url, headers=headers, data=data, json=json.dumps(data), verify=module.params["validate_certs"])
		elif method == "DELETE":
			resp = requests.delete(url, headers=headers, data=data, verify=module.params["validate_certs"])
		elif method == "GET":
			resp = requests.get(url, headers=headers, verify=module.params["validate_certs"])

		if resp.status_code not in required_http_code:
			module.fail_json(msg="Error: HTTP {}".format(resp.status_code), payload=data, status_code=-1)

		return resp

	except (HTTPError, httplib.HTTPException) as http_exception:

		module.fail_json(
			msg=("Error sending API request"
				 "Please validate parameters provided."
				 "\n*** end_point=%s\n ==> %s" % (url, to_text(http_exception))),
			payload=data,
			status_code=http_exception.code)

	except Exception as unknown_exception:

		module.fail_json(
			msg=("Unknown error in API request"
				 "\n*** end_point=%s\n%s" % (url, to_text(unknown_exception))),
			payload=data,
			STatus_code=-1)
