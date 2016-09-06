#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb server objects
(c) 2014, Mischa Peters <mpeters@a10networks.com>

This file is part of Ansible

Ansible is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Ansible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
"""

DOCUMENTATION = '''
---
module: a10_hostname
version_added: 2.2
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage slb server objects on A10 Networks devices via aXAPI
author: "KD (@ciberkot)"
notes:
    - Requires A10 Networks aXAPI 3.0
options:
  host:
    description:
      - hostname or ip of your A10 Networks device
    required: true
  username:
    description:
      - admin account of your A10 Networks device
    required: true
    aliases: ['user', 'admin']
  password:
    description:
      - admin password of your A10 Networks device
    required: true
    aliases: ['pass', 'pwd']
  systemname:
    description:
      - slb server name
    required: true
    aliases: ['server']
  state:
    description:
      - create, update or remove slb server
    required: false
    default: present
    choices: ['present', 'absent']
'''

EXAMPLES = '''
# Create a new server
- a10_server:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    systemname: test

'''

def main():

    sdk = XAPI()

    argument_spec = sdk.a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            systemname=dict(type='str', aliases=['systemname'], required=True),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    state = module.params['state']
    write_config = module.params['write_config']
    systemname = module.params['systemname']

    if systemname is None:
        module.fail_json(msg='server_name is required')

    sdk.logon(module)

    json_post = {
        "hostname": {
              "value": systemname
            }
    }

    result = {"responce" : "NULL"}
    changed = False
    if state == 'present':
        sdk.post(module, uri = '/axapi/v3/hostname', payload = json_post)
        changed = True
    elif state == 'absent':
        sdk.post(module, uri = '/axapi/v3/hostname', payload = json_post)
        changed = True

    # if the config has changed, save the config unless otherwise requested
#    if changed and write_config:
#        write_result = axapi_call(module, session_url + '&method=system.action.write_memory')
#        if axapi_failure(write_result):
#            module.fail_json(msg="failed to save the configuration: %s" % write_result['response']['err']['msg'])

    # log out of the session nicely and exit
    sdk.logoff(module)

    module.exit_json(changed=changed, meta=result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10XAPI import *

import re



if __name__ == '__main__':
    main()
