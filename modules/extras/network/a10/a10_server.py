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
module: a10_server
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
  server_name:
    description:
      - slb server name
    required: true
    aliases: ['server']
  server_ip:
    description:
      - slb server IP address
    required: false
    default: null
    aliases: ['ip', 'address']
  server_status:
    description:
      - slb virtual server status
    required: false
    default: enabled
    aliases: ['status']
    choices: ['enabled', 'disabled']
  server_ports:
    description:
      - A list of ports to create for the server. Each list item should be a
        dictionary which specifies the C(port:) and C(protocol:), but can also optionally
        specify the C(status:). See the examples below for details. This parameter is
        required when C(state) is C(present).
    required: false
    default: null
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
    server: test
    server_ip: 1.1.1.100
    server_ports:
      - port-number: 8080
        protocol: tcp
      - port-number: 8443
        protocol: TCP

'''

def main():

    sdk = XAPI()

    argument_spec = sdk.a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            server_name=dict(type='str', aliases=['server'], required=True),
            server_ip=dict(type='str', aliases=['ip', 'address']),
            server_status=dict(type='str', default='enabled', aliases=['status'], choices=['enabled', 'disabled']),
            server_ports=dict(type='list', aliases=['port'], default=[]),
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
    slb_server = module.params['server_name']
    slb_server_ip = module.params['server_ip']
    slb_server_status = module.params['server_status']
    slb_server_ports = module.params['server_ports']

    if slb_server is None:
        module.fail_json(msg='server_name is required')

    sdk.logon(module)

    # validate the ports data structure
#    sdk.validate_ports(module, slb_server_ports)

    # add optional module parameters
#    if slb_server_ip:
#        json_post['server']['host'] = slb_server_ip
#
#    if slb_server_ports:
#        json_post['server']['port_list'] = slb_server_ports
#
#    if slb_server_status:
#        json_post['server']['status'] = sdk.axapi_enabled_disabled(slb_server_status)

    json_post = {
        "server-list": [
            {
              "name":slb_server,
              "host":slb_server_ip,
              "port-list": slb_server_ports
            }
         ]
    }


    (slb_server_status, slb_server_data) = sdk.get(module, uri = '/axapi/v3/slb/server/'+slb_server)
    result = "NULL"
    changed = False
#    slb_server_status = 201
    if state == 'present':
        if slb_server_status != 200:
            result = dict(msg="the server was not present")
            if not slb_server_ip:
                module.fail_json(msg='you must specify an IP address when creating a server')

            sdk.post(module, uri = '/axapi/v3/slb/server', payload = json_post)
            changed = True
        else:
            result = dict(msg="the server was present")
            def port_needs_update(src_ports, dst_ports):
                '''
                Checks to determine if the port definitions of the src_ports
                array are in or different from those in dst_ports. If there is
                a difference, this function returns true, otherwise false.
                '''
                for src_port in src_ports:
                    found = False
                    different = False
                    for dst_port in dst_ports:
                        if src_port['port_num'] == dst_port['port_num']:
                            found = True
                            for valid_field in VALID_PORT_FIELDS:
                                if src_port[valid_field] != dst_port[valid_field]:
                                    different = True
                                    break
                            if found or different:
                                break
                    if not found or different:
                        return True
                # every port from the src exists in the dst, and none of them were different
                return False

            def status_needs_update(current_status, new_status):
                '''
                Check to determine if we want to change the status of a server.
                If there is a difference between the current status of the server and
                the desired status, return true, otherwise false.
                '''
                if current_status != new_status:
                    return True
                return False

            defined_ports = slb_server_data.get('server', {}).get('port_list', [])
            current_status = slb_server_data.get('server', {}).get('status')

            # we check for a needed update several ways
            # - in case ports are missing from the ones specified by the user
            # - in case ports are missing from those on the device
            # - in case we are change the status of a server
            if port_needs_update(defined_ports, slb_server_ports) or port_needs_update(slb_server_ports, defined_ports) or status_needs_update(current_status, axapi_enabled_disabled(slb_server_status)):
                json_post = {
                        "port-list": slb_server_ports
                }
                print "!!!!!!!!!json_post!!!!!!!!!!", json_post
#               json_post = {
#                       "port-list": [
#                         {
#                         "port-number":80,
#                         "protocol":"tcp",
#                         }
#                       ]
#               }

                sdk.delete(module, uri = '/axapi/v3/slb/server/'+slb_server+"/port-list")
                sdk.post(module, uri = '/axapi/v3/slb/server/'+slb_server+"/port-list", payload = json_post)
                changed = True

        # if we changed things, get the full info regarding
        # the service group for the return data below
        #if changed:
        #    (result,msg) = sdk.post(module, uri = '/axapi/v3/slb/server', payload = json_post)
        #else:
        #    result = slb_server_data
    elif state == 'absent':
        if slb_server_exists:
            sdk.post(module, uri = '/axapi/v3/slb/server', payload = json_post)
            changed = True
        else:
            result = dict(msg="the server was not present - absent")

    # if the config has changed, save the config unless otherwise requested
#    if changed and write_config:
#        write_result = axapi_call(module, session_url + '&method=system.action.write_memory')
#        if axapi_failure(write_result):
#            module.fail_json(msg="failed to save the configuration: %s" % write_result['response']['err']['msg'])

    # log out of the session nicely and exit
    sdk.logoff(module)

    module.exit_json(changed=changed, content=result)

# standard ansible module imports
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.a10XAPI import *

import re

from ansible.module_utils.netcfg import NetworkConfig, dumps
from ansible.module_utils.netcli import Command



if __name__ == '__main__':
    main()

