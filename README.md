# ansible
A10 modules for ansible
#
Place the A10 modules under :
/usr/local/lib/python2.7/dist-packages/ansible-2.2.0-py2.7.egg/ansible

./module_utils/a10XAPI.py
./modules/extras/network/a10/a10_hostname.py
./modules/extras/network/a10/a10_server.py

You can run each task separately:
1. Change the hostname of the vthunder insance:
 ansible-playbook -c local  a10-xapi-host.yaml -vvvv

2. Create a new server 
  ansible-playbook -c local  a10-xapi-server.yaml -vvvv

Or you can run both tasks in one shot:
ansible-playbook -c local  a10.yaml -vvvv
