#!/usr/bin/python

import json
import urllib2
import urllib
import ssl

DOCUMENTATION = '''
module: nessus
short_description: "Configures nessus scans and retrieves scan results"
author:
  - Nick Wilburn
requirements:
  - only standard library needed
options:
  hostname:
    description:
      - The hostname of the nessus server
  port:
    description:
      - The port that the nessus server is running on
'''

def call_api(url, **kwargs):

    opts = kwargs.get('opts')
    headers = kwargs.get('headers')
    access_key = kwargs.get('access_key')
    secret_key = kwargs.get('secret_key')
    token = kwargs.get('token')

    if headers is None:
        if secret_key is not None:
            headers = {
                'Content-Type': 'application/json',
                'X-ApiKeys': 'accessKey={access_key};secretKey={secret_key}'.format(**locals())
            }
        elif token is not None:
            headers = {
                'Content-Type': 'application/json',
                'X-Cookie': 'token={token}'.format(**locals())
            }
    else:
        if secret_key is not None:
            headers = headers.update({
                'X-ApiKeys': 'accessKey={access_key};secretKey={secret_key}'.format(**locals())
            })
        elif token is not None:
            headers = headers.update({
                'X-Cookie': 'token={token}'.format(**locals())
            })

    if opts is not None:
        data = json.dumps(opts)
        request_args = {"url": url, "data": data, "headers": headers}
    else:
        request_args = {"url": url, "headers": headers}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    opener = urllib2.build_opener(urllib2.HTTPSHandler(context=ctx))
    urllib2.install_opener(opener)

    request = urllib2.Request(**request_args)
    response = urllib2.urlopen(request)
    return response

def get_credential(url, username, password):


    opts = {
        'username': username,
        'password': password
    }

    headers = {
        'Content-Type': 'application/json'
    }

    url = url + '/session'
    response = call_api(url, opts=opts, headers=headers)

    credential = json.loads(response.read())['token']
    return credential

def get_template_uuid(url, template_name, **kwargs):

    secret_key = kwargs.get('secret_key')
    access_key = kwargs.get('access_key')
    token = kwargs.get('token')
    url = url + '/policies'

    if token is not None:
        response = call_api(url, token=token)
    else:
        response = call_api(url, secret_key=secret_key, access_key=access_key)    

    template_uuid = [policy['template_uuid'] for policy in json.loads(response.read())['policies'] if policy['name'] == template_name]
    return template_uuid[0]

def create_scan(url, target, template_uuid, **kwargs):

    token = kwargs.get('token') 
    secret_key = kwargs.get('secret_key')
    access_key = kwargs.get('access_key')

    opts = {
        "uuid": template_uuid,
        "settings": {
            "name": "New Scan",
            "enabled": True,
            "text_targets": target
        }
    }

    url = url + '/scans'

    if token is not None:
        response = call_api(url, token=token, opts=opts)
    else:
        response = call_api(url, access_key=access_key, secret_key=secret_key)

    scan_uuid = json.loads(response.read())['scan']['id']
    return scan_uuid

def launch_scan(url, scan_uuid, **kwargs):

    token = kwargs.get('token')
    secret_key = kwargs.get('secret_key')
    access_key = kwargs.get('access_key')

    opts = {
        "scan_id": scan_uuid
    }

    url = url + '/scans/{scan_uuid}/launch'.format(**locals())

    if token is not None:
        response = call_api(url, token=token, opts=opts)
    else:
        response = call_api(url, access_key=access_key, secret_key=secret_key, opts=opts)

    if response.getcode() == 403:
        return "Launching scan failed. Scan is disabled"
    elif response.getcode() == 404:
        return "Launching scan failed. The scan does not exist"
    elif response.getcode() == 200:
        scan_uuid = json.loads(response.read())['scan_uuid']
        return {'scan_uuid': scan_uuid}
    

def main():
    module = AnsibleModule(
        argument_spec=dict(
            url=dict(required=True),
            username=dict(required=False),
            password=dict(required=False),
            secret_key=dict(required=False),
            access_key=dict(required=False),
            template_name=dict(required=False),
            target=dict(required=True)
        ),
        supports_check_mode=True
    )

    if module.check_mode:
        module.exit_json(changed=False)
    url = module.params['url']
    username = module.params['username']
    password = module.params['password']
    secret_key = module.params['secret_key']
    access_key = module.params['access_key']
    template_name = module.params['template_name']
    target = module.params['target']

    if username is not None:
        token = get_credential(url, username=username, password=password)
        template_uuid = get_template_uuid(url, template_name, token=token)
        scan_uuid = create_scan(url, target, template_uuid, token=token )
        run_scan = launch_scan(url, scan_uuid, token=token)
    elif secret_key is not None:
        template_uuid = get_template_uuid(url, template_name, secret_key=secret_key, access_key=access_key)
        scan_uuid = create_scan(url, target, template_uuid, secret_key=secret_key, access_key=access_key)
        run_scan = launch_scan(url, scan_uuid, secret_key=secret_key, access_key=access_key)


    if run_scan is not None:
        msg = "Scan uuid: %s" % (run_scan)
        module.exit_json(changed=False,msg=msg)
    else:
        msg = "Login token is %s" % (run_scan)
        module.fail_json(msg=msg)

from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()