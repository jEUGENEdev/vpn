"""Privileged native acceptance client. No user prompts on disposable CI hosts.

The calling native suite already has administrative privileges to install/remove
services. It must still prove the public status credential cannot mutate policy.
"""
import base64, json, os, pathlib, platform, ssl, subprocess, urllib.error, urllib.request

def request(data_dir, status_token, action, body):
    assert os.environ.get('GITHUB_ACTIONS') == 'true', 'Disposable native CI hosts only'
    base='https://127.0.0.1:17891/local/'
    certificate=json.loads((pathlib.Path(data_dir)/'ui-session.json').read_bytes())['certificate']
    def call(certificate, url, token, payload=None, expected=200):
        # Use the shipped desktop transport for mutations as well as its TLS
        # validation. No credentials are passed through process arguments.
        command=pathlib.Path(__file__).with_name('desktop_control_client.cjs')
        output=subprocess.check_output(['node',str(command)],input=json.dumps({
            'certificate':certificate,'url':url,'token':token,'body':payload}).encode())
        response=json.loads(output)
        assert response['status']==expected, response['status']
        return response['body']
    # Verify an actual mutation with the public credential is rejected.
    call(certificate,base+action,status_token,body,expected=403)
    ticket=call(certificate,base+'control/request',status_token,{'action':action,'data':body},expected=201)
    private=pathlib.Path(data_dir)/'control/session.json'
    try:raw=private.read_bytes()
    except PermissionError:
        assert platform.system()=='Darwin'
        raw=subprocess.check_output(['sudo','-n','/bin/cat',str(private)])
    session=json.loads(raw)
    assert session['address'].startswith('https://127.0.0.1:')
    review=call(session['certificate'],session['address']+'/review?id='+ticket['id'],session['token'])
    call(session['certificate'],session['address']+'/commit?id='+ticket['id'],session['token'],{'digest':review['digest']})
    # Power commits intentionally restart the service. Native suites wait for
    # persisted state and check network behavior instead of retrying mutations.
    if action=='vpn':return None
    result=call(certificate,base+'control/result/'+ticket['id'],ticket['receipt'])
    assert result['status']==200, result['status']
    return result['body']


def public_opener(data_dir):
    session=json.loads((pathlib.Path(data_dir)/'ui-session.json').read_bytes())
    ctx=ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(base64.b64decode(session['certificate'])))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))

def state(data_dir,token):
    req=urllib.request.Request('https://127.0.0.1:17891/local/state',headers={'Authorization':'Bearer '+token})
    with public_opener(data_dir).open(req,timeout=3) as response:return json.load(response)

if __name__=='__main__':
    import sys
    assert os.environ.get('GITHUB_ACTIONS')=='true', 'Disposable native CI hosts only'
    data=pathlib.Path('/var/lib/linevpn') if platform.system()=='Darwin' else pathlib.Path(os.environ['PROGRAMDATA'])/'LineVPN'
    token=(data/'ui-token').read_text().strip()
    action=sys.argv[1]
    result=state(data,token) if action=='state' else request(data,token,action,json.loads(sys.argv[2] if len(sys.argv)>2 else sys.stdin.read()))
    print(json.dumps(result))
