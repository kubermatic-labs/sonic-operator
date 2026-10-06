// SPDX-License-Identifier: Apache-2.0

package sonic

// Native service activation must retain the inspected host launcher, effective
// unit, platform inputs and local host-network container. In particular an
// HWSKU mismatch must not turn a routing restart into container/image replacement.
const traditionalHostDigest = "0f884c2af47da31b885f5bce8d6f61f9b2964aa9395e142877ba3b14ff34b475"
const traditionalHostScript = `import pathlib,hashlib,json,subprocess,re
config=json.loads(subprocess.check_output(['sonic-cfggen','-d','--print-data']))
meta=config['DEVICE_METADATA']['localhost']; platform=meta['platform']; hwsku=meta['hwsku']
assert re.fullmatch(r'[A-Za-z0-9_.-]+',platform) and re.fullmatch(r'[A-Za-z0-9_.-]+',hwsku)
container=json.loads(subprocess.check_output(['docker','inspect','bgp']))[0]
env=dict(v.split('=',1) for v in container['Config']['Env'])
assert container['HostConfig']['NetworkMode']=='host' and env.get('NAMESPACE_ID','')=='' and env.get('DEV','')=='' and env.get('RUNTIME_OWNER')=='local'
mounts=[m for m in container['Mounts'] if m['Destination']=='/usr/share/sonic/hwsku']
assert len(mounts)==1 and mounts[0]['Source']=='/usr/share/sonic/device/'+platform+'/'+hwsku
files=['/usr/local/bin/bgp.sh','/usr/local/bin/container','/usr/local/bin/write_standby.py','/etc/resolvconf/update-libc.d/update-containers','/etc/sonic/sonic-environment']
files += ['/usr/share/sonic/device/'+platform+'/'+name for name in ['asic.conf','platform_env.conf','platform.json']]
result={p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() if pathlib.Path(p).is_file() else None for p in files}
result['unit']=hashlib.sha256(subprocess.check_output(['systemctl','cat','bgp.service'])).hexdigest()
result['platform']=platform; result['hwsku']=hwsku; result['feature']=config.get('FEATURE',{}).get('bgp',{})
print(hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest())`
