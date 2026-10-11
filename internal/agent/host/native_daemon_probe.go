// SPDX-License-Identifier: Apache-2.0
package host

// Host-root read-only collector. Container root cannot read a setuid snmpd's
// environ without CAP_SYS_PTRACE; host root can, as qualified on both images.
// Only sanitized booleans, argv, times and a transient config digest are emitted.
// No private configuration/environment content reaches stdout or stderr.
const nativeDaemonProbe = `import hashlib,json,os,subprocess,sys,time
from pathlib import Path

def directives(path,allowed):
    if not path.exists(): return True
    if path.is_symlink() or not path.is_file(): return False
    for line in path.read_text().splitlines():
        line=line.strip()
        if line and not line.startswith('#') and line.split()[0] not in allowed: return False
    return True

# Net-SNMP persists every loaded USM user (name, localized keys) at startup and
# shutdown; only the user names leave this probe.
def persisted_users(path):
    users=[]
    if not path.exists(): return users
    for line in path.read_text().splitlines():
        fields=line.split()
        if not fields or fields[0]!='usmUser': continue
        if len(fields)<6: raise ValueError()
        name=fields[4]
        if name.startswith('0x'): name=bytes.fromhex(name[2:]).decode('ascii')
        elif len(name)>=2 and name[0]==name[-1]=='"': name=name[1:-1]
        else: raise ValueError()
        users.append(name)
    return sorted(users)

# chrony reads every conf.d/*.conf. Only the operator-owned makestep drop-in may
# carry directives; the probe reports its digest and identity, never its content.
# Returns (None, '') when absent.
def chrony_step_file(root):
    path=root/'etc/chrony/conf.d/sonic-operator-makestep.conf'
    if not path.exists() and not path.is_symlink(): return None,''
    if path.is_symlink() or not path.is_file(): raise ValueError()
    with path.open('rb') as f:
        data=f.read(4097); info=os.fstat(f.fileno())
    if len(data)>4096: raise ValueError()
    return dict(device=info.st_dev,inode=info.st_ino,modifiedNS=info.st_mtime_ns,changedNS=info.st_ctime_ns),hashlib.sha256(data).hexdigest()

def mapped_library_matches(proc,root):
    mappings=[line.split() for line in (proc/'maps').read_text().splitlines() if 'libnetsnmp.so.' in line]
    if not mappings or any(len(m)!=6 for m in mappings): return False
    if len({tuple(m[3:]) for m in mappings})!=1: return False
    # Overlayfs can expose its lower filesystem's device in /proc/maps but an
    # overlay device from stat(container_root/path). Compare actual mapped bytes
    # to the independently hash-qualified installed file, not those device IDs.
    loaded=(proc/'map_files'/mappings[0][0]).read_bytes()
    installed=(root/'usr/lib/x86_64-linux-gnu/libnetsnmp.so.40').read_bytes()
    return hashlib.sha256(loaded).digest()==hashlib.sha256(installed).digest()

def collect(mode):
    if mode=='snmp':
        lines=subprocess.check_output(['docker','top','snmp','-eo','pid,comm'],text=True).splitlines()[1:]
        pids=[line.split()[0] for line in lines if len(line.split())==2 and line.split()[1]=='snmpd']
        if len(pids)!=1: raise ValueError()
        pid=pids[0]; config='/etc/snmp/snmpd.conf'
    elif mode in ('ntpsec','chrony'):
        pid=subprocess.check_output(['systemctl','show','--property=MainPID','--value',mode+'.service'],text=True).strip()
        config='/etc/ntpsec/ntp.conf' if mode=='ntpsec' else '/etc/chrony/chrony.conf'
    else: raise ValueError()
    if not pid.isdigit() or int(pid)==0: raise ValueError()
    proc=Path('/proc')/pid; root=proc/'root'
    initial=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
    executable={'snmp':'usr/sbin/snmpd','ntpsec':'usr/sbin/ntpd','chrony':'usr/sbin/chronyd'}[mode]
    loaded_exe=(proc/'exe').stat(); installed_exe=(root/executable).stat()
    if (loaded_exe.st_dev,loaded_exe.st_ino)!=(installed_exe.st_dev,installed_exe.st_ino): raise ValueError()
    args=[x.decode() for x in (proc/'cmdline').read_bytes().split(b'\0') if x]
    env=dict(x.decode().split('=',1) for x in (proc/'environ').read_bytes().split(b'\0') if b'=' in x)
    file=root/config.lstrip('/')
    if file.is_symlink(): raise ValueError()
    with file.open('rb') as f:
        data=f.read(); info=os.fstat(f.fileno())
    auxiliary=True
    clean=True
    users=[]
    step,stepDigest=None,''
    if mode=='snmp':
        clean=not any(k.startswith('SNMP') for k in env) and env.get('HOME','/root')=='/root'
        auxiliary=mapped_library_matches(proc,root)
        for path in ['/etc/snmp/snmpd.local.conf','/etc/snmp/snmp.local.conf','/root/.snmp/snmpd.conf','/root/.snmp/snmpd.local.conf','/root/.snmp/snmp.conf','/root/.snmp/snmp.local.conf','/usr/share/snmp/snmpd.conf','/var/lib/snmp/snmpd.local.conf','/var/lib/snmp/snmpd.0.conf']:
            auxiliary=auxiliary and not (root/path.lstrip('/')).exists()
        auxiliary=auxiliary and directives(root/'etc/snmp/snmp.conf',{'mibs'})
        auxiliary=auxiliary and directives(root/'var/lib/snmp/snmpd.conf',{'setserialno','engineBoots','oldEngineID','usmUser'})
        if auxiliary: users=persisted_users(root/'var/lib/snmp/snmpd.conf')
    elif mode=='chrony':
        for directory,pattern in [('etc/chrony/conf.d','*.conf'),('etc/chrony/sources.d','*.sources'),('run/chrony-dhcp','*.sources')]:
            for path in (root/directory).glob(pattern):
                if path.name!='sonic-operator-makestep.conf' or directory!='etc/chrony/conf.d': auxiliary=auxiliary and directives(path,set())
        step,stepDigest=chrony_step_file(root)
    final=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
    if initial!=final or file.stat().st_mtime_ns!=info.st_mtime_ns or file.stat().st_ctime_ns!=info.st_ctime_ns: raise ValueError()
    uptime=time.clock_gettime(time.CLOCK_BOOTTIME); wall=time.time()
    return dict(pid=int(pid),bootID=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),file=dict(device=info.st_dev,inode=info.st_ino,modifiedNS=info.st_mtime_ns,changedNS=info.st_ctime_ns),arguments=args,startUptime=int(initial)/os.sysconf('SC_CLK_TCK'),observedWall=wall,observedUptime=uptime,configModified=info.st_mtime,configChanged=info.st_ctime,configDigest=hashlib.sha256(data).hexdigest(),environmentClean=clean,auxiliaryClean=auxiliary,persistedUsers=users,stepFile=step,stepDigest=stepDigest)

try:
    print(json.dumps(collect(sys.argv[1])))
except Exception:
    print('{}')
`
