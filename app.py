from pathlib import Path
import ctypes
import ipaddress
import os
import sys
import uuid
import xml.etree.ElementTree as ET
from runtime import entry,parser,run

PROFILES={'quick':['-sT','--top-ports','100'],'lan-discovery':['-sn'],
 'service-detection':['-sT','-sV','--version-light','--top-ports','100'],
 'localhost-audit':['-sT','-p','1-1024'],'tcp-audit':['-sT','--top-ports','1000'],
 'basic-udp':['-sU','--top-ports','20']}

def command(profile,target,authorized=False):
    if profile not in PROFILES:raise ValueError('Nieznany profil.')
    network=ipaddress.ip_network(target,strict=False)
    if network.num_addresses>256:raise ValueError('Maksymalnie 256 adresów na uruchomienie.')
    if not network.is_loopback and not authorized:raise ValueError('Wymagane --authorized dla własnego lub uzgodnionego celu.')
    if profile=='localhost-audit' and not network.is_loopback:raise ValueError('Ten profil jest tylko dla localhost.')
    return ['nmap',*PROFILES[profile],'-T3','--max-retries','1','--host-timeout','60s',str(network) if '/' in target else str(network.network_address)]

def parse_xml(path):
    path=Path(path)
    if path.stat().st_size>64*1024*1024:raise ValueError('XML zbyt duży.')
    text=path.read_text(encoding='utf-8')
    if '<!DOCTYPE' in text or '<!ENTITY' in text:raise ValueError('Deklaracje DTD nie są obsługiwane.')
    try:root=ET.fromstring(text)
    except ET.ParseError as e:raise ValueError('Błędny XML.') from e
    if root.tag!='nmaprun':raise ValueError('To nie jest XML Nmap.')
    hosts={}
    for host in root.findall('host'):
        addresses=[a.get('addr') for a in host.findall('address') if a.get('addrtype') in ('ipv4','ipv6')]
        if not addresses:continue
        address=str(ipaddress.ip_address(addresses[0]));ports={}
        for port in host.findall('./ports/port'):
            ident=f'{port.get("protocol")}/{int(port.get("portid"))}';state=port.find('state');service=port.find('service')
            ports[ident]={'state':state.get('state') if state is not None else 'unknown','service':dict(service.attrib) if service is not None else {}}
        status=host.find('status')
        hosts[address]={'status':status.get('state') if status is not None else 'unknown','ports':ports}
    return hosts

def compare(a,b):
    changes=[]
    for host in sorted(a.keys()|b.keys()):
        if host not in a:changes.append({'host':host,'event':'NEW_HOST'});continue
        if host not in b:changes.append({'host':host,'event':'REMOVED_HOST'});continue
        left=a[host]['ports'];right=b[host]['ports']
        for port in sorted(left.keys()|right.keys()):
            if port not in left:event='NEW_PORT'
            elif port not in right:event='PORT_NOT_IN_RESULT'
            elif left[port]['state']!=right[port]['state']:event='PORT_STATE_CHANGE'
            elif left[port]['service']!=right[port]['service']:event='SERVICE_CHANGE'
            else:continue
            changes.append({'host':host,'port':port,'event':event,'before':left.get(port),'after':right.get(port)})
    return {'changes':changes,'note':'Brak portu w wyniku nie oznacza potwierdzonego zamknięcia. Porównuj zgodne profile.'}

def build():
    p=parser('Nmap: domyślnie plan; wykonanie przez --apply.')
    p.add_argument('command',nargs='?',choices=['scan','export','compare'])
    p.add_argument('--profile',choices=PROFILES,default='quick');p.add_argument('--target',default='127.0.0.1')
    p.add_argument('--authorized',action='store_true');p.add_argument('--apply',action='store_true')
    p.add_argument('--xml');p.add_argument('--other');p.add_argument('--directory',default='reports')
    return p

def handle(a):
    if a.command=='export' and a.xml:return parse_xml(a.xml)
    if a.command=='compare' and a.xml and a.other:return compare(parse_xml(a.xml),parse_xml(a.other))
    if a.command=='scan':
        cmd=command(a.profile,a.target,a.authorized)
        if not a.apply:return {'plan':cmd,'executed':False}
        if a.profile=='basic-udp':
            admin=bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name=='nt' else os.geteuid()==0
            if not admin:raise PermissionError('UDP scan wymaga administratora/root.')
        directory=Path(a.directory);directory.mkdir(parents=True,exist_ok=True);base=directory/('nmap-'+uuid.uuid4().hex)
        run(cmd[:-1]+['-oA',str(base),cmd[-1]],timeout=900)
        return {'hosts':parse_xml(base.with_suffix('.xml')),'xml':str(base.with_suffix('.xml')),'txt':str(base.with_suffix('.nmap'))}
    raise ValueError('Nieprawidłowe argumenty.')

if __name__=='__main__':sys.exit(entry(build,handle))
