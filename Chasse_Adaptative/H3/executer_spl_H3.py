"""Validation des templates H3, Python 3.10+, bibliotheque standard uniquement.
Ce programme ne constitue pas une execution PPO et ne produit pas de verdict.
"""
import argparse
import base64
import csv
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

VERSION = 'H3-templates-1.2'
TEMPLATES = {
    'R1': 'dns_lookup',
    'R2': 'cisco_nvm_flow_lookup',
    'R3': 'sysmon_process_lookup',
    'R4': 'windows_security_lookup',
    'R5': 'symantec_alert_lookup',
    'R6': 'http_context_lookup',
}


def quote(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def load_context(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data.get('action') != 'R1' or data.get('status') not in ('ok', 'empty'):
        raise ValueError('Le contexte doit etre un resultat R1 termine sans erreur ni avertissement.')
    if data.get('limit_reached'):
        raise ValueError('R1 a atteint la limite : relancer R1 avec --limite plus elevee.')
    ips = set()
    for row in data['results']:
        value = row.get('h3_src_ip')
        if value:
            ips.add(str(ipaddress.ip_address(value)))
    if not ips:
        raise ValueError('Aucune IP source exploitable dans R1.')
    return sorted(ips), data


def build_spl(action, index='botsv3', ips=(), limit=100000,
              web_destination=None, web_reason=None):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', index):
        raise ValueError('Nom index invalide.')
    if not 1 <= limit <= 1000000:
        raise ValueError('Limite attendue entre 1 et 1000000.')
    ips = [str(ipaddress.ip_address(x)) for x in ips]
    base = 'search index=' + index
    if action != 'R1' and not ips:
        raise ValueError('R1 est necessaire pour obtenir les IP sources.')
    def filt(*fields):
        vals = ','.join(quote(x) for x in ips)
        return ' | where ' + ' OR '.join(f'in({f},{vals})' for f in fields)
    if action == 'R1':
        spl = base + r''' sourcetype="stream:dns" source="stream:dns" "NIMLOC"
| spath input=_raw path=query_type{} output=h3_query_type
| where mvfind(h3_query_type,"^NIMLOC$")>=0
| spath input=_raw path=src_ip output=h3_src_ip
| spath input=_raw path=dest_ip output=h3_dest_ip
| spath input=_raw path=src_port output=h3_src_port
| spath input=_raw path=dest_port output=h3_dest_port
| spath input=_raw path=transport output=h3_transport
| spath input=_raw path=query{} output=h3_query
| spath input=_raw path=timestamp output=h3_timestamp
| eval h3_epoch=_time
| table _time h3_epoch host source sourcetype h3_src_ip h3_dest_ip h3_src_port h3_dest_port h3_transport h3_query h3_query_type h3_timestamp _raw'''
    elif action == 'R2':
        spl = base + ' sourcetype="syslog" source="cisconvmflowdata"'
        spl += filt('sa', 'da')
        spl += ' | where sp=137 OR dp=137 | table _time host sa da sp dp pr pn ppn pa ph dh fst fet _raw'
    elif action == 'R3':
        spl = base + ' sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"'
        spl += r''' | rex field=_raw "<EventID[^>]*>(?<h3_event_id>[0-9]+)</EventID>"
| where h3_event_id="3"'''
        for field in ('SourceIp', 'DestinationIp', 'SourcePort', 'DestinationPort', 'Protocol', 'Image', 'ProcessGuid', 'UtcTime'):
            spl += '\n| rex field=_raw ' + quote("<Data Name=['\"]" + field + "['\"]>(?<h3_" + field + ">[^<]*)</Data>")
        spl += filt('h3_SourceIp', 'h3_DestinationIp')
        spl += ' | where h3_SourcePort="137" OR h3_DestinationPort="137" | table _time host h3_* _raw'
    elif action == 'R4':
        spl = base + ' sourcetype="WinEventLog:Security"'
        spl += r''' | rex field=_raw "EventCode=(?<h3_event_id>[0-9]+)"
| where h3_event_id="5156" OR h3_event_id="5157"'''
        for label, field, pattern in (
            ('Source Address', 'src_ip', r'[^\r\n]+'),
            ('Destination Address', 'dest_ip', r'[^\r\n]+'),
            ('Source Port', 'src_port', '[0-9]+'),
            ('Destination Port', 'dest_port', '[0-9]+'),
            ('Application Name', 'application', r'[^\r\n]+'),
            ('Direction', 'direction', r'[^\r\n]+'),
            ('Protocol', 'protocol', '[0-9]+'),
            ('Process ID', 'pid', '[0-9]+')):
            spl += '\n| rex field=_raw ' + quote(label + r':[ \t]*(?<h3_' + field + '>' + pattern + ')')
        spl += filt('h3_src_ip', 'h3_dest_ip')
        spl += ' | where h3_src_port="137" OR h3_dest_port="137" | table _time host h3_* _raw'
    elif action == 'R5':
        spl = base + ' (sourcetype="symantec:ep:packet:file" OR sourcetype="symantec:ep:traffic:file" OR sourcetype="symantec:ep:security:file" OR sourcetype="symantec:ep:risk:file" OR sourcetype="symantec:ep:behavior:file")'
        # Formats distincts : ne jamais lire une MAC comme un port security.
        spl += r'''
| rex field=_raw "Local:\s*(?<h3_local_ip>[0-9.]+),"
| rex field=_raw "IP Address:\s*(?<h3_risk_ip>[0-9.]+),"
| rex field=_raw "^[^,]+,[^,]+,[^,]+,(?<h3_behavior_ip>[0-9.]+),"
| rex field=_raw "Local:\s*[0-9.]+,Local:\s*(?<h3_net_local_port>[0-9]+)(?:,|$)"
| rex field=_raw "Remote:\s*(?<h3_remote_ip>[0-9.]+),Remote:[^,]*,Remote:\s*(?<h3_net_remote_port>[0-9]+)(?:,|$)"
| rex field=_raw "Local Port (?<h3_sec_local_port>[0-9]+)"
| rex field=_raw "Remote Port (?<h3_sec_remote_port>[0-9]+)"
| eval h3_local_port=case(sourcetype="symantec:ep:security:file",h3_sec_local_port,sourcetype="symantec:ep:packet:file" OR sourcetype="symantec:ep:traffic:file",h3_net_local_port)
| eval h3_remote_port=case(sourcetype="symantec:ep:security:file",h3_sec_remote_port,sourcetype="symantec:ep:packet:file" OR sourcetype="symantec:ep:traffic:file",h3_net_remote_port)'''
        spl += filt('h3_local_ip', 'h3_remote_ip', 'h3_risk_ip', 'h3_behavior_ip')
        spl += ' | where h3_local_port="137" OR h3_remote_port="137" OR sourcetype="symantec:ep:security:file" OR sourcetype="symantec:ep:risk:file" OR sourcetype="symantec:ep:behavior:file"'
        spl += ' | table _time host sourcetype h3_local_ip h3_remote_ip h3_risk_ip h3_behavior_ip h3_local_port h3_remote_port _raw'
    elif action == 'R6':
        if not web_destination or not web_reason or not web_reason.strip():
            raise ValueError('R6 conditionnelle : fournir --destination-web et --justification-web (preuve reliant cette destination a H3).')
        ipaddress.ip_address(web_destination)
        spl = base + ' sourcetype="stream:http" | spath'
        spl += filt('src_ip', 'dest_ip')
        spl += ' | where dest_ip=' + quote(web_destination)
        spl += ' | table _time host src_ip dest_ip site uri url user_agent status _raw'
    else:
        raise ValueError('Action SPL inconnue. R7 est une decision, sans requete SPL.')
    return spl + '\n| head ' + str(limit)


def execute(spl, args, password):
    url = f'https://{args.host}:{args.port}/services/search/jobs/export'
    body = urllib.parse.urlencode(dict(search=spl, output_mode='json',
                                      earliest_time=args.earliest, latest_time=args.latest)).encode()
    req = urllib.request.Request(url, data=body, method='POST')
    auth = base64.b64encode((args.username + ':' + password).encode()).decode()
    req.add_header('Authorization', 'Basic ' + auth)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    context = ssl._create_unverified_context() if args.certificat_autosigne else ssl.create_default_context()
    results, messages = [], []
    with urllib.request.urlopen(req, context=context, timeout=args.timeout) as response:
        for line in response:
            if not line.strip():
                continue
            item = json.loads(line)
            if str(item.get('preview', False)).lower() in ('true', '1'):
                continue
            if isinstance(item.get('result'), dict):
                results.append(item['result'])
            elif set(item) - {'preview', 'lastrow', 'offset', 'fields'}:
                messages.append(item)
    return results, messages


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--action', choices=['R1','R2','R3','R4','R5','R6'], default='R1')
    p.add_argument('--contexte', help='Fichier JSON produit par R1')
    p.add_argument('--index', default='botsv3')
    p.add_argument('--limite', type=int, default=100000)
    p.add_argument('--earliest', default='0')
    p.add_argument('--latest', default='now')
    p.add_argument('--destination-web')
    p.add_argument('--justification-web')
    p.add_argument('--executer', action='store_true', help='Executer dans Splunk. Sinon generation SPL seulement.')
    p.add_argument('--host', default=os.getenv('SPLUNK_HOST','localhost'))
    p.add_argument('--port', type=int, default=8089)
    p.add_argument('--username', default=os.getenv('SPLUNK_USERNAME','burlegate'))
    p.add_argument('--certificat-autosigne', action='store_true', help='Labo uniquement : desactive la verification TLS.')
    p.add_argument('--timeout', type=int, default=300)
    p.add_argument('--sortie', default=str(Path(__file__).resolve().parent / 'outputs'))
    args = p.parse_args()
    try:
        if not 1 <= args.port <= 65535 or args.timeout <= 0:
            raise ValueError('Port ou timeout invalide.')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', args.host):
            raise ValueError('--host attend un nom de serveur ou une IPv4, sans URL.')
        ips, ctx = load_context(args.contexte) if args.contexte else ([], {})
        spl = build_spl(args.action, args.index, ips, args.limite, args.destination_web, args.justification_web)
        if ctx and (ctx['index'] != args.index or ctx['earliest'] != args.earliest or ctx['latest'] != args.latest):
            raise ValueError('Conserver le meme index et les memes bornes de recherche que R1.')
    except (ValueError, OSError, KeyError) as exc:
        p.error(str(exc))
    folder = Path(args.sortie)
    folder.mkdir(parents=True, exist_ok=True)
    stem = 'H3_' + args.action + '_' + TEMPLATES[args.action] + '_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    (folder / (stem + '.spl')).write_text(spl, encoding='utf-8')
    print(spl)
    report = dict(version=VERSION, action=args.action, template_id=TEMPLATES[args.action], mode='validation_technique_templates_spl',
                  created_at_utc=datetime.now(timezone.utc).isoformat(), index=args.index,
                  earliest=args.earliest, latest=args.latest, source_ips=ips,
                  context_file=str(Path(args.contexte).resolve()) if args.contexte else None,
                  context_sha256=hashlib.sha256(Path(args.contexte).read_bytes()).hexdigest() if args.contexte else None,
                  script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  spl=spl, limit=args.limite, limit_reached=False,
                  web_justification=args.justification_web, status='generated', results=[], messages=[],
                  verdict=None, note='Filtrage par IP : correspondance temporelle et causalite non etablies automatiquement.')
    code = 0
    if args.executer:
        password = os.getenv('SPLUNK_PASSWORD') or getpass.getpass('Mot de passe Splunk : ')
        start = time.monotonic()
        try:
            rows, messages = execute(spl, args, password)
            report.update(results=rows, messages=messages, result_count=len(rows),
                          limit_reached=len(rows)>=args.limite)
            serialized = json.dumps(messages).upper()
            report['status'] = ('error' if any(x in serialized for x in ('"ERROR"','"FATAL"'))
                                else 'warning' if messages else 'ok' if rows else 'empty')
            if report['limit_reached']:
                report['status'] = 'truncated'
            if report['status'] in ('error','warning','truncated'):
                code = 1
            if rows:
                fields = sorted(set().union(*(r.keys() for r in rows)))
                with (folder / (stem + '.csv')).open('w', encoding='utf-8-sig', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v for k,v in r.items()} for r in rows)
        except Exception as exc:
            report.update(status='error', error=str(exc))
            code = 1
        finally:
            report['duration_seconds'] = round(time.monotonic()-start,3)
    target = folder / (stem + '.json')
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('\nEtat :', report['status'], '| Lignes :',len(report['results']))
    print('Resultat :', target.resolve())
    if report.get('error'):
        print('Erreur :',report['error'])
    return code


if __name__ == '__main__':
    sys.exit(main())
