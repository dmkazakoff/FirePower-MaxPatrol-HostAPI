from lxml import etree as ET
import socket
import transliterate
import os
import glob
import codecs
import urllib
import io
import re
import sys

# csv = ''
export_files = 0
lb_limit = 1000
lb_count = 0
vuln_db_global = []
host_db_global = []

def iterate_export():

    global export_files
    global csv
    global lb_limit
    global lb_count

    if export_files > 0:
        csv.write(u"ScanFlush\n")
        csv.close()
    export_files = export_files + 1
    csv = io.open("export/output_" + str(export_files) + '.txt', "w", encoding='utf8')
    csv.write(u"SetDomain, Global\n")
    csv.write(u"SetSource, MaxPatrol\n")
    csv.write(u"SetSourceType, 2\n")
    lb_count = 0

    return csv

def translate(MySTR):
    return urllib.quote(MySTR.encode('utf8'))


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True


def search_vulnerdb(id):
    for vulner in vuln_db_global:
        if vulner['id'] == id:
            return vulner
    return {}

def checking_existingval(soft):
    if (soft["version"]):
        checkval = soft["version"]
    else:
        checkval = soft["name"]
    return checkval

def guess_os(software): # Just a guess by keywords =)
    for soft in software:
        checkval = checking_existingval(soft)
        if 'Linux' in checkval:
            return soft["name"], soft["version"]
    for soft in software:
        checkval = checking_existingval(soft)
        if 'SUSE' in checkval:
            return soft["name"], soft["version"]
    for soft in software:
        checkval = checking_existingval(soft)
        if 'Oracle' in checkval:
            return soft["name"], soft["version"]
    for soft in software:
        checkval = checking_existingval(soft)
        if 'Server' in checkval:
            return soft["name"], soft["version"]
    for soft in software:
        checkval = checking_existingval(soft)
        if 'Microsoft' in checkval:
            return soft["name"], soft["version"]
    for soft in software:
        checkval = checking_existingval(soft)
        if 'Windows' in checkval or 'OSX' in checkval or 'IBM' in checkval or 'Cisco' in checkval:
            return soft["name"], soft["version"]
    return software[0]['name'],software[0]['version']


path = os.path.join(os.path.dirname(__file__), 'reports')

for filename in os.listdir(path):
    if not filename.endswith('.xml'): continue
    fullname = os.path.join(path, filename)

    parser = ET.XMLParser(recover=True)
    tree = ET.parse(fullname, parser)
    root = tree.getroot()

    print("===================================")
    for vulners_base in root.iter('{http://www.ptsecurity.ru/reports}vulners'):
        for vulners in vulners_base.iter('{http://www.ptsecurity.ru/reports}vulner'):

            vulner_title = ''
            vulner_cve = []
            vulner_cvss = ''
            vulner_crit = ''
            vulner_descr = ''
            vulner_short_descr = ''
            vulner_fix = ''
            vuln_parse = 0
            vuln_with_cve = 0
            vuln_bid = ''
            vuln_id = ''

            for vulner in vulners.iter():

                if vulner.tag == '{http://www.ptsecurity.ru/reports}vulner':
                    vulner_id = vulner.get('id')

                if vulner.tag == '{http://www.ptsecurity.ru/reports}title':
                    vuln_parse = 1
                    vulner_title = vulner.text

                if vulner.tag == '{http://www.ptsecurity.ru/reports}short_description' and vuln_parse == 1:
                    vulner_short_descr = vulner.text

                if vulner.tag == '{http://www.ptsecurity.ru/reports}description' and vuln_parse == 1:
                    vulner_descr = vulner.text

                if vulner.tag == '{http://www.ptsecurity.ru/reports}cvss' and vuln_parse == 1:
                    vulner_cvss = vulner.get('base_score')

                if vulner.tag == '{http://www.ptsecurity.ru/reports}global_id' and vuln_parse == 1 and vulner.get('name') == 'CVE':
                    vulner_cve.append(vulner.get('value'))
                    vuln_with_cve = 1

                if vulner.tag == '{http://www.ptsecurity.ru/reports}global_id' and vuln_parse == 1 and vulner.get('name') == 'BID':
                    vulner_bid = vulner.get('value')

                if vulner.tag == '{http://www.ptsecurity.ru/reports}how_to_fix' and vuln_parse == 1:
                    vulner_fix = vulner.text


            if (vuln_with_cve == 1):
                # print(u" - ID: {}".format(vulner_id))
                # print(u" - Title: {}".format(vulner_title))
                # print(u" - Short Description: {}".format(vulner_short_descr))
                # print(u" - Description: {}".format(vulner_descr))
                # print(u" - CVSS: {}".format(vulner_cvss))
                # print(u" - BID: {}".format(vulner_bid))
                # print(u" - CVE: {}".format(vulner_cve))
                # print(u" - FIX: {}".format(vulner_fix))
                vuln_db_global.append({'id': vulner_id, 'title': vulner_title, 'short_desc': vulner_short_descr, 'desc': vulner_descr, 'cvss': vulner_cvss, 'cve': vulner_cve, 'bid': vulner_bid, 'fix': vulner_fix})
                vuln_with_cve = 0
                vuln_parse = 0

    for host_base in root.iter('{http://www.ptsecurity.ru/reports}host'):

        host_db = {}
        host_db['sw'] = []
        host_db['mac'] = ''
        host_db['os_name'] = ''
        host_db['os_version'] = ''
        host_db['mac'] = ''
        host_db['services'] = []
        host_db['vulnerability'] = []

        for host in host_base.iter():

            if host.tag == '{http://www.ptsecurity.ru/reports}host':
                host_db['ip'] = host.get('ip')
                print("IP: " + host_db['ip'])
            if host.tag == '{http://www.ptsecurity.ru/reports}soft':
                sw_name = ''
                sw_ver = ''
                found_network = 0
                for soft in host.iter():
                    if soft.tag == '{http://www.ptsecurity.ru/reports}name' and soft.text == 'Network Configuration':
                        found_network = 1
                    if soft.tag == '{http://www.ptsecurity.ru/reports}name' and soft.text != 'Network Configuration':
                        sw_name = soft.text
                    if soft.tag == '{http://www.ptsecurity.ru/reports}version' and soft.text != 'Network Configuration':
                        sw_ver = soft.text
                        host_db['sw'].append({'name': sw_name, 'version': sw_ver})
                        sw_name = ''
                        sw_ver = ''

                    if soft.tag == '{http://www.ptsecurity.ru/reports}vulner':
                        vulner_id = soft.get('id')
                        vulnerability_item = {}

                        vulnerability_item = search_vulnerdb(vulner_id)
                        if 'title' in vulnerability_item.keys():
                            host_db['vulnerability'].append(vulnerability_item)

                    if soft.tag == '{http://www.ptsecurity.ru/reports}vulners' and found_network == 1:
                        for vulners in soft.iter('{http://www.ptsecurity.ru/reports}vulner'):

                            for vulner in vulners.iter():

                                if vulner.tag == '{http://www.ptsecurity.ru/reports}param' and vulner.text:

                                    if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", vulner.text.lower()) and len(vulner.text) > 0:
                                        host_db['mac'] = vulner.text

                                for services in vulner.iter('{http://www.ptsecurity.ru/reports}row'):
                                    fieldnum = 1
                                    protocol = ''
                                    port = ''
                                    service = ''

                                    for service in services.iter('{http://www.ptsecurity.ru/reports}field'):
                                        if fieldnum == 1 and not ('tcp' in service.text or 'udp' in service.text):
                                            break

                                        if fieldnum == 1 and ('tcp' in service.text or 'udp' in service.text):
                                            protocol = service.text
                                            # print("PROTOCOL: " + protocol)
                                        if fieldnum == 3:
                                            port = service.text
                                        if fieldnum == 5:
                                            service = service.text

                                        fieldnum = fieldnum + 1

                                    if (fieldnum == 6):
                                        host_db['services'].append({'proto': protocol, 'port': port, 'service': service})
                            # print(host_db['services'])
                            host_db['services'] = []
                    elif soft.tag == '{http://www.ptsecurity.ru/reports}vulners' and found_network != 1:
                        # Second type of Packages in TABLE
                        for packages in soft.iter('{http://www.ptsecurity.ru/reports}table'):
                            if packages.get('name') == 'Genpackages':
                                for pack in packages.iter('{http://www.ptsecurity.ru/reports}row'):
                                    sw_name = ''
                                    sw_ver = ''
                                    n = 0
                                    for pack_field in pack.iter('{http://www.ptsecurity.ru/reports}field'):
                                        if (n == 0):
                                            sw_name = pack_field.text
                                        elif (n == 1):
                                            sw_ver = pack_field.text
                                        n = n + 1
                                        # print(pack_field.tag, pack_field.text)
                                    host_db['sw'].append({'name': sw_name, 'version': sw_ver})
                                    sw_name = ''
                                    sw_ver = ''
        host_db['os_name'], host_db['os_version'] = guess_os(host_db['sw'])

        host_db_global.append({'ip': host_db['ip'], 'mac': host_db['mac'], 'os_name': host_db['os_name'],
                               'os_version': host_db['os_version'], 'sw': host_db['sw'],
                               'services': host_db['services'], 'vulnerability': host_db['vulnerability']})

# Writing CSV
# csv = iterate_export();

for host in host_db_global:
    csv = iterate_export();

    csv.write(u"AddHost, {}, {}\n".format(host['ip'], host['mac']))
    lb_count = lb_count + 1
    csv.write(u"SetMap, MaxPatrolMap\n")
    lb_count = lb_count + 1
    csv.write(u"SetOS, {}, {}, {}, {}\n".format(host['ip'], host['os_name'], host['os_name'], host['os_version']))
    lb_count = lb_count + 1

    for service in host['services']:
        csv.write(u"AddService, {}, {}, {}, , {}\n".format(host['ip'], service['port'], service['proto'], service['service']))
        lb_count = lb_count + 1

    for software in host['sw']:
        csv.write(u"AddClientApp, {}, {}, , {}\n".format(host['ip'], software['name'], software['version']))
        lb_count = lb_count + 1


    for vulnerability in host['vulnerability']:
        if isinstance(vulnerability, dict):

            if (vulnerability["fix"]):
                fix = vulnerability["fix"]
            else:
                fix = ''
            if (vulnerability["desc"]):
                desc = vulnerability["desc"]
            elif (vulnerability["short_desc"]):
                desc = vulnerability["short_desc"]
            else:
                desc = ''
            csv.write(u"AddScanResult, {}, \"MaxPatrol\", {}, {}, {}, \"{}\", \"{}\", \"cve_ids: {}\", \"bugtraq_ids: {}\"\n".format(
            host['ip'],
            vulnerability['id'],
            '',
            '',
            unicode(translate("CVSS: " +  vulnerability["cvss"] + " " + vulnerability["title"]), "utf-8"),
            unicode(translate(desc + fix), "utf-8"),
                " ".join(vulnerability["cve"]),
            vulnerability['bid']))
            lb_count = lb_count + 1

csv.write(u"ScanFlush\n")
csv.close()