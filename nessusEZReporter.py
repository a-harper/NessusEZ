import xml.etree.ElementTree as ET
import ipaddress
import os
import sys
import string
import random
import shutil
import fileinput

reportname = ""


class Issue:
    nessus_id = ""
    name = ""
    risk = ""
    cvss3 = ""
    references = ""
    hosts = []
    description = ""
    recommendation = ""
    synopsis = ""
    summary = ""

def loader(target):
    """
        Works out whether to load a single file or a directory of files
    """
    filelist = []
    if os.path.isdir(target):
        # It's a directory
        for file in os.listdir(target):
            if file.endswith(".nessus"):
                filelist.append(os.path.abspath(os.path.join(target, file)))
    else:
        # Not a directory
        filelist.append(os.path.abspath(target))
    return filelist


def main():
    files = loader(sys.argv[1])
    issues = []
    xmlpath = []
    for file in files:
        print("Loading file: ", file)
        tree = ET.parse(file)
        root = tree.getroot()
        # Let's get the report name
        report_tag = root.findall(".//Report")
        if not report_tag:
            print("This file doesn't appear to be valid.")
            break
        # Let's get prefs
        prefs_tag = root.findall(".//Preferences")
        if not prefs_tag:
            print("This file doesn't appear to be valid.")
            break
        prefs = prefs_tag[0]
        sprefs = prefs[0]
        found = False
        x = 0
        targs = ""
        while not found:
            if sprefs[x][0].text == 'TARGET':
                found = True
                targs = sprefs[x][1].text.split(',')
            x += 1
        print("Report name: ", report_tag[0].attrib["name"])
        print("Report targets: ", targs)

        report_hosts = root.findall(".//ReportHost")
        for host in report_hosts:
            cur_host = host.attrib['name']
            host_items = host.findall(".//ReportItem")
            for item in host_items:
                desc = ""
                cvss3 = ""
                recommendation = ""
                synopsis = ""
                summary = ""
                plugin_id = item.attrib['pluginID']
                plugin_name = item.attrib['pluginName']
                port = item.attrib['port']
                severity = item.attrib['severity']
                for tag in item:
                    if tag.tag == 'description':
                        desc = tag.text
                    if tag.tag == 'cvss3_vector':
                        cvss3 = tag.text
                    if tag.tag == 'solution':
                        recommendation = tag.text
                    if tag.tag == 'synopsis':
                        synopsis = tag.text
                    if tag.tag == 'plugin_output':
                        summary = tag.text
                if not any(x.nessus_id == plugin_id for x in issues):
                    iss = Issue()
                    iss.nessus_id = plugin_id
                    iss.name = plugin_name
                    iss.hosts = []
                    iss.risk = severity
                    iss.description = desc
                    iss.cvss3 = cvss3
                    iss.synopsis = synopsis
                    iss.recommendation = recommendation
                    iss.hosts.append((cur_host, ipaddress.ip_address(cur_host), [[port, summary]]))
                    iss.hosts.sort(key=lambda i: i[1])
                    issues.append(iss)
                else:
                    iss = [x for x in issues if x.nessus_id == plugin_id][0]
                    host_exist = next((x for x in iss.hosts if x[0] == cur_host), None)
                    if host_exist:
                        port_exist = next((x for x in host_exist[2][0] if x == port), None)
                        if not port_exist:
                            host_exist[2].append([port, summary])
                            host_exist[2].sort(key=lambda y: int(y[0]))
                    else:
                        iss.hosts.append((cur_host, ipaddress.ip_address(cur_host), [[port, summary]]))
                        iss.hosts.sort(key=lambda i: i[1])

    # Time to generate the report
    html = ""
    issues.sort(key=lambda z: int(z.risk), reverse=True)
    for issue in issues:
        ident = ''.join(random.choices(string.ascii_lowercase, k=5))
        while ident in html:
            ident = ''.join(random.choices(string.ascii_lowercase, k=5))
        ident2 = ''.join(random.choices(string.ascii_lowercase, k=5))
        while ident2 in html:
            ident2 = ''.join(random.choices(string.ascii_lowercase, k=5))
        html += '<div class="accordion-item"><h5 class="accordion-header" id="{2}"><button class="accordion-button-collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#{3}">{0} - PluginID: {1}</button></h5></div>'.format(issue.name, issue.nessus_id, ident2, ident)
        html += '<div id="{0}" class="accordion-collapse collapse" data-bs-parent="#accordionFlushExample">'.format(ident)
        html += '<div class="accordion-body">'
        html += '<div><b>Affected hosts:</b> {0}</div>'.format(', '.join([n[0] for n in issue.hosts]))
        html += '<div><b>Nessus Risk:</b> {0}</div>'.format(issue.risk)
        html += '<div><b>CVSS:</b> {0}</div>'.format(issue.cvss3)
        html += '<div><b>Description:</b> {0}</div>'.format(issue.description)
        html += '<div><b>Synopsis:</b> {0}</div>'.format(issue.synopsis)
        html += '<div><b>Recommendation:</b> {0}</div>'.format(issue.recommendation)
        html += '<br /><br />'
        html += '<div><h5>Specific port details:</h5></div>'
        for host in issue.hosts:
            html += '<div>{0}: {1}</div>'.format(host[0], ', '.join([n[0] for n in host[2]]))
        html += '<br /><br />'
        html += '<div><h5>Port Specific Plugin Output:</h5></div>'
        for host in issue.hosts:
            html += '<div><h6>{0}</h6></div>'.format(host[0])
            for port in host[2]:
                html += '<div><h7><b>Port: {0}</b></h7></div>'.format(port[0])
                html += '<div><b>Tool output:</b> <pre>{0}</pre></div>'.format(port[1])
                html += '<br />'
        html += '<br /></div></div>'
        html += '<br />'
    template = 'template.html'
    outfile = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
    destination = outfile + '.html'
    out = shutil.copyfile(template, destination)
    with fileinput.FileInput(destination, inplace=True) as file:
        for line in file:
            print(line.replace('{{ content }}', html), end='')
main()
