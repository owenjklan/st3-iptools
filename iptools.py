from importlib import import_module
import os
import sys
from subprocess import check_output, CalledProcessError

import sublime
from sublime import error_message, message_dialog, status_message
import sublime_plugin


global requests


IP_INFO_TEMPLATE = """
<div style="color: black; background-color: white;">
<h3>IP Info for: {ipaddr}</h3>
<p><strong>Country</strong> {country}</p>
<p><strong>Organisation</strong> {org}</p>
<p><strong>Location</strong> {loc}</p>
</div>
"""


def get_selections(view):
    sel = view.sel()
    strs = [view.substr(s) for s in sel]
    return strs


def modify_sys_path(newpath):
    sys.path.append(newpath)
    print("Added {} to import paths".format(newpath))


def plugin_loaded():
    global requests

    settings = sublime.load_settings("IPTools.sublime-settings")
    py3_path = settings.get("python_3_path")
    print("Found python3 system packages path: {}".format(py3_path))
    if py3_path:
        modify_sys_path(py3_path)

        # Import our system-provided custom modules, like Requests
        requests = import_module("requests")
        print("Requests import successful")


def geo_ip_lookup(ip):
    GEOIP_URL = "https://ipinfo.io/{}/json"

    ip_url = GEOIP_URL.format(ip)

    response = requests.get(ip_url)

    try:
        ip_info = response.json()
    except ValueError as ve:
        return None
    return ip_info


def make_whois_request(lookup_target):
    """
    Make a WHOIS request against https://whois.com
    """
    WHOIS_URL = "https://whois.com/search.php?query={}"
    target = lookup_target.strip()
    response = requests.get(WHOIS_URL.format(target))

    if response.status_code != 200:
        error_message("Failed WHOIS look up on '{}'".format(target))
        print("--- WHOIS LOOKUP RESULT ---")
        print(response.content)
        print("---------------------------")
        return

    show_content = extract_raw_whois(response.content)


def extract_raw_whois(html_content):
    """
    Based on output of searches from https://whois.com
    """
    root = ET.fromstring(html_content)
    whois_raw = root.findall("//pre[@id='registryData']")
    print(whois_raw)


def get_addresses(hostname):
    hostname = hostname.strip()
    settings = sublime.load_settings("IPTools.sublime-settings")

    cmd = settings.get("ip_lookup_cmd")

    # Do we actually have a lookup command configured?
    if cmd is None:
        error_message((
            "No IPv4 Address lookup command is defined!\n"
            "Please specify the 'ip_lookup_cmd' in the settings file.\n"
            "Settings file: {}.".format(
                os.path.join(
                    sublime.packages_path(),
                    "IPTools.sublime-settings")))
        )
        return None

    # Take our single string command line and split into the 
    cmd = sublime.expand_variables(cmd, {"hostname": hostname})
    command = cmd.split()

    print("Dig IP lookup: {}".format(command))
    print("Performing IPv4 address lookup on: {}".format(hostname))

    try:
        output = check_output(command)
    except CalledProcessError as cpe:
        status_message(str(cpe))
        return None
    # except FileNotFoundError as fnfe:
    #     error_message(("Failed performing DNS lookup!\n"
    #         "Your configured 'ip_lookup_cmd' doesn't apper to work."))
    #     return None

    return [l.decode('utf-8') for l in output.splitlines()]


class GeoIpLookupCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        ip_addr = get_selections(self.view)[0]
        ip_info = geo_ip_lookup(ip_addr)

        if ip_info is None:
            error_message("No results were returned for '{}'".format(ip))
            status_message("No results were returned for '{}'".format(ip))
            return

        country_str = ip_info['country'] if 'country' in ip_info else '<Not specified>'
        org_str = ip_info['org'] if 'org' in ip_info else '<Not specified>'
        loc_str = ip_info['loc'] if 'loc' in ip_info else '<Not specified>'

        html_content = IP_INFO_TEMPLATE.format(
            ipaddr=ip_addr,
            country=country_str,
            org=org_str,
            loc=loc_str)
        self.view.show_popup(html_content, max_width=400, max_height=500)


class DnsIpLookup(sublime_plugin.TextCommand):
    def run(self, edit):
        hostname = get_selections(self.view)[0]
        addresses = get_addresses(hostname)
        if addresses is not None:
            self.view.show_popup("\n".join(addresses),
                                 flags=sublime.HIDE_ON_MOUSE_MOVE_AWAY)
        else:
            status_message((
                "Either this name does not resolve or another "
                "error has occurred. Check the console for more details."))


class WhoisLookup(sublime_plugin.TextCommand):
    def run(self, edit):
        target = get_selections(self.view)[0]
        if target:
            make_whois_request(target)
