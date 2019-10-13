import os
import sys
from subprocess import check_output, CalledProcessError

import sublime
from sublime import error_message, status_message
import sublime_plugin

import requests


SETTINGS_FILE = "IPTools.sublime-settings"

IP_INFO_TEMPLATE = """
<div style="color: black; background-color: white; padding: 10px;">
    <h3>IP Info for: {ipaddr}</h3>
    <strong>Host Name</strong> {hostname} <a href='{hostname}'>Copy</a><br>
    <strong>Organisation</strong> {org} <a href='{org}'>Copy</a><br>
    <strong>City</strong> {city} <a href='{city}'>Copy</a><br>
    <strong>Region</strong> {region} <a href='{region}'>Copy</a><br>
    <strong>Country</strong> {country} <a href='{country}'>Copy</a><br>
    <strong>Time Zone</strong> {timezone} <a href='{timezone}'>Copy</a><br>
    <strong>Location</strong> {loc} <a href='{loc}'>Copy</a>
</div>
"""


def check_ip_lookup_cmd(value):
    pass
# End config validator functions


# This dictionary specifies additional functions to do in-depth validation
# of plugin settings. For instance, there may be a Python 3 path defined,
# but does it actually exist and is it actually a directory?
config_validators = {
    "ip_lookup_cmd": check_ip_lookup_cmd,
}


def get_selections(view):
    sel = view.sel()
    strs = [view.substr(s) for s in sel]
    return strs


def modify_sys_path(newpath):
    sys.path.append(newpath)
    print("Added {} to import paths".format(newpath))


def plugin_loaded():
    pass


def get_settings_path():
    """
    Convenience function to provide the fully resolved path to this
    plugin's settings file.
    """
    return os.path.join(sublime.packages_path(), SETTINGS_FILE)


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
    settings = sublime.load_settings(SETTINGS_FILE)

    whois_url = settings.get("whois_lookup_url")
    if whois_url is None:
        error_message((
            "No WHOIS lookup URL is defined!\n"
            "Please specify the 'whois_lookup_url' in the settings file.\n"
            "Settings file: {}.".format(get_settings_path()))
        )
        return None

    target = lookup_target.strip()
    response = requests.get(sublime.expand_variables(
        whois_url, {"lookup_target": target}))

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
    settings = sublime.load_settings(SETTINGS_FILE)

    cmd = settings.get("ip_lookup_cmd")

    # Do we actually have a lookup command configured?
    if cmd is None:
        error_message((
            "No IPv4 Address lookup command is defined!\n"
            "Please specify the 'ip_lookup_cmd' in the settings file.\n"
            "Settings file: {}.".format(get_settings_path()))
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
    except FileNotFoundError as fnfe:
        error_message((
            "Failed performing DNS lookup!\n"
            "Your configured 'ip_lookup_cmd' doesn't apper to exist!."))
        return None

    return [l.decode('utf-8') for l in output.splitlines()]


class GeoIpLookupCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        ip_addr = get_selections(self.view)[0]
        ip_info = geo_ip_lookup(ip_addr)

        if ip_info is None:
            error_message("No results were returned for '{}'".format(ip_addr))
            status_message("No results were returned for '{}'".format(ip_addr))
            return

        country_str = self.extract_geoip_property(ip_info, "country")
        org_str = self.extract_geoip_property(ip_info, "org")
        loc_str = self.extract_geoip_property(ip_info, "loc")
        city_str = self.extract_geoip_property(ip_info, "city")
        region_str = self.extract_geoip_property(ip_info, "region")
        timezone_str = self.extract_geoip_property(ip_info, "timezone")
        hostname_str = self.extract_geoip_property(ip_info, "hostname")

        html_content = IP_INFO_TEMPLATE.format(
            ipaddr=ip_addr,
            hostname=hostname_str,
            city=city_str,
            region=region_str,
            country=country_str,
            timezone=timezone_str,
            org=org_str,
            loc=loc_str)
        self.view.show_popup(
            html_content, on_navigate=self.copy_to_clipboard,
            max_width=400, max_height=500,
            flags=sublime.HIDE_ON_MOUSE_MOVE_AWAY,)

    def copy_to_clipboard(self, href_content):
        if href_content:
            sublime.set_clipboard(href_content)
            self.view.hide_popup()

    def extract_geoip_property(self, result, propname):
        outvalue = result[propname] if propname in result else '<Not specified>'
        return outvalue


class DnsIpLookup(sublime_plugin.TextCommand):
    def run(self, edit):
        hostname = get_selections(self.view)[0]
        addresses = get_addresses(hostname)
        if addresses is not None:
            out_lines = []
            for address in addresses:
                out_lines.append("{} <a href='{}'>Copy</a>".format(
                    address, address))
            self.view.show_popup("\n".join(out_lines),
                                 flags=sublime.HIDE_ON_MOUSE_MOVE_AWAY,
                                 on_navigate=self.copy_to_clipboard)
        else:
            status_message((
                "Either this name does not resolve or another "
                "error has occurred. Check the console for more details."))

    def copy_to_clipboard(self, href_content):
        if href_content:
            sublime.set_clipboard(href_content)
            self.view.hide_popup()


class WhoisLookup(sublime_plugin.TextCommand):
    def run(self, edit):
        target = get_selections(self.view)[0]
        if target:
            make_whois_request(target)


class ValidateIpToolsConfigCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        settings = sublime.load_settings(SETTINGS_FILE)

        whois_url = settings.get("whois_lookup_url")
        ip_lookup_cmd = settings.get("ip_lookup_cmd")
        python_3_path = settings.get("python_3_path")

        python_3_path_defined = "Yes" if python_3_path else "No"
        whois_url_defined = "Yes" if whois_url else "No"
        ip_lookup_cmd_defined = "Yes" if ip_lookup_cmd else "No"

        print("Python 3 Path:         {}".format(python_3_path_defined))
        print("WHOIS URL:             {}".format(whois_url_defined))
        print("DNS IP Lookup Command: {}".format(ip_lookup_cmd_defined))