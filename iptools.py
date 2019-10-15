import os
import sys
from subprocess import check_output, CalledProcessError
import textwrap

import sublime
from sublime import error_message, status_message
import sublime_plugin

import requests
import bs4
from bs4 import BeautifulSoup


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

# Used to indicate whether HTTPS requests made with requests library should
# care about SSL Verification
ssl_verify = True


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
    global ssl_verify
    settings = sublime.load_settings(SETTINGS_FILE)
    ssl_verify = settings.get("requests_verify_ssl")
    # print("ssl_verify: ", ssl_verify)


def get_settings_path():
    """
    Convenience function to provide the fully resolved path to this
    plugin's settings file.
    """
    return os.path.join(sublime.packages_path(), SETTINGS_FILE)


def geo_ip_lookup(ip):
    GEOIP_URL = "https://ipinfo.io/{}/json"

    ip_url = GEOIP_URL.format(ip)

    print("{} verify SSL".format("Will" if ssl_verify else "Won't"))
    try:
        response = requests.get(ip_url, timeout=5, verify=ssl_verify)
    except requests.exceptions.ReadTimeout:
        error_message("Timeout reading GeoIP lookup response!")
        return
    except requests.exceptions.SSLError as ssle:
        if "verify failed" in str(ssle):
            display_ssl_verify_error()
            return
        error_message(("An SSL Error occurred!"))

    try:
        ip_info = response.json()
    except ValueError as ve:
        return None
    return ip_info


def display_ssl_verify_error():
    sublime.error_message((
        "A request to a HTTPS service has failed due to SSL verification "
        "errors. This may indicate that you are on a corporate or "
        "educational network, behind an SSL-intercepting proxy. To remedy "
        "this, you can disable SSL verification under the IPTools context"
        " menu."
    ))


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
        addresses = self.get_addresses(hostname)
        if addresses is not None:
            out_lines = []
            for address in addresses:
                out_lines.append("{} <a href='{}'>Copy</a>".format(
                    address, address))
            self.view.show_popup("\n".join(out_lines),
                                 flags=sublime.HIDE_ON_MOUSE_MOVE_AWAY,
                                 on_navigate=self.copy_to_clipboard)
        else:
            error_message((
                "Either this name does not resolve or another "
                "error has occurred. Check the console for more details."))

    def get_addresses(self, hostname):
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

    def copy_to_clipboard(self, href_content):
        if href_content:
            sublime.set_clipboard(href_content)
            self.view.hide_popup()


class DnsTxtLookup(sublime_plugin.TextCommand):
    def run(self, edit):
        hostname = get_selections(self.view)[0]
        records = self.get_text_records(hostname)
        print(records)
        if records is not None and len(records) > 0:
            out_lines = []
            for txt_record in records:
                out_lines.append("{} <a href='{}'>Copy</a><br>".format(
                    txt_record, txt_record))
            self.view.show_popup("\n".join(out_lines),
                                 flags=sublime.HIDE_ON_MOUSE_MOVE_AWAY,
                                 # min_width=400, min_height=500,
                                 on_navigate=self.copy_to_clipboard)
        elif len(records) == 0:
            error_message(("No TXT records exist for {}".format(hostname)))
        else:
            error_message((
                "Either this name does not resolve, has no TXT records or "
                " another error has occurred. "
                "Check the console for more details."))

    def get_text_records(self, hostname):
        hostname = hostname.strip()
        settings = sublime.load_settings(SETTINGS_FILE)

        cmd = settings.get("txt_lookup_cmd")

        # Do we actually have a lookup command configured?
        if cmd is None:
            error_message((
                "No TXT Record lookup command is defined!\n"
                "Please specify the 'txt_lookup_cmd' in the settings file.\n"
                "Settings file: {}.".format(get_settings_path()))
            )
            return None

        # Take our single string command line and split into the 
        cmd = sublime.expand_variables(cmd, {"hostname": hostname})
        command = cmd.split()

        print("Dig TXT lookup: {}".format(command))
        print("Performing TXT record lookup on: {}".format(hostname))

        try:
            output = check_output(command)
        except CalledProcessError as cpe:
            status_message(str(cpe))
            return None
        except FileNotFoundError as fnfe:
            error_message((
                "Failed performing DNS TXT lookup!\n"
                "Your configured 'txt_lookup_cmd' doesn't apper to exist!."))
            return None

        return [l.decode('utf-8') for l in output.splitlines() if len(l.strip()) > 0]

    def copy_to_clipboard(self, href_content):
        if href_content:
            sublime.set_clipboard(href_content)
            self.view.hide_popup()


class WhoisLookup(sublime_plugin.TextCommand):
    def run(self, edit):
        target = get_selections(self.view)[0]
        if target:
            self.make_whois_request(edit, self.view.window(), target)

    def make_whois_request(self, view_edit, window, lookup_target):
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
        try:
            print("{} verify SSL".format("Will" if ssl_verify else "Won't"))
            response = requests.get(sublime.expand_variables(
                whois_url, {"lookup_target": target}),
                timeout=5, verify=ssl_verify)
        except requests.exceptions.ReadTimeout:
            error_message("Timeout reading WHOIS response!")
            return
        except requests.exceptions.SSLError as ssle:
            if "verify failed" in str(ssle):
                display_ssl_verify_error()
                return
            error_message(("An SSL Error occurred!"))

        if response.status_code != 200:
            error_message("Failed WHOIS look up on '{}'".format(target))
            print("--- WHOIS LOOKUP RESULT ---")
            print(response.content)
            print("---------------------------")
            return

        show_content = self.extract_raw_whois(response.content)
        new_view = window.new_file()
        new_view.set_name("WHOIS: {}".format(lookup_target))
        new_view.insert(view_edit, 0, show_content)

    def extract_raw_whois(self, html_content):
        """
        Based on output of searches from https://whois.com
        """
        soup = BeautifulSoup(html_content)
        raw_content = soup.find("pre", {"id": "registryData"})

        if raw_content is None:
            # Try looking for "registrarData"
            raw_content = soup.find("pre", {"id": "registrarData"})

        return raw_content.text.replace('\r\n', '\n')


class SetSslVerifyCommand(sublime_plugin.WindowCommand):
    def run(self):
        global ssl_verify
        if ssl_verify:
            # Alert to be sure this is what the user wants to do
            confirm_disable_verify = sublime.ok_cancel_dialog(
                ("Disabling SSL Verification can open you up to security "
                 "risks! Only disable this if you know what you're doing."),
                ok_title="Disable Verification"
            )
            if confirm_disable_verify == True:
                ssl_verify = False
        else:
            ssl_verify = True
        settings = sublime.load_settings(SETTINGS_FILE)
        settings.set("requests_verify_ssl", ssl_verify)

    def is_checked(self):
        return ssl_verify


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
