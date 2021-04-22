#!/usr/bin/python

 # 
 # This file is part of the zyxel-router-extract distribution (https://github.com/ or http://xxx.github.io).
 # Copyright (c) 2015 Liviu Ionescu.
 # 
 # This program is free software: you can redistribute it and/or modify  
 # it under the terms of the GNU General Public License as published by  
 # the Free Software Foundation, version 3.
 #
 # This program is distributed in the hope that it will be useful, but 
 # WITHOUT ANY WARRANTY; without even the implied warranty of 
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License 
 # along with this program. If not, see <http://www.gnu.org/licenses/>.
 #
import sys
import lzw
import logging as log
import re
import base64
from lxml import etree
import argparse

header_len = 60
header_pattern = '<compressed alg=lzw len=(\d+)>.+<crc=0x([0-9A-Fa-f]+)>'

def decode_password(p):
    return base64.b64decode(p).decode('utf-8').rstrip('\x00')

def extract_ppp_info(xmltree):
    return extract_username_password(xmltree, "//WANPPPConnection")

def show_users(xmltree):
    users = xmltree.xpath("//Use_Login_Info[@instance]")
    if len(users) == 0:
        log.warn("Found no users. Please report your configuration!")
        return
    print("Users configured on router: ")
    for u in users:
        username = u.xpath("./UserName/text()")
        if len(username) == 0:
            log.warn("Expected Username but didn't find one")
            continue
        username = username[0]
        password = u.xpath("./Password/text()")
        if len(password) == 0:
            log.warn("Expected Password but didn't find one")
            continue
        password = password[0]
        disabled = u.xpath("./Enable[text() = 'FALSE']")
        if len(disabled) == 0:
            disabled = ""
        else:
            disabled = "[DISABLED]"
        print("Username: {0}\t\tPassword: {1}\t{2}".format(username, decode_password(password), disabled))

def extract_wifi(xmltree):
    xpath = "//WlVirtIntfCfg[@instance and not(./WlEnblSsid = '0')]"
    wifi = []
    mynodes = xmltree.xpath(xpath)
    for node in mynodes:
        ssid = node.xpath("./WlSsid/text()")
        if len(ssid) == 0:
            log.warn("Skipping Wifi node without SSID.")
            continue
        ssid = ssid[0]
        authmode = node.xpath("./WlAuthMode/text()")
        if len(authmode) == 0:
            log.warn("Can't find authentication mode for WPA ssid '{0}'".format(ssid))
            authmode = "unknown"
        else:
            authmode = authmode[0]
        if 'psk' in authmode:
            log.info("Found WPA/PSK(2) authentication")
            psk = node.xpath("./WlWpaPsk/text()")
            if len(psk) == 0:
                log.warn("Can't find PreSharedKey for WPA ssid '{0}'".format(ssid))
                continue
            psk = psk[0]
        wifi.append({ 'ssid' : ssid, 'auth': authmode, 'key': psk })
    return wifi 

def show_ppp(xmltree):
    print("PPP configuration: ")
    ppp = xmltree.xpath("//WANPPPConnection[@instance and not(./Enable = 'FALSE')]")
    if len(ppp) == 0:
        log.warn("Couldn't find any PPP Configuration Info")
        return
    logins = []
    for p in ppp:
        username = p.xpath("./Username/text()")
        if len(username) == 0:
            log.warn("Expected Username but none found")
            continue
        username = username[0]
        password = p.xpath("./Password/text()")
        if len(password) == 0:
            log.warn("Expected Password but none found")
            continue
        password = password[0]
        up = (username, decode_password(password))
        if up not in logins:
            log.info("Adding new username '{0}' with password '{1}'".format(up[0], up[1]))
            logins.append(up)
        else:
            log.info("Username '{0}' with password '{1}' already exists. Skipping...".format(up[0], up[1]))
    for u, p in logins:
        print("Username: {0}\t\tPassword: {1}".format(u, p))

def show_wifi(xmltree):
    print("Wifi info: ")
    wifi_info = extract_wifi(xmltree)
    log.info(wifi_info)
    for w in wifi_info:
        print("SSID: '{0}'    Authentication: {1}     Password: '{2}'".format(w['ssid'], w['auth'], w['key']))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract Username and Password information from ZyXel Modem backup file.')
    parser.add_argument("filename", help="Name of the backup file saved from the router. E.g. 'configuration-backupsettings.conf'")
    parser.add_argument("-v", "--verbose", help="Provide more verbose output", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--config", help="Dump XML tree of configuration", action="store_true")
    group.add_argument("--users", help="Only show router user accounts", action="store_true")
    group.add_argument("--ppp", help="Only show PPP information", action="store_true")
    group.add_argument("--wifi", help="Only show Wifi information", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
        log.info("Verbose output.")
    else:
        log.basicConfig(format="%(levelname)s: %(message)s")

    filename = args.filename

    with open(filename, 'rb') as f:
        try:
            b = f.read(header_len)
        except Exception as e:
            log.info(e)
            log.critical("Failed to read from '{0}'".format(filename))
            sys.exit(1)

        match = re.search(header_pattern, str(b))
        if (not match):
            log.critical("File '{0}' does not look like a valid ZyXeL modem backup file.".format(filename))
            log.critical("Bad magic: was expecting file to match '{0}'".format(str(header_pattern)))
            sys.exit(1)
        try:
            data_len = int(match.group(1))
        except Exception as e:
            log.info(e)
            log.critical("Data length field is corrupt: '{0}'".format(match.group(1)))
            sys.exit(1)

        try:
            data_crc = int('0x' + match.group(2), 16)
        except Exception as e:
            log.info(e)
            log.critical("Data crc is corrupt: '{0}'".format(match.group(2)))
            sys.exit(1)


        log.info("File data has length of '{0}' with a crc of '{1}'".format(data_len, hex(data_crc)))

        try:
            compressed_data = f.read(data_len)
            log.info("Read '{0}' bytes from '{1}'".format(data_len, filename))
        except Exception as e:
            log.info(e)
            log.critical("Unable to read {0} bytes from '{1}'".format(data_len, filename))
            sys.exit(1)

        try:
            # the file has multiple "pages" so we need to use the "PagingDecoder" here
            decoder = lzw.PagingDecoder(initial_code_size=258)
            log.info("LZW Decompressing data...")
            r = b"".join([b"".join(pg) for pg in decoder.decodepages(compressed_data)])
            log.info("OK.")
        except Exception as e:
            log.info(e)
            log.critical("Data decompression failed! Possible file corruption.")
            sys.exit(1)

        try:
            # parse uncompressed data into xml tree
            log.info("Parsing XML data...")
            xmltree = etree.fromstring(r)
            log.info("OK")
        except Exception as e:
            log.info(r.decode('utf-8'))
            log.info(e)
            log.critical("Failed to generate XML tree! Possible file corruption.")
            sys.exit(1)

        if args.config:
            print(etree.tostring(xmltree, pretty_print=True).decode('utf-8'))
        elif args.users:
            show_users(xmltree)
        elif args.ppp:
            show_ppp(xmltree)
        elif args.wifi:
            show_wifi(xmltree)
        else:
            # default is show all except for config
            show_users(xmltree)
            print('')
            show_ppp(xmltree)
            print('')
            show_wifi(xmltree)
            print('')
