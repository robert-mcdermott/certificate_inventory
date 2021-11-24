#!/usr/bin/python3
"""
Short Description:  SSL/TLS Certificate Inventory Script
Long Description:   A script that interrogates the provided CIDR network ranges, finds HTTPS web servers
                    running on the desired port(s) and gathers provides a report to standard output in
                    CSV format, containing the following columns:

                      - IP Address
                      - DNS hostname of the IP address (reverse lookup)
                      - Subject (hostname) of the certificate
                      - The issuer of the certificate
                      - The start date of the certificate
                      - The expiration data of the certificate
                      - Number of days util/past expiration
                      - Expired boolean - True or False
                      - The unique fingerprint of the certificate
                    
                    This is a quick hackish was to do this and needs a lot of improvements
"""
import configparser
import datetime
import ipaddress
import os
import random
import socket
import sys
import ssl
import urllib.request

def main():
    print("IP:port, DNS Hostname, Certificate Name, Issuer, Start Date, Expiration Date, Days Until Expiration, Expired, Fingerprint")
    ips = allips(subnets)
    random.shuffle(ips)
    for ip in ips:
        for port in ports:
            if isalive(ip, port):
                print(getcertinfo(ip, port))
                sys.stdout.flush()


def getcertinfo(ip, port):
    """Takes an IP and port number and returns information about the certificate and host. The 
    parsing of the fields is an attempt to just get the basic information as some certificates
    have some very verbose infomation that is not useful for a report of this type. This hackish
    parsing should be replaced with some more elegant regular expressions.
    """
    # run the openssl commandline utility and return the results
    out = os.popen(cmd % (ip, port)).readlines()
    
    # there is com variation about spacing after CN ('CN=' and 'CN ='), standardize it
    out = [x.replace(" =", "=") for x in out]

    # Get the certificate name 
    cert = out[0].split("CN=")[-1].split("/")[0].split(',')[0].strip().lower()
    
    # Get the CA that issued the certificate
    issuer = out[1].split("CN=")[-1].split(",")[0].split("/")[0].strip()
    
    # Get expiration date info
    expire_date_str = out[2].split("=")[-1].strip()
    expire_date = datetime.datetime.strptime(expire_date_str, '%b %d %H:%M:%S %Y %Z') 
    expire_delta_days = (expire_date - now).days
    expired = expire_date <= now  # is it expired? True or False
    expire_date_short = expire_date.strftime("%Y-%m-%d")
    
    # Get issued date info
    start_date_str = out[3].split("=")[-1].strip()
    start_date = datetime.datetime.strptime(start_date_str, '%b %d %H:%M:%S %Y %Z')
    start_date_short = start_date.strftime("%Y-%m-%d")
    
    # Unique certifcat signature
    fingerprint = out[4].split("=")[-1].strip()
    
    # Reversse lookup of the IP address in DNS 
    hostname = dnsname(ip)
    return "%s:%s, %s, %s, %s, %s, %s, %s, %s, %s" % (ip, port, hostname, cert, issuer, start_date_short, expire_date_short, expire_delta_days, expired, fingerprint)


now = datetime.datetime.now()
expire_date = "Mar 26 00:00:00 2018 GMT"
expire_date_dt = datetime.datetime.strptime(expire_date, '%b %d %H:%M:%S %Y %Z')
expire_date_short = expire_date_dt.strftime("%Y-%m-%d")
age = (expire_date_dt - now).days

def isalive(ip, port):
    """Takes and IP address and port and returns True if an HTTPS web server is located at that
    IP/port and False if not.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    host = "https://%s:%s" % (ip, port) 
    try:
        socket.setdefaulttimeout(1)
        code = urllib.request.urlopen(host, context=ctx).getcode()
        return True
    except urllib.error.URLError:
        return False
    except:
        return False 

def cidr2ip(cidr):
    """Take a network CIDR range and return a list of IP addresses"""
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr)]
    except:
        print("Error: Invalid CIDR range defined\n")
        sys.exit(1)


def allips(subnets):
    """Takes a CIDR formated (192.160.1.0/24) subnet and returns a list of all the individual
    IP addresses that the provided CIDR contains. /32 is as single IP address CIDR.
    """
    ips = []
    for subnet in subnets:
        ips.extend(cidr2ip(subnet))
    return ips


def dnsname(ip):
    """Returns the DNS hostname of the provided IP address if it's in DNS (PTR record)"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return 'null' 

if __name__ == "__main__":
    cmd ="echo -n| openssl s_client -connect %s:%s 2>/dev/null | openssl x509 -noout -subject -issuer -enddate -startdate -fingerprint"
    now = datetime.datetime.now()
    
    configfile = 'config.ini'
    if not os.path.exists(configfile):
        print("Error: configuration file '%s' missing\n" % configfile)
        sys.exit(1)
    config = configparser.ConfigParser()
    config.read(configfile)
    subnets = [x.strip() for x in config.get('config', 'subnets').split()]
    ports = [x.strip() for x in config.get('config', 'ports').split()]

    main()
