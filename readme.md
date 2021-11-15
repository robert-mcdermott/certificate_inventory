# SSL/TLS Certificate Inventory 

## Description 

A script that interrogates the provided CIDR network ranges, finds HTTPS web servers running on the desired port(s) and gathers provides a report to standard output in CSV format, containing the following columns:
- IP Address
- DNS hostname of the IP address (reverse lookup)
- Subject (hostname) of the certificate
- The issuer of the certificate
- The start date of the certificate
- The expiration data of the certificate
- The unique fingerprint of the certificate   

This is a quick hackish was to do this and needs a lot of improvements

## Requirements

- Linux operating system (tested on Ubuntu 18.04)
- Openssl command-line utility (sudo apt install openssl)
- Python 3.x


## Usage

Edit the configuration file "config.ini" and define the subnets that you want to interrogate in valid CIDR format and the ports that you want check for HTTPS web servers. Each subnet and port has to be on its own line and indented in the correct sections as shown below:

```ini
[config]
subnets = 
    192.168.0.0/24
    172.17.64.0/28
ports =
    443
```

After the configuration is in place, run the following command from a host that has access to the configured networks. In this example the report will be located in the file 'cert-inventory-2021-11-15.csv'.

```bash
python3 certificate_inventory.py > cert-inventory-2021-11-15.csv
```
