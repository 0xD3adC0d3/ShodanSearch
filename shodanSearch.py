#!/usr/bin/python

'''
Usage: shodan_search.py [-h] [-v] [-s SEARCH] [-l]

Perform searches on Shodan

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Enable verbose output
  -s SEARCH      The search query
  -l             Print location information
'''

import argparse
import logging
import shodan
import sys

API_KEY = "CENSORED"

parser = argparse.ArgumentParser(description='Perform searches on Shodan')

parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output', default=False)
parser.add_argument('-s', action="store", dest="search", help="The search query")
parser.add_argument('-l', action="store_true", dest="location", help="Print location information")

args = parser.parse_args()

if len(sys.argv) < 3 or args.search is None:
    parser.print_help()
    sys.exit(1)
    
level = logging.DEBUG if args.verbose else logging.INFO
logging.basicConfig(level=level, format='[%(asctime)s.%(msecs)03d]  %(message)s', datefmt="%Y-%m-%d %H:%M:%S")

try:
        logging.debug("[D] Configuring the API Key")
        api = shodan.Shodan(API_KEY)
        
        logging.debug("[D] Search query : " + args.search)
        
        result = api.search(args.search)
        
        total = result['total'] 
        matches = result['matches']
        
        logging.info("[I] Number of results : " + str(total))

        for service in result['matches']:
                headStr = "# [I] IP address : " + str(service['ip_str']) + " #"
                logging.info("#" * len(headStr))
                logging.info(headStr)
                logging.info("#" * len(headStr))
                
                logging.info("[I] ASN : " + str(service['asn']))
                logging.info("[I] ISP : " + str(service['isp']))
                logging.info("[I] Organization : " + str(service['org']))
                
                for d in service['domains']:
                        logging.debug("[I] Domain : " + str(d))
                        
                for h in service['hostnames']:
                        logging.debug("[I] Hostname : " + str(h))
                
                logging.debug("[I] OS : " + str(service['os']))
                logging.debug("[I] Transport protocol : " + str(service['transport']))
                logging.debug("[I] Port : " + str(service['port']))
                logging.debug("[I] Data : " + str(service['data']))
                
                if args.location:
                        loc = service['location']
                        logging.info("[I] City : " + str(loc['city']))
                        logging.info("[I] Region : " + str(loc['region_code']))
                        logging.info("[I] Postal code : " + str(loc['postal_code']))
                        logging.info("[I] Country : " + str(loc['country_name']))
                        logging.info("[I] Country code : " + str(loc['country_code']))
                        logging.info("[I] Longitude : " + str(loc['longitude']))
                        logging.info("[I] Latitude : " + str(loc['latitude']))
except Exception as e:
        logging.debug("[D] Exception : " + str(e))
        sys.exit(1)