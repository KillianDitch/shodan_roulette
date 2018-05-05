#!/usr/bin/python3

# Insert Shodan API Key. DELETE IF SHARING!
SHODAN_API_KEY = "SHODAN_API_KEY"


import random
import ipaddress
import shodan
import time
from collections import OrderedDict

# Initialize API key
api = shodan.Shodan(SHODAN_API_KEY)


# Generate IP Address
def roll_ip():
    # Create random ipaddress object from 0 to max IP address as int
    random_ip = ipaddress.ip_address(random.randint(0,2147483647))
    # Reroll IP address if RFC1918
    if random_ip.is_private:
        print("Rerolling external IP")
        # I guess recursion requires returning everything
        return str(roll_ip())
    else:
        # Return the valid external IP address as a string
        return str(random_ip)


# Strip Shodan datapoints will None/Null values
def trim_host(host):
    label_dict = OrderedDict([
              ('country_code', "Country Code: "),
              ('country_code3', "Country Code3: "),
              ('country_name', "Country Name: "),
              ('area_code', "Area Code: "),
              ('region_code', "Region Code: "),
              ('city', "City: "),
              ('postal_code', "Postal Code: "),
              ('latitude', "Latitude: "),
              ('longitude', "Longitude: "),
              ('asn', "ASN: "),
              ('org', "Org: "),
              ('isp', "ISP: "),
              ('hostnames', "Hostnames: "),
              ('ip', "IP: "),
              ('ip_str', "IP Str: "),
              ('ports', "Ports: "),
              ('os', "OS: "),
              ('dma_code', "DMA Code: "),
              ('tags', "Tags: "),
              ('data', "Data: "),
              ('last_update', "Last Update: ")])
    
    # Remove label and element if element value is None/Null
    trimmed_host = dict(host)
    for element,value in trimmed_host.items():
        if str(value) == "None" or value == []:
            del(trimmed_host[element])
            del(label_dict[element])
    
    pad = "-"*75
    
    # Build output
    host_output = ""
    for label in label_dict:
        if (label == 'country_code' or label == 'country_code3' or label == 'country_name' or label == 'area_code' or label == 'region_code' 
            or label == 'city' or label == 'postal_code'or label == 'latitude'or label == 'longitude'or label == 'asn'or label == 'org'):
            if "Location" not in host_output:
                host_output += "\r\nLocation\r\n" + pad + "\r\n"
            host_output += "{:<15}{:>60}\r\n".format(label_dict[label],trimmed_host[label])
            
        elif (label == 'isp' or label == 'hostnames' or label == 'ip' or label == 'ip_str' or label == 'ports'):
            if "Internet" not in host_output:
                host_output += "\r\nInternet\r\n" + pad + "\r\n"
            host_output += "{:<15}{:>60}\r\n".format(label_dict[label],trimmed_host[label])
            
        elif label == 'os' or label == 'dma_code' or label == 'tags' or label == 'data' or label == 'last_update':
            if "General" not in host_output:
                host_output += "\r\nGeneral\r\n" + pad + "\r\n"
            host_output += "{:<15}{:>60}\r\n".format(label_dict[label],trimmed_host[label])
        else:
            host_output += "{:<15}{:>60}\r\n".format(label_dict[label],trimmed_host[label])
    
    return host_output


# Look up host via Shodan API
def query_shodan():
    # Retrieve random valid external IP address
    target_ip = roll_ip()
    print("Fetching Shodan Results for {}...\r\n".format(target_ip))
    
    # Try making the Shodan call with the provided IP address
    try:
        host = api.host(target_ip,minify=True)

        host_info = trim_host(host)
        
        return host_info
    # Handle errors
    except shodan.APIError, e:
        # If no info, reroll and requery until valid
        if str(e) == "No information available for that IP.":
            print(e)
            print("Pausing and rerolling...\r\n")
            # Sleep to avoid Shodan API rate limit
            time.sleep(1.25)
            
            return query_shodan()
        else:
            print(e)


def main():
    host_data = query_shodan()
    print(host_data)

if __name__ == "__main__":
    main()
