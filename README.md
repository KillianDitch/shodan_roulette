# shodan_roulette
Query Shodan for random IP addresses.

This script requires a Shodan API key. Once that's added, the script will generate a random IP address, verify that it is a non-RFC 1918 (internal) address, then check Shodan for results related to that IP. If no results are returned, another IP address is rolled.

This version currently only pulls the "minify=True" results--basically the location and general information. Later versions should figure out a way to display the juicier details.
