from hostquery.hostquery import HostQuery

def is_address_alive(ip_address):
    '''
    Takes in an ip address and runs nmap scans to determine if host is alive
    '''
    hq = HostQuery()

    # Namp Ping check ip_address to see if it's in use
    hq.ip_address = ip_address
    response = hq.run()  # Response 0 for pingable, 1 for unreachable. Same as OS exit/return codes.
    return response