from subprocess import Popen, PIPE
from os import remove
from libnmap.parser import NmapParser
import socket


class HostQuery(object):
    """
    This class requires the following applications on the server

    1. NMAP application binary installed on Operating System
    2. python-libnmap 0.5.1 or greater
    """
    _nmap_xml_file_location = None
    _nmap_xml_file_name = None
    _os_pings = None

    def __init__(self,
                 ip_address=None,
                 nmap_binary="/usr/bin/nmap",
                 ping_binary="/bin/ping",
                 nmap_xml_file_location='/tmp',
                 os_pings=5):
        """
        :param ip_address: And IP Address in a String can be passed in at anytime
        :param nmap_binary: Path and name of the NMAP binary
        :param ping_binary: Path and name of the ping binary
        :param os_pings: Number of ping packets to send in an Integer
        :return: Nothing
        """
        self.ip_address = ip_address
        self.nmap_binary = nmap_binary
        self.ping_binary = ping_binary
        self.nmap_xml_file_location = nmap_xml_file_location
        self.nmap_xml_file_name = 'nmap_scantype_{0}_ip_{1}.xml'
        self.os_pings = os_pings

    @property
    def nmap_xml_file_location(self):
        return self._nmap_xml_file_location

    @nmap_xml_file_location.setter
    def nmap_xml_file_location(self, value):
        if not value: raise ValueError(u"You must enter an temporary file location!")
        if not isinstance(value, (str, unicode, basestring)): raise ValueError(u"File location must be a string!")
        value = value.rstrip('/')
        self._nmap_xml_file_location = value

    @property
    def nmap_xml_file_name(self):
        return self._nmap_xml_file_name

    @nmap_xml_file_name.setter
    def nmap_xml_file_name(self, value):
        if not value: raise ValueError(u"You must enter an temporary file name!")
        if not isinstance(value, (str, unicode, basestring)): raise ValueError(u"File name must be a string!")
        value = value.replace("/", "")
        self._nmap_xml_file_name = value

    @property
    def os_pings(self):
        return self._os_pings

    @os_pings.setter
    def os_pings(self, value):
        if not value: raise ValueError(u"You must enter an number of os pings to send!")
        if not isinstance(value, (long, int)): raise ValueError(u"OS pings must be a Integer!")
        self._os_pings = value

    def run(self, query_level=2):
        """
        :param query_level: 1-For nmap ping scan, 2-For nmap ping scan and regular(bash) ping
        :return: 0-Host is alive responding to queries, and 1-Host is not alive not responding to queries

        Run host query that will run up to 2 checks to determine if the host is alive.
        Querying will stop querying after a single positive result is found to prevent false negatives.

        Checks:
        1. nmap multi port syn ping
        2. os level ping
        """
        if not self.ip_address:
            return ValueError(u"You must set the global variable 'ip_address' before executing the 'run' method!")
        if not (1 <= query_level <= 2):
            return ValueError(u"You must choose a query level between 1 and 2. 1-For nmap ping scan, "
                              u"2-For nmap ping scan and regular(bash shell) ping.")

        if query_level >= 1 and self.nmap_multi_port_syn_ping() == 0:
            return 0
        elif query_level >= 2 and self.os_ping() == 0:
            return 0
        else:
            return 1

    def nmap_multi_port_syn_ping(self, portlist=(21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 138, 139, 143, 443, 8080)):
        nmap_xml_file = self.nmap_xml_file_location + '/' + self.nmap_xml_file_name.format("nmap_multi_port_syn_ping",
                                                                                           self.ip_address.replace(".",
                                                                                                                   "_"))

        if not isinstance(portlist, (tuple, list)):
            raise TypeError(u"Portlist must be either a list or tuple integers/port numbers.")

        if not all(isinstance(p, int) for p in portlist):
            raise TypeError(u"Port numbers must be an integer!")

        ports = ','.join(str(p) for p in portlist)

        proc = Popen([self.nmap_binary, '-oX', nmap_xml_file, '-sP', '-PS' + ports, self.ip_address],
                     stdout=PIPE,
                     stderr=PIPE)
        stdout, stderr = proc.communicate()

        error = stderr.strip('\n') if stderr else stdout.strip('\n')

        if not proc.returncode == 0:
            raise OSError(u"Ran into issue running nmap multi port syn scan: {0}".format(error))

        if proc.returncode == 0:
            nmap_report = NmapParser.parse_fromfile(nmap_xml_file)
            remove(nmap_xml_file)
            if nmap_report.hosts_up >= 1:
                return 0
            else:
                return 1
        else:
            return 1

    def os_ping(self):
        proc = Popen([self.ping_binary, '-c{0}'.format(self.os_pings), '-n', self.ip_address], stdout=PIPE, stderr=PIPE)
        stdout, stderr = proc.communicate()

        error = stderr.strip('\n') if stderr else stdout.strip('\n')

        if not proc.returncode == 0 and not proc.returncode == 1:
            raise OSError(u"Ran into issue running os ping: {0}".format(error))

        if proc.returncode == 0:
            return 0
        else:
            return 1

    def get_hostname_by_address(self):
        try:
            hostname, aliaslist, ipaddlist = socket.gethostbyaddr(self.ip_address)
            return hostname
        except socket.herror:
            hostname = None
            return hostname
        except socket.gaierror:
            hostname = None
            return hostname


    # def nmap_syn_ping(self):
    #     nmap_xml_file = self.nmap_xml_file_location + '/' + self.nmap_xml_file_name.format("nmap_syn_ping",
    #                                                                                        self.ip_address.replace(".",
    #                                                                                                                "_"))
    #
    #     proc = Popen([self.nmap_binary, '-oX', nmap_xml_file, '-Pn', self.ip_address], stdout=PIPE, stderr=PIPE)
    #     stdout, stderr = proc.communicate()
    #
    #     print stderr
    #     print stdout
    #
    #     error = stderr.strip('\n') if stderr else stdout.strip('\n')
    #
    #     if not proc.returncode == 0:
    #         raise OSError(u"Ran into issue running nmap syn scan: {0}".format(error))
    #
    #     if proc.returncode == 0:
    #         nmap_report = NmapParser.parse_fromfile(nmap_xml_file)
    #         print nmap_report
    #         remove(nmap_xml_file)
    #         if nmap_report.hosts_up >= 1:
    #             return 0
    #         else:
    #             return 1
    #     else:
    #         return 1


# The -sP option sends an ICMP echo request and a TCP packet to port 80 by default.
#               When executed by an unprivileged user, a SYN packet is sent (using a connect()
#               call) to port 80 on the target. When a privileged user tries to scan targets on a
#               local ethernet network, ARP requests (-PR) are used unless --send-ip was
#               specified. The -sP option can be combined with any of the discovery probe types
#               (the -P* options, excluding -P0) for greater flexibility. If any of those probe
#               type and port number options are used, the default probes (ACK and echo request)
#               are overridden. When strict firewalls are in place between the source host
#               running Nmap and the target network, using those advanced techniques is
#               recommended. Otherwise hosts could be missed when the firewall drops probes or
#               their responses.

# -PS [portlist] (TCP SYN Ping)
#               This option sends an empty TCP packet with the SYN flag set. The default
#               destination port is 80 (configurable at compile time by changing
#               DEFAULT_TCP_PROBE_PORT in nmap.h), but an alternate port can be specified as a
#               parameter. A comma separated list of ports can even be specified (e.g.
#               -PS22,23,25,80,113,1050,35000), in which case probes will be attempted against
#               each port in parallel.
#
#               The SYN flag suggests to the remote system that you are attempting to establish a
#               connection. Normally the destination port will be closed, and a RST (reset)
#               packet sent back. If the port happens to be open, the target will take the second
#               step of a TCP 3-way-handshake by responding with a SYN/ACK TCP packet. The
#               machine running Nmap then tears down the nascent connection by responding with a
#               RST rather than sending an ACK packet which would complete the 3-way-handshake
#               and establish a full connection. The RST packet is sent by the kernel of the
#               machine running Nmap in response to the unexpected SYN/ACK, not by Nmap itself.
#
#               Nmap does not care whether the port is open or closed. Either the RST or SYN/ACK
#               response discussed previously tell Nmap that the host is available and
#               responsive.