<<<<<<< HEAD
#!/usr/bin/python

#
# Windows Azure Guest Agent
#
# Requires Python 2.4+ and Openssl 1.0+
#
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx
#

#import array

#import array
import array
#import
import base64
import httplib
import os
import os.path
import platform
import re
import shutil
import socket
import SocketServer
import struct
import sys
import tempfile
import textwrap
import threading
import time
import traceback
import xml.dom.minidom

GuestAgentName = "LinuxAgent"
GuestAgentVersion = "" # filled in by build; be careful with this line and GuestAgentVersion
ProtocolVersion = "2011-12-31"
Config = None
LinuxDistro = None

class Global:
    Verbose = False
    ShortSleep = 0 # good for testing/debugging
    SendData = None
    DhcpResponse = None

class WindowsClass:
    def Detect(self):
        return (platform.uname()[0] == "Windows")
Windows = WindowsClass()

class LinuxClass:
    def Detect(self):
        return (platform.uname()[0] == "Linux")
Linux = LinuxClass()

class UbuntuClass:
    HostnameFile = "/etc/hostname"
    def Detect(self):
        return os.path.isfile("/etc/lsb-release") and "Ubuntu" in GetFileContents("/etc/lsb-release")
Ubuntu = UbuntuClass()

class SuseClass:
    HostnameFile = "/etc/HOSTNAME"
    def Detect(self):
        return os.path.isfile("/etc/SuSE-release")
Suse = SuseClass()

class RedHatClass:
    def Detect(self):
        return os.path.isfile("/etc/redhat-release")
RedHat = RedHatClass()

PossibleEthernetInterfaces = ["seth0", "seth1", "eth0", "eth1"]
RulesFiles = [ "/lib/udev/rules.d/75-persistent-net-generator.rules",
               "/etc/udev/rules.d/70-persistent-net.rules" ]
VarLibDhcpDirectories = ["/var/lib/dhclient", "/var/lib/dhcpcd", "/var/lib/dhcp"]
EtcDhcpClientConfFiles = ["/etc/dhcp/dhclient.conf", "/etc/dhcp3/dhclient.conf"]
LibDir = "/var/lib/waagent"

# This lets us index into a string or an array of integers transparently.
def Ord(a):
    if type(a) == type("a"):
        a = ord(a)
    return a

def IsWindows():
    return Windows.Detect()

def IsLinux():
    return Linux.Detect()

def DetectLinuxDistro():
    global LinuxDistro
    if RedHat.Detect():
        LinuxDistro = "RedHat"
        return 1
    if Ubuntu.Detect():
        LinuxDistro = "Ubuntu"
        return 1
    if Suse.Detect():
        LinuxDistro = "Suse"
        return 1
    return 0

def IsRedHat():
    return "RedHat" in LinuxDistro

def IsUbuntu():
    return "Ubuntu" in LinuxDistro

def IsSuse():
    return "Suse" in LinuxDistro

def GetLastPathElement(path):
    return path.rsplit('/', 1)[1]

def GetFileContents(filepath):
    file = open(filepath)
    try:
        return file.read()
    finally:
        file.close()

def SetFileContents(filepath, contents):
    file = open(filepath, "w")
    try:
        file.write(contents)
    finally:
        file.close()

def ReplaceFileContentsAtomic(filepath, contents):
    handle, temp = tempfile.mkstemp(dir = os.path.dirname(filepath))
    try:
        os.write(handle, contents)
    finally:
        os.close(handle)
    try:
        os.rename(temp, filepath)
        return
    except:
        pass
    os.remove(filepath)
    os.rename(temp, filepath)

def Run(a):
    LogIfVerbose(a)
    return os.system(a)

def GenerateTransportCert():
    Run("openssl req -x509 -nodes -subj /CN=LinuxTransport -days 32768 -newkey rsa:2048 -keyout TransportPrivate.pem -out TransportCert.pem")
    cert = ""
    for line in GetFileContents("TransportCert.pem").split("\n"):
        if not "CERTIFICATE" in line: 
            cert += line.rstrip()
    return cert

def DecryptPassword(e):
    SetFileContents("password.p7m",
        "MIME-Version: 1.0\n"
        + "Content-Disposition: attachment; filename=\"password.p7m\"\n"
        + "Content-Type: application/x-pkcs7-mime; name=\"password.p7m\"\n"
        + "Content-Transfer-Encoding: base64\n\n"
        + textwrap.fill(e, 64))
    return os.popen("openssl cms -decrypt -in password.p7m -inkey Certificates.pem -recip Certificates.pem").read()

def CreateAccount(user, password, expiration, thumbprint):
    if IsWindows():
        Log("skipping CreateAccount on Windows")
        return
    group = "wheel"
    if IsUbuntu():
        group = "admin"
    command = "useradd " + user + " -G " + group
    if expiration != None:
        command += " -e " + expiration.split(".")[0]
    Run(command)
    Run("echo " + password + " | passwd --stdin " + user)
    if (thumbprint != None):
        Run("rm -f /home/" + user + "/.ssh/id_rsa*")
        Run("mkdir /home/" + user + "/.ssh")
        Run("chmod 600 " + thumbprint + ".pem")
        Run("ssh-keygen -y -f " + thumbprint + ".pem > /home/" + user + "/.ssh/id_rsa.pub")
        Run("cp " + thumbprint + ".pem /home/" + user + "/.ssh/id_rsa")
        Run("chmod 600 /home/" + user + "/.ssh/id_rsa*")
        Run("chown " + user + " /home/" + user + "/.ssh/id_rsa*")
        Run("cp -f /home/" + user + "/.ssh/id_rsa.pub /home/" + user + "/.ssh/authorized_keys")
    Log("Created user account: " + user)

def ActivateResourceDisk():
    if IsWindows():
        Log("skipping ActivateResourceDisk on Windows")
        return
    format = Config.get("ResourceDisk.Format")
    if format != None and format.lower().startswith("n"):
        return
    device = "/dev/hdb"
    if Run("ls -R /sys/devices/ | grep vmbus | grep hdb > /dev/null"):
        if Run("ls -R /sys/devices/ | grep vmbus | grep sdb > /dev/null"):
            Log("Skipping ActivateResourceDisk: Unable to detect disk topology")
            return
        else:
            device = "/dev/sdb"
    if not Run("mount | grep ^" + device + "1"):
        Log(device + "1 is already mounted.")
        return
    mountpoint = Config.get("ResourceDisk.MountPoint")
    if mountpoint == None:
        mountpoint = "/mnt/resource"
    Run("mkdir " + mountpoint)
    if Run("mount " + device + "1 " + mountpoint):
        if os.popen("sfdisk -q -c " + device + " 1").read().rstrip() == "7":
            Run("sfdisk -c " + device + " 1 83")
        else:
            Log("Failed to mount " + device + "1 and partition type is not NTFS. Will not reformat.")
            return
        fs = Config.get("ResourceDisk.Filesystem")
        if fs == None:
            fs = "ext3"
        Run("mkfs." + fs + " " + device + "1")
        if Run("mount " + device + "1 " + mountpoint):
            Log("Unexpected failure to mount after formatting")
            return
    swap = Config.get("ResourceDisk.EnableSwap")
    if swap != None and swap.lower().startswith("y"):
        sizeKB = int(Config.get("ResourceDisk.SwapSizeMB")) * 1024
        if os.path.isfile(mountpoint + "/swapfile") and os.path.getsize(mountpoint + "/swapfile") != (sizeKB * 1024):
            os.remove(mountpoint + "/swapfile")
        if not os.path.isfile(mountpoint + "/swapfile"):
            Run("dd if=/dev/zero of=" + mountpoint + "/swapfile bs=1024 count=" + str(sizeKB))
            Run("mkswap " + mountpoint + "/swapfile")
        Run("swapon " + mountpoint + "/swapfile")
        Log("Enabled " + str(sizeKB) + " KB of swap at " + mountpoint + "/swapfile")
    Log("Resource disk (" + device + "1) is mounted at " + mountpoint)

def ReloadSshd():
    name = None
    if IsRedHat() or IsSuse():
        name = "sshd"
    if IsUbuntu():
        name = "ssh"
    if name == None:
        return
    if not Run("service " + name + " status | grep running"):
        Run("service " + name + " reload")

def Provision():
    if IsWindows():
        Log("skipping Provision on Windows")
        return None
    enabled = Config.get("Provisioning.Enabled")
    if enabled != None and enabled.lower().startswith("n"):
        return None
    Log("Provisioning image started.")
    regenerateKeys = Config.get("Provisioning.RegenerateSshHostKeyPair")
    type = Config.get("Provisioning.SshHostKeyPairType")
    if regenerateKeys == None or regenerateKeys.lower().startswith("y"):
        Run("rm -f /etc/ssh/ssh_host_ecdsa_key*")
        Run("rm -f /etc/ssh/ssh_host_dsa_key*")
        Run("rm -f /etc/ssh/ssh_host_rsa_key*")
        Run("rm -f /etc/ssh/ssh_host_key*")
        Log("Generating SSH host " + type + " keypair.")
        Run("ssh-keygen -N '' -t " + type + " -f /etc/ssh/ssh_host_" + type + "_key")
        ReloadSshd()
    Run("touch " + LibDir + "/provisioned")
    dvd = "/dev/hdc"
    if os.path.exists("/dev/scd0"):
        dvd = "/dev/scd0"
    if Run("fdisk -l " + dvd + " | grep Disk"):
        return None
    os.makedirs("/mnt/cdrom/secure", 0700)
    Run("mount " + dvd + " /mnt/cdrom/secure")
    ovfxml = GetFileContents("/mnt/cdrom/secure/ovf-env.xml")
    SetFileContents("ovf-env.xml", ovfxml)
    runProgs = Config.get("Provisioning.RunPrograms")
    auxProg = "/mnt/cdrom/secure/waagent-aux.sh"
    if runProgs != None and runProgs.lower().startswith("y") and os.path.isfile(auxProg):
        Log("Running auxillary programs from the DVD.")
        Run(auxProg)
    ovfxml = GetFileContents("ovf-env.xml")
    Run("umount /mnt/cdrom/secure")
    if ovfxml != None:
        Log("Provisioning image from OVF data in the DVD.")
        ovfobj = OvfEnv().Parse(ovfxml)
        ovfobj.Process()
    delRootPass = Config.get("Provisioning.DeleteRootPassword")
    if delRootPass != None and delRootPass.lower().startswith("y"):
        DeleteRootPassword()
    Log("Provisioning image completed.")
    return os.popen("ssh-keygen -lf /etc/ssh/ssh_host_" + type + "_key.pub  | cut -f 2 -d ' ' | tr -d :").read()

def IsInRangeInclusive(a, low, high):
    return (a >= low and a <= high)

def IsPrintable(ch):
    return IsInRangeInclusive(ch, Ord('A'), Ord('Z')) or IsInRangeInclusive(ch, Ord('a'), Ord('z')) or IsInRangeInclusive(ch, Ord('0'), Ord('9'))

def HexDump(buffer, size):
    if size < 0:
        size = len(buffer)
    result = ""
    for i in range(0, size):
        if (i % 16) == 0:
            result += "%06X: " % i
        byte = struct.unpack("B", buffer[i])[0]
        result += "%02X " % byte
        if (i & 15) == 7:
            result += " "
        if ((i + 1) % 16) == 0 or (i + 1) == size:
            j = i
            while ((j + 1) % 16) != 0:
                result += "   "
                if (j & 7) == 7:
                    result += " "
                j += 1
            result += " "
            for j in range(i - (i % 16), i + 1):
                byte = struct.unpack("B", buffer[j])[0]
                k = '.'
                if IsPrintable(byte):
                    k = chr(byte)
                result += k
            if (i + 1) != size:
                result += "\n"
    return result

def HexDump2(buffer):
    return HexDump3(buffer, 0, len(buffer))

def HexDump3(buffer, offset, length):
    return ''.join(['%02X' % Ord(char) for char in buffer[offset:offset + length]])
    
def ThrottleLog(counter):
    # Log everything up to 10, every 10 up to 100, then every 100.
    return (counter < 10) or ((counter < 100) and ((counter % 10) == 0)) or ((counter % 100) == 0)

def IntegerToIpAddressV4String(a):
    return "%u.%u.%u.%u" % ((a >> 24) & 0xFF, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF)

def Logger():

    class T(object):

        def __init__(self):
            self.File = None

    self = T()

    def LogToFile(message):
        FilePath = ["/var/log/waagent.log", "waagent.log"][IsWindows()]
        if not os.path.isfile(FilePath) and self.File != None:
            self.File.close()
            self.File = None
        if self.File == None:
            self.File = open(FilePath, "a")
        self.File.write(message + "\n")
        self.File.flush()

    def Log(message):
        LogWithPrefix("", message)

    def LogWithPrefix(prefix, message):
        t = time.localtime()
        t = "%04u/%02u/%02u %02u:%02u:%02u " % (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        t += prefix
        for line in message.split("\n"):
            line = t + line
            print(line)
            LogToFile(line)

    return Log, LogWithPrefix

Log, LogWithPrefix = Logger()

def NoLog(message):
    pass

def LogIfVerbose(message):
    if Global.Verbose == True:
        Log(message)

def LogWithPrefixIfVerbose(prefix, message):
    if Global.Verbose == True:
        LogWithPrefix(prefix, message)

def Debug(message):
    LogWithPrefix("Debug:", message)

def Warn(message):
    LogWithPrefix("WARNING:", message)

def WarnWithPrefix(prefix, message):
    LogWithPrefix("WARNING:" + prefix, message)

def Error(message):
    LogWithPrefix("ERROR:", message)

def ErrorWithPrefix(prefix, message):
    LogWithPrefix("ERROR:" + prefix, message)

def GetHttpDateTimeNow():
    # Date: Fri, 25 Mar 2011 04:53:10 GMT
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

def linux_ioctl_GetIpv4Address(ifname):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

def linux_ioctl_GetInterfaceMac(ifname):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02X' % Ord(char) for char in info[18:24]])

def GetIpv4Address():
    if IsLinux():
        for ifname in PossibleEthernetInterfaces:
            try:
                return linux_ioctl_GetIpv4Address(ifname)
            except IOError, e:
                #ErrorWithPrefix("GetIpv4Address:", str(e))
                #ErrorWithPrefix("GetIpv4Address:", traceback.format_exc())
                pass
    else:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception, e:
            ErrorWithPrefix("GetIpv4Address:", str(e))
            ErrorWithPrefix("GetIpv4Address:", traceback.format_exc())

def GetMacAddress():
    if IsWindows():
        # Windows:   Physical Address. . . . . . . . . : 00-15-17-79-00-7F\n
        a = "ipconfig /all | findstr /c:\"Physical Address\" | findstr /v \"00-00-00-00-00-00-00\""
        a = os.popen(a).read()
        a = re.sub("\s+$", "", a)
        a = re.sub(".+ ", "", a)
        a = re.sub(":", "", a)
        a = re.sub("-", "", a)
    else:
        for ifname in PossibleEthernetInterfaces:
            try:
                a = linux_ioctl_GetInterfaceMac(ifname)
                break
            except IOError, e:
                #ErrorWithPrefix("GetMacAddress:", str(e))
                #ErrorWithPrefix("GetMacAddress:", traceback.format_exc())
                pass
    return HexStringToByteArray(a)

def Network_Route_SetDefaultGateway(gateway):
    if IsWindows():
        return
    Run("/sbin/route add -net 0.0.0.0 netmask 0.0.0.0 gw " + gateway)

def Network_Route_Add(net, mask, gateway):
    if IsWindows():
        return
    net = IntegerToIpAddressV4String(net)
    mask = IntegerToIpAddressV4String(mask)
    gateway = IntegerToIpAddressV4String(gateway)    
    Run("/sbin/route add -net " + net + " netmask " + mask + " gw " + gateway)

def HexStringToByteArray(a):
    b = ""
    for c in range(0, len(a) / 2):
        b += struct.pack("B", int(a[c * 2:c * 2 + 2], 16))
    return b

class Util(object):
    def _HttpGet(self, url, headers):
        LogIfVerbose("HttpGet(" + url + ")")
        maxRetry = 2
        if url.startswith("http://"):
            url = url[7:]
            url = url[url.index("/"):]
        for retry in range(0, maxRetry + 1):
            strRetry = str(retry)
            log = [NoLog, Log][retry > 0]
            log("retry HttpGet(" + url + "),retry=" + strRetry)
            response = None
            strStatus = "None"
            try:
                httpConnection = httplib.HTTPConnection(self.Endpoint)
                if headers == None:
                    request = httpConnection.request("GET", url)
                else:
                    request = httpConnection.request("GET", url, None, headers)
                response = httpConnection.getresponse()
                strStatus = str(response.status)
            except:
                pass
            log("response HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
            if response == None or response.status != httplib.OK:
                Error("HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                if retry == maxRetry:
                    Log("raise HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                    raise response
                else:
                    Log("sleep 10 seconds HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                    time.sleep(10)
            else:
                log("return HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                return response.read()

    def HttpGetWithoutHeaders(self, url):
        return self._HttpGet(url, None)

    def HttpGetWithHeaders(self, url):
        return self._HttpGet(url, {"x-ms-agent-name": GuestAgentName, "x-ms-version": ProtocolVersion})

    def HttpSecureGetWithHeaders(self, url, transportCert):
        return self._HttpGet(url, {"x-ms-agent-name": GuestAgentName,
                                   "x-ms-version": ProtocolVersion,
                                   "x-ms-cipher-name": "DES_EDE3_CBC",
                                   "x-ms-guest-agent-public-x509-cert": transportCert})

    def HttpPost(self, url, data):
        LogIfVerbose("HttpPost(" + url + ")")
        maxRetry = 2
        for retry in range(0, maxRetry + 1):
            strRetry = str(retry)
            log = [NoLog, Log][retry > 0]
            log("retry HttpPost(" + url + "),retry=" + strRetry)
            response = None
            strStatus = "None"
            try:
                httpConnection = httplib.HTTPConnection(self.Endpoint)
                request = httpConnection.request("POST", url, data, {"x-ms-agent-name": GuestAgentName,
                                                                     "Content-Type": "text/xml; charset=utf-8",
                                                                     "x-ms-version": ProtocolVersion})
                response = httpConnection.getresponse()
                strStatus = str(response.status)
            except:
                pass
            log("response HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
            if response == None or (response.status != httplib.OK and response.status != httplib.ACCEPTED):
                Error("HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                if retry == maxRetry:
                    Log("raise HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                    raise response
                else:
                    Log("sleep 10 seconds HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                    time.sleep(10)
            else:
                log("return HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                return response

def LoadBalancerProbeServer(port):

    class T(object):
        def __init__(self, port):
            enabled = Config.get("LBProbeResponder")
            if enabled != None and enabled.lower().startswith("n"):
                return
            self.ProbeCounter = 0
            self.server = SocketServer.TCPServer((GetIpv4Address(), port), TCPHandler)
            self.server_thread = threading.Thread(target = self.server.serve_forever)
            self.server_thread.setDaemon(True)
            self.server_thread.start()

        def shutdown(self):
            global EnableLoadBalancerProbes
            if not EnableLoadBalancerProbes:
                return
            self.server.shutdown()

    class TCPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            context.ProbeCounter = (context.ProbeCounter + 1) % 1000000
            log = [NoLog, LogIfVerbose][ThrottleLog(context.ProbeCounter)]
            strCounter = str(context.ProbeCounter)
            log("load balancer probe " + strCounter)
            self.request.recv(1024)
            self.request.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/html\r\nDate: " + GetHttpDateTimeNow() + "\r\n\r\nOK")

    context = T(port)
    return context

class ConfigurationProvider(object):
    def __init__(self):
        self.values = dict()
        if os.path.isfile("/etc/waagent.conf") == False:
            return
        for line in GetFileContents("/etc/waagent.conf").split("\n"):
            if not line.startswith("#") and "=" in line:
                parts = line.split()[0].split('=')
                self.values[parts[0]] = parts[1].strip("\" ")

    def get(self, key):
        return self.values.get(key)

class UdevRulesWatcher(object):
    def __init__(self):
        self.shutdown = False
        self.server_thread = threading.Thread(target = self.watch_forever)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

    def watch_forever(self):
        while not self.shutdown:
            for a in RulesFiles:
                if os.path.isfile(a):
                    if os.path.isfile(GetLastPathElement(a)):
                        os.remove(GetLastPathElement(a))
                    shutil.move(a, ".")
                    Log("UdevRulesWatcher: Moved " + a + " -> " + LibDir)
            time.sleep(5)

    def shutdown(self):
        self.shutdown = True
        self.server_thread.join()


class RoleProperties(Util):
    def __init__(self, Agent, ContainerId, RoleInstanceId, Thumbprint):
        self.Agent = Agent
        self.Endpoint = Agent.Endpoint
        self.ContainerId = ContainerId
        self.RoleInstanceId = RoleInstanceId
        self.Thumbprint = Thumbprint

    def post(self):
        roleProperties = ("<?xml version=\"1.0\" encoding=\"utf-8\"?><RoleProperties><Container>"
                        + "<ContainerId>" + self.ContainerId + "</ContainerId>"
                        + "<RoleInstances><RoleInstance>"
                        + "<Id>" + self.RoleInstanceId + "</Id>"
                        + "<Properties><Property name=\"CertificateThumbprint\" value=\"" + self.Thumbprint + "\" /></Properties>"
                        + "</RoleInstance></RoleInstances></Container></RoleProperties>")
        a = self.HttpPost("/machine?comp=roleProperties", roleProperties)
        Log("Posted Role Properties. CertificateThumbprint=" + self.Thumbprint)
        return a


class Certificates(object):
#
# <CertificateFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="certificates10.xsd">
#  <Version>2010-12-15</Version>
#  <Incarnation>2</Incarnation>
#  <Format>Pkcs7BlobWithPfxContents</Format>
#  <Data>MIILTAY...
#  </Data>
# </CertificateFile>
#
    def __init__(self):
        self.reinitialize()

    def reinitialize(self):
        self.Incarnation = None
        self.Role = None

    def Parse(self, xmlText):
        self.reinitialize()
        SetFileContents("Certificates.xml", xmlText)
        dom = xml.dom.minidom.parseString(xmlText)
        for a in [ "CertificateFile", "Version", "Incarnation",
                   "Format", "Data", ]:
            if not dom.getElementsByTagName(a):
                return Error("ERROR: missing " + a)
        node = dom.childNodes[0]
        if node.localName != "CertificateFile":
            return Error("root not CertificateFile")
        SetFileContents("Certificates.p7m",
            "MIME-Version: 1.0\n"
            + "Content-Disposition: attachment; filename=\"Certificates.p7m\"\n"
            + "Content-Type: application/x-pkcs7-mime; name=\"Certificates.p7m\"\n"
            + "Content-Transfer-Encoding: base64\n\n"
            + dom.getElementsByTagName("Data")[0].childNodes[0].data)
        Run("openssl cms -decrypt -in Certificates.p7m -inkey TransportPrivate.pem -recip TransportCert.pem | openssl pkcs12 -nodes -password pass: -out Certificates.pem")
        # There may be multiple certificates in this package. Split them.
        file = open("Certificates.pem")
        index = 1
        output = open(str(index) + ".pem", "w")
        prvDone = False
        for line in file.readlines():
            output.write(line)
            if line.startswith("-----END PRIVATE KEY-----"):
                output.close()
                index += 1
                output = open(str(index) + ".pem", "w")
            if line.startswith("-----END CERTIFICATE-----"):
                output.close()
                if prvDone == False:
                    prvDone = True
                    input = open(str(index) + ".pem")
                    output = open("1.pem", "a")
                    output.write(input.read())
                    input.close()
                    output.close()
                    os.remove(str(index) + ".pem")
                    index = 1
                index += 1
                if os.path.isfile(str(index) + ".pem"):
                    output = open(str(index) + ".pem", "a")
        index = 1
        filename = str(index) + ".pem"
        while os.path.isfile(filename):
            thumbprint = os.popen("openssl x509 -in " + filename + " -fingerprint -noout | cut -f 2 -d = | tr -d :").read()
            os.rename(filename, thumbprint + ".pem")
            index += 1
            filename = str(index) + ".pem"
        return self

class SharedConfig(object):
#
# <SharedConfig version="1.0.0.0" goalStateIncarnation="1">
#   <Deployment name="db00a7755a5e4e8a8fe4b19bc3b330c3" guid="{ce5a036f-5c93-40e7-8adf-2613631008ab}" incarnation="2">
#     <Service name="MyVMRoleService" guid="{00000000-0000-0000-0000-000000000000}" />
#     <ServiceInstance name="db00a7755a5e4e8a8fe4b19bc3b330c3.1" guid="{d113f4d7-9ead-4e73-b715-b724b5b7842c}" />
#   </Deployment>
#   <Incarnation number="1" instance="MachineRole_IN_0" guid="{a0faca35-52e5-4ec7-8fd1-63d2bc107d9b}" />
#   <Role guid="{73d95f1c-6472-e58e-7a1a-523554e11d46}" name="MachineRole" settleTimeSeconds="10" />
#   <LoadBalancerSettings timeoutSeconds="0" waitLoadBalancerProbeCount="8">
#     <Probes>
#       <Probe name="MachineRole" />
#       <Probe name="55B17C5E41A1E1E8FA991CF80FAC8E55" />
#       <Probe name="3EA4DBC19418F0A766A4C19D431FA45F" />
#     </Probes>
#   </LoadBalancerSettings>
#   <OutputEndpoints>
#     <Endpoint name="MachineRole:Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" type="SFS">
#       <Target instance="MachineRole_IN_0" endpoint="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" />
#     </Endpoint>
#   </OutputEndpoints>
#   <Instances>
#     <Instance id="MachineRole_IN_0" address="10.115.153.75">
#       <FaultDomains randomId="0" updateId="0" updateCount="0" />
#       <InputEndpoints>
#         <Endpoint name="a" address="10.115.153.75:80" protocol="http" isPublic="true" loadBalancedPublicAddress="70.37.106.197:80" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
#           <LocalPorts>
#             <LocalPortRange from="80" to="80" />
#           </LocalPorts>
#         </Endpoint>
#         <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" address="10.115.153.75:3389" protocol="tcp" isPublic="false" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
#           <LocalPorts>
#             <LocalPortRange from="3389" to="3389" />
#           </LocalPorts>
#         </Endpoint>
#         <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteForwarder.RdpInput" address="10.115.153.75:20000" protocol="tcp" isPublic="true" loadBalancedPublicAddress="70.37.106.197:3389" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
#           <LocalPorts>
#             <LocalPortRange from="20000" to="20000" />
#           </LocalPorts>
#         </Endpoint>
#       </InputEndpoints>
#     </Instance>
#   </Instances>
# </SharedConfig>
#
    def __init__(self):
        self.reinitialize()

    def reinitialize(self):
        self.Deployment = None
        self.Incarnation = None
        self.Role = None
        self.LoadBalancerSettings = None
        self.OutputEndpoints = None
        self.Instances = None

    def Parse(self, xmlText):
        self.reinitialize()
        SetFileContents("SharedConfig.xml", xmlText)
        dom = xml.dom.minidom.parseString(xmlText)
        for a in [ "SharedConfig", "Deployment", "Service",
                   "ServiceInstance", "Incarnation", "Role", ]:
            if not dom.getElementsByTagName(a):
                return Error("ERROR: missing " + a)
        node = dom.childNodes[0]
        if node.localName != "SharedConfig":
            return Error("root not SharedConfig")
        program = Config.get("Role.TopologyConsumer")
        if program != None and program != "None":
            os.spawnl(os.P_NOWAIT, program, program, LibDir + "/SharedConfig.xml")
        return self

class HostingEnvironmentConfig(object):
#
# <HostingEnvironmentConfig version="1.0.0.0" goalStateIncarnation="1">
#   <StoredCertificates>
#     <StoredCertificate name="Stored0Microsoft.WindowsAzure.Plugins.RemoteAccess.PasswordEncryption" certificateId="sha1:C093FA5CD3AAE057CB7C4E04532B2E16E07C26CA" storeName="My" configurationLevel="System" />
#   </StoredCertificates>
#   <Deployment name="db00a7755a5e4e8a8fe4b19bc3b330c3" guid="{ce5a036f-5c93-40e7-8adf-2613631008ab}" incarnation="2">
#     <Service name="MyVMRoleService" guid="{00000000-0000-0000-0000-000000000000}" />
#     <ServiceInstance name="db00a7755a5e4e8a8fe4b19bc3b330c3.1" guid="{d113f4d7-9ead-4e73-b715-b724b5b7842c}" />
#   </Deployment>
#   <Incarnation number="1" instance="MachineRole_IN_0" guid="{a0faca35-52e5-4ec7-8fd1-63d2bc107d9b}" />
#   <Role guid="{73d95f1c-6472-e58e-7a1a-523554e11d46}" name="MachineRole" hostingEnvironmentVersion="1" software="" softwareType="ApplicationPackage" entryPoint="" parameters="" settleTimeSeconds="10" />
#   <HostingEnvironmentSettings name="full" Runtime="rd_fabric_stable.110217-1402.RuntimePackage_1.0.0.8.zip">
#     <CAS mode="full" />
#     <PrivilegeLevel mode="max" />
#     <AdditionalProperties><CgiHandlers></CgiHandlers></AdditionalProperties>
#   </HostingEnvironmentSettings>
#   <ApplicationSettings>
#     <Setting name="__ModelData" value="&lt;m role=&quot;MachineRole&quot; xmlns=&quot;urn:azure:m:v1&quot;>&lt;r name=&quot;MachineRole&quot;>&lt;e name=&quot;a&quot; />&lt;e name=&quot;b&quot; />&lt;e name=&quot;Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp&quot; />&lt;e name=&quot;Microsoft.WindowsAzure.Plugins.RemoteForwarder.RdpInput&quot; />&lt;/r>&lt;/m>" />
#     <Setting name="Microsoft.WindowsAzure.Plugins.Diagnostics.ConnectionString" value="DefaultEndpointsProtocol=http;AccountName=osimages;AccountKey=DNZQ..." />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountEncryptedPassword" value="MIIBnQYJKoZIhvcN..." />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountExpiration" value="2022-07-23T23:59:59.0000000-07:00" />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountUsername" value="test" />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Enabled" value="true" />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteForwarder.Enabled" value="true" />
#     <Setting name="Certificate|Microsoft.WindowsAzure.Plugins.RemoteAccess.PasswordEncryption" value="sha1:C093FA5CD3AAE057CB7C4E04532B2E16E07C26CA" />
#   </ApplicationSettings>
#   <ResourceReferences>
#     <Resource name="DiagnosticStore" type="directory" request="Microsoft.Cis.Fabric.Controller.Descriptions.ServiceDescription.Data.Policy" sticky="true" size="1" path="db00a7755a5e4e8a8fe4b19bc3b330c3.MachineRole.DiagnosticStore\" disableQuota="false" />
#   </ResourceReferences>
# </HostingEnvironmentConfig>
#
    def __init__(self):
        self.reinitialize()

    def reinitialize(self):
        self.StoredCertificates = None
        self.Deployment = None
        self.Incarnation = None
        self.Role = None
        self.HostingEnvironmentSettings = None
        self.ApplicationSettings = None
        self.Certificates = None
        self.ResourceReferences = None

    def Parse(self, xmlText):
        self.reinitialize()
        SetFileContents("HostingEnvironmentConfig.xml", xmlText)
        dom = xml.dom.minidom.parseString(xmlText)
        for a in [ "HostingEnvironmentConfig", "Deployment", "Service",
                   "ServiceInstance", "Incarnation", "Role", ]:
            if not dom.getElementsByTagName(a):
                return Error("ERROR: missing " + a)
        node = dom.childNodes[0]
        if node.localName != "HostingEnvironmentConfig":
            return Error("root not HostingEnvironmentConfig")
        self.ApplicationSettings = dom.getElementsByTagName("Setting")
        self.Certificates = dom.getElementsByTagName("StoredCertificate")
        return self

    def Process(self):
        ActivateResourceDisk()
        User = None
        Pass = None
        Expiration = None
        Thumbprint = None
        for b in self.ApplicationSettings:
            sname = b.getAttribute("name")
            svalue = b.getAttribute("value")
            if sname == "Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountEncryptedPassword":
                Pass = DecryptPassword(svalue)
            elif sname == "Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountUsername":
                User = svalue
            elif sname == "Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountExpiration":
                Expiration = svalue
            elif sname == "Certificate|Microsoft.WindowsAzure.Plugins.RemoteAccess.PasswordEncryption":
                Thumbprint = svalue.split(':')[1].upper()
        if User != None and User != "root":
            CreateAccount(User, Pass, Expiration, Thumbprint)
        for c in self.Certificates:
            cname = c.getAttribute("name")
            csha1 = c.getAttribute("certificateId").split(':')[1].upper()
            cpath = c.getAttribute("storeName")
            clevel = c.getAttribute("configurationLevel")
            if not os.path.isfile(csha1 + ".pem"):
                Log("Certificate with thumbprint: " + csha1 + " was not retrieved.")
        program = Config.get("Role.ConfigurationConsumer")
        if program != None and program != "None":
            os.spawnl(os.P_NOWAIT, program, program, LibDir + "/HostingEnvironmentConfig.xml")

class GoalState(Util):
#
# <GoalState xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="goalstate10.xsd">
#   <Version>2010-12-15</Version>
#   <Incarnation>1</Incarnation>
#   <Machine>
#     <ExpectedState>Started</ExpectedState>
#     <LBProbePorts>
#       <Port>16001</Port>
#     </LBProbePorts>
#   </Machine>
#   <Container>
#     <ContainerId>c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2</ContainerId>
#     <RoleInstanceList>
#       <RoleInstance>
#         <InstanceId>MachineRole_IN_0</InstanceId>
#         <State>Started</State>
#         <Configuration>
#           <HostingEnvironmentConfig>http://10.115.153.40:80/machine/c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2/MachineRole%5FIN%5F0?comp=config&amp;type=hostingEnvironmentConfig&amp;incarnation=1</HostingEnvironmentConfig>
#           <SharedConfig>http://10.115.153.40:80/machine/c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2/MachineRole%5FIN%5F0?comp=config&amp;type=sharedConfig&amp;incarnation=1</SharedConfig>
#           <Certificates>http://10.115.153.40:80/machine/c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2/MachineRole%5FIN%5F0?comp=certificates&amp;incarnation=1</Certificates>
#         </Configuration>
#       </RoleInstance>
#     </RoleInstanceList>
#   </Container>
# </GoalState>
#
# There is only one Role for VM images.
#
# Of primary interest is:
#  Machine/ExpectedState -- this is how shutdown is requested
#  LBProbePorts -- an http server needs to run here
#  We also note Container/ContainerID and RoleInstance/InstanceId to form the health report.
#  And of course, Incarnation
#
    def __init__(self, Agent):
        self.Agent = Agent
        self.Endpoint = Agent.Endpoint
        self.TransportCert = Agent.TransportCert
        self.reinitialize()

    def reinitialize(self):
        self.Incarnation = None # integer
        self.ExpectedState = None # "Started" or "Stopped"
        self.HostingEnvironmentConfigUrl = None
        self.HostingEnvironmentConfigXml = None
        self.HostingEnvironmentConfig = None
        self.SharedConfigUrl = None
        self.SharedConfigXml = None
        self.SharedConfig = None
        self.CertificatesUrl = None
        self.CertificatesXml = None
        self.Certificates = None
        self.RoleInstanceId = None
        self.ContainerId = None
        self.LoadBalancerProbePort = None # integer, ?list of integers
        self.RoleProperties = None

    def Parse(self, xmlText):
        self.reinitialize()
        node = xml.dom.minidom.parseString(xmlText).childNodes[0]
        if node.localName != "GoalState":
            return Error("root not GoalState")
        for a in node.childNodes:
            if a.nodeType == node.ELEMENT_NODE:
                if a.localName == "Incarnation":
                    for b in a.childNodes:
                        self.Incarnation = b.data
                        Log("GoalState.Incarnation:" + self.Incarnation)
                elif a.localName == "Machine":
                    for b in a.childNodes:
                        if b.nodeType == node.ELEMENT_NODE:
                            if b.localName == "ExpectedState":
                                for c in b.childNodes:
                                    self.ExpectedState = c.data
                                    Log("GoalState.Machine.ExpectedState:" + self.ExpectedState)
                            elif b.localName == "LBProbePorts":
                                for c in b.childNodes:
                                    if c.nodeType == node.ELEMENT_NODE:
                                        if c.localName == "Port":
                                            for d in c.childNodes:
                                                self.LoadBalancerProbePort = int(d.data)
                                                Log("Machine.LBProbePorts.Port:" + str(self.LoadBalancerProbePort))
                elif a.localName == "Container":
                    for b in a.childNodes:
                        if b.nodeType == node.ELEMENT_NODE:
                            if b.localName == "ContainerId":
                                self.ContainerId = b.childNodes[0].data
                                Log("ContainerId:" + self.ContainerId)
                            elif b.localName == "RoleInstanceList":
                                for c in b.childNodes:
                                    if c.localName == "RoleInstance":
                                        for d in c.childNodes:
                                            if d.nodeType == node.ELEMENT_NODE:
                                                if d.localName == "InstanceId":
                                                    self.RoleInstanceId = d.childNodes[0].data
                                                    Log("RoleInstanceId:" + self.RoleInstanceId)
                                                elif d.localName == "State":
                                                    pass
                                                elif d.localName == "Configuration":
                                                    for e in d.childNodes:
                                                        if e.nodeType == node.ELEMENT_NODE:
                                                            if e.localName == "HostingEnvironmentConfig":
                                                                self.HostingEnvironmentConfigUrl = e.childNodes[0].data
                                                                LogIfVerbose("HostingEnvironmentConfigUrl:" + self.HostingEnvironmentConfigUrl)
                                                                self.HostingEnvironmentConfigXml = self.HttpGetWithHeaders(self.HostingEnvironmentConfigUrl)
                                                                self.HostingEnvironmentConfig = HostingEnvironmentConfig().Parse(self.HostingEnvironmentConfigXml)
                                                            elif e.localName == "SharedConfig":
                                                                self.SharedConfigUrl = e.childNodes[0].data
                                                                LogIfVerbose("SharedConfigUrl:" + self.SharedConfigUrl)
                                                                self.SharedConfigXml = self.HttpGetWithHeaders(self.SharedConfigUrl)
                                                                self.SharedConfig = SharedConfig().Parse(self.SharedConfigXml)
                                                            elif e.localName == "Certificates":
                                                                self.CertificatesUrl = e.childNodes[0].data
                                                                LogIfVerbose("CertificatesUrl:" + self.CertificatesUrl)
                                                                self.CertificatesXml = self.HttpSecureGetWithHeaders(self.CertificatesUrl, self.TransportCert)
                                                                self.Certificates = Certificates().Parse(self.CertificatesXml)
        if self.Incarnation == None:
            return Error("Incarnation missing")
        if self.ExpectedState == None:
            return Error("ExpectedState missing")
        if self.RoleInstanceId == None:
            return Error("RoleInstanceId missing")
        if self.ContainerId == None:
            return Error("ContainerId missing")
        SetFileContents("GoalState." + self.Incarnation + ".xml", xmlText)
        return self

    def Process(self):
        self.HostingEnvironmentConfig.Process()

def Unpack(buffer, offset, range):
    result = 0
    for i in range:
        result = (result << 8) | Ord(buffer[offset + i])
    return result

def UnpackLittleEndian(buffer, offset, length):
    return Unpack(buffer, offset, range(length - 1, -1, -1))

def UnpackBigEndian(buffer, offset, length):
    return Unpack(buffer, offset, range(0, length))

def BuildDhcpRequest():
#
# typedef struct _DHCP {
#     UINT8   Opcode;                     /* op:     BOOTREQUEST or BOOTREPLY */
#     UINT8   HardwareAddressType;        /* htype:  ethernet */
#     UINT8   HardwareAddressLength;      /* hlen:   6 (48 bit mac address) */
#     UINT8   Hops;                       /* hops:   0 */
#     UINT8   TransactionID[4];           /* xid:    random */
#     UINT8   Seconds[2];                 /* secs:   0 */
#     UINT8   Flags[2];                   /* flags:  0 or 0x8000 for broadcast */
#     UINT8   ClientIpAddress[4];         /* ciaddr: 0 */
#     UINT8   YourIpAddress[4];           /* yiaddr: 0 */
#     UINT8   ServerIpAddress[4];         /* siaddr: 0 */
#     UINT8   RelayAgentIpAddress[4];     /* giaddr: 0 */
#     UINT8   ClientHardwareAddress[16];  /* chaddr: 6 byte ethernet MAC address */
#     UINT8   ServerName[64];             /* sname:  0 */
#     UINT8   BootFileName[128];          /* file:   0  */
#     UINT8   MagicCookie[4];             /*   99  130   83   99 */
#                                         /* 0x63 0x82 0x53 0x63 */
#     /* options -- hard code ours */
#
#     UINT8 MessageTypeCode;              /* 53 */
#     UINT8 MessageTypeLength;            /* 1 */
#     UINT8 MessageType;                  /* 1 for DISCOVER */
#     UINT8 End;                          /* 255 */
# } DHCP;
#

    LogIfVerbose("BuildDhcpRequest")

    # tuple of 244 zeros
    # (struct.pack_into would be good here, but requires Python 2.5)
    sendData = [0] * 244

    transactionID = os.urandom(4)
    macAddress = GetMacAddress()

    # Opcode = 1
    # HardwareAddressType = 1 (ethernet/MAC)
    # HardwareAddressLength = 6 (ethernet/MAC/48 bits)
    for a in range(0, 3):
        sendData[a] = [1, 1, 6][a]

    # fill in transaction id (random number to ensure response matches request)
    for a in range(0, 4):
        sendData[4 + a] = Ord(transactionID[a])

    # fill in ClientHardwareAddress
    for a in range(0, 6):
        sendData[0x1C + a] = Ord(macAddress[a])

    LogIfVerbose("BuildDhcpRequest:transactionId:%s,%04X" % (HexDump2(transactionID), UnpackBigEndian(sendData, 4, 4)))
    LogIfVerbose("BuildDhcpRequest:ClientHardwareAddress:%s,%012X" % (HexDump2(macAddress), UnpackBigEndian(sendData, 0x1C, 6)))

    # DHCP Magic Cookie: 99, 130, 83, 99
    # MessageTypeCode = 53 DHCP Message Type
    # MessageTypeLength = 1
    # MessageType = DHCPDISCOVER
    # End = 255 DHCP_END
    for a in range(0, 8):
        sendData[0xEC + a] = [99, 130, 83, 99, 53, 1, 1, 255][a]
    return array.array("c", map(chr, sendData))

def HandleDhcpResponse(sendData, receiveBuffer):

    LogIfVerbose("HandleDhcpResponse")
    bytesReceived = len(receiveBuffer)
    if bytesReceived < 0xF6:
        Error("too few bytes received " + str(bytesReceived))
        return False

    LogIfVerbose("bytesReceived: " + hex(bytesReceived))
    LogWithPrefixIfVerbose("DHCP response:", HexDump(receiveBuffer, bytesReceived))

    # check transactionId, cookie, MAC address
    # cookie should never mismatch
    # transactionId and MAC address I believe can mismatch -- we got the response meant from another machine

    LogIfVerbose("    sent cookie(0xEC:4):" + HexDump3(sendData, 0xEC, 4))
    LogIfVerbose("received cookie(0xEC:4):" + HexDump3(receiveBuffer, 0xEC, 4))
    LogIfVerbose("    sent transactionID(4:4):" + HexDump3(sendData, 4, 4))
    LogIfVerbose("received transactionID(4:4):" + HexDump3(receiveBuffer, 4, 4))
    LogIfVerbose("    sent ClientHardwareAddress(0x1C:6):" + HexDump3(sendData, 0x1C, 6))
    LogIfVerbose("received ClientHardwareAddress(0x1C:6):" + HexDump3(receiveBuffer, 0x1C, 6))

    LogIfVerbose("checking transactionId, cookie, MAC address")
    for offsets in [range(4, 4 + 4), range(0x1C, 0x1C + 6), range(0xEC, 0xEC + 4)]:
        for offset in offsets:
            sentByte = Ord(sendData[offset])
            receivedByte = Ord(receiveBuffer[offset])
            if sentByte != receivedByte:
                Error("HandleDhcpResponse:    sentByte[0x%02X]:0x%02X" % (offset, sentByte))
                Error("HandleDhcpResponse:recievedByte[0x%02X]:0x%02X" % (offset, receivedByte))
                Error("HandleDhcpResponse:    sent cookie:" + HexDump3(sendData, 0xEC, 4))
                Error("HandleDhcpResponse:received cookie:" + HexDump3(receiveBuffer, 0xEC, 4))
                Error("HandleDhcpResponse:    sent transactionID:" + HexDump3(sendData, 4, 4))
                Error("HandleDhcpResponse:received transactionID:" + HexDump3(receiveBuffer, 4, 4))
                Error("HandleDhcpResponse:    sent ClientHardwareAddress:" + HexDump3(sendData, 0x1C, 6))
                Error("HandleDhcpResponse:received ClientHardwareAddress:" + HexDump3(receiveBuffer, 0x1C, 6))
                Error("HandleDhcpResponse:transactionId, cookie, or MAC address mismatch")
                return False
    endpoint = None

    #
    # Walk all the returned options, parsing out what we need, ignoring the others.
    # We need the custom option 245 to find the the endpoint we talk to,
    # as well as, to handle some Linux DHCP client incompatibilities,
    # options 3 for default gateway and 249 for routes. And 255 is end.
    #

    i = 0xF0 # offset to first option
    while i < bytesReceived:
        option = Ord(receiveBuffer[i])
        length = 0
        if (i + 1) < bytesReceived:
            length = Ord(receiveBuffer[i + 1])
        LogIfVerbose("DHCP option " + hex(option) + " at offset:" + hex(i) + " with length:" + hex(length))
        if option == 255:
            LogIfVerbose("DHCP packet ended at offset " + hex(i))
            break
        elif option == 249:
            # http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
            LogIfVerbose("routes at offset:" + hex(i) + " with length:" + hex(length))
            if length < 5:
                Error("routes too small")
                return False # or hope the DHCP client worked?
            j = i + 2
            while j < (i + length + 2):
                maskLengthBits = Ord(receiveBuffer[j])
                maskLengthBytes = (((maskLengthBits + 7) & ~7) >> 3)
                mask = 0xFFFFFFFF & (0xFFFFFFFF << (32 - maskLengthBits))
                j += 1
                net = UnpackBigEndian(receiveBuffer, j, maskLengthBytes)
                net <<= (32 - maskLengthBytes * 8)
                net &= mask
                j += maskLengthBytes
                gateway = UnpackBigEndian(receiveBuffer, j, 4)
                j += 4
                Network_Route_Add(net, mask, gateway)
            if j != (i + length + 2):
                Error("trouble parsing routes")
                return False # or hope the DHCP client worked?

        elif option == 3 or option == 245:
            if i + 5 < bytesReceived:
                if length != 4:
                    Error("endpoint or defaultGateway not 4 bytes")
                    return False # or hope the DHCP client worked? (for option 3)
                IpAddress = "%u.%u.%u.%u" % (Ord(receiveBuffer[i + 2]), Ord(receiveBuffer[i + 3]), Ord(receiveBuffer[i + 4]), Ord(receiveBuffer[i + 5]))
                if option == 3:
                    Network_Route_SetDefaultGateway(IpAddress)
                    name = "defaultGateway"
                else:
                    endpoint = IpAddress
                    name = "endpoint"
                LogIfVerbose(name + ": " + IpAddress + " at " + hex(i))
            else:
                Error(name + " data too small")
                return False # or hope the DHCP client worked? (for option 3)
        else:
            LogIfVerbose("skipping DHCP option " + hex(option) + " at " + hex(i) + " with length " + hex(length))
        i += length + 2
    return endpoint

def DoDhcpWork():
    #
    # Discover the wire server via DHCP option 245.
    # And default gateway via option 3, for Linux, to workaround incompatibility with fabric DHCP configuration,
    # and handle Microsoft extension option 249.
    #

    if not IsWindows():
        Run("iptables -D INPUT -p udp --dport 68 -j ACCEPT")
        Run("iptables -I INPUT -p udp --dport 68 -j ACCEPT")

    sleepDurations = [0, 5, 10, 30, 60, 60, 60, 60]
    maxRetry = len(sleepDurations)
    lastTry = (maxRetry - 1)
    for retry in range(0, maxRetry):
        try:
            strRetry = str(retry)
            prefix = "DoDhcpWork,try=" + strRetry
            LogIfVerbose(prefix)
            sendData = BuildDhcpRequest()
            LogWithPrefixIfVerbose("DHCP request:", HexDump(sendData, len(sendData)))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((GetIpv4Address(), 68))
            bytesSent = sock.sendto(sendData, ("<broadcast>", 67))
            receiveBuffer = sock.recv(1024)
            endpoint = HandleDhcpResponse(sendData, receiveBuffer)
            if not endpoint:
                LogIfVerbose("No endpoint found")
            if endpoint or retry == lastTry:
                if endpoint:
                    Global.SendData = sendData
                    Global.DhcpResponse = receiveBuffer
                if retry == lastTry:
                    LogIfVerbose("DoDhcpWork,try=" + strRetry + ",=>lastTry")
                return endpoint
            productionSleepDuration = sleepDurations[retry % len(sleepDurations)]
            sleepDuration = [productionSleepDuration, retry, 1][Global.ShortSleep % 3]
            LogIfVerbose("DoDhcpWork,sleep=" + str(sleepDuration))
            time.sleep(sleepDuration)
        except Exception, e:
            ErrorWithPrefix(prefix, str(e))
            ErrorWithPrefix(prefix, traceback.format_exc())
    return False

def UpdateAndPublishHostNameCommon(name):

    replaceFiles = dict()
    setFiles = dict()

    # RedHat
    if IsRedHat():
        filepath = "/etc/sysconfig/network"
        if os.path.isfile(filepath):
            replaceFiles[filepath] = (
                "HOSTNAME=" + name + "\n"
                + "\n".join(filter(lambda a: not a.startswith("HOSTNAME"), GetFileContents(filepath).split("\n"))))

        for ethernetInterface in PossibleEthernetInterfaces:
            filepath = "/etc/sysconfig/network-scripts/ifcfg-" + ethernetInterface
            if os.path.isfile(filepath):
                replaceFiles[filepath] = (
                    "DHCP_HOSTNAME=" + name + "\n"
                    + "\n".join(filter(lambda a: not a.startswith("DHCP_HOSTNAME"), GetFileContents(filepath).split("\n"))))

    # Ubuntu
    if IsUbuntu():
        setFiles[Ubuntu.HostnameFile] = name

    # Suse
    if IsSuse():
        setFiles[Suse.HostnameFile] = name

    for filepath in EtcDhcpClientConfFiles:
        if os.path.isfile(filepath):
            replaceFiles[filepath] = (
                "send host-name \"" + name + "\";\n"
                + "\n".join(filter(lambda a: not a.startswith("send host-name"), GetFileContents(filepath).split("\n"))))

    for path, contents in replaceFiles.iteritems():
        ReplaceFileContentsAtomic(path, contents)

    for path, contents in setFiles.iteritems():
        SetFileContents(path, contents)

def UpdateAndPublishHostName(name):
    # Set hostname locally and publish to iDNS

    Run("hostname " + name)

    UpdateAndPublishHostNameCommon(name)

    for ethernetInterface in PossibleEthernetInterfaces:
        Run("ifdown " + ethernetInterface + " && ifup " + ethernetInterface)
    if Global.SendData != None and Global.DhcpResponse != None:
        HandleDhcpResponse(Global.SendData, Global.DhcpResponse)

    # Important: We do not restore routes if the in-box DHCP client wipes out routes again.
    # Leases in Azure don't require renewal and don't expire. Nothing will break
    # as long as the DHCP client is not restarted. This will be fixed when Azure DHCP servers
    # implement option 121 for classless static routes and include the default route in the
    # option to conform with RFC 3442.

class OvfEnv(object):
#
# OLD:
# <?xml version="1.0" encoding="utf-8"?>
# <Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" xmlns:rdfe="http://schemas.microsoft.com/2009/05/WindowsAzure/ServiceManagement" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
#   <rdfe:ProvisioningSection>
#     <OSDParameters xmlns="http://schemas.microsoft.com/2009/05/WindowsAzure/ServiceManagement" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
#         <ComputerName>LinuxAgent</ComputerName>
#         <AdministratorPassword>something</AdministratorPassword>
#     </OSDParameters>
#   </rdfe:ProvisioningSection>
# </Environment>
#
# NEW:
# <?xml version="1.0" encoding="utf-8"?>
# <Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" xmlns:wa="http://schemas.microsoft.com/windowsazure" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
#    <wa:ProvisioningSection>
#      <LinuxProvisioningConfigurationSet xmlns="http://schemas.microsoft.com/windowsazure" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
#        <ConfigurationSetType>LinuxProvisioningConfiguration</ConfigurationSetType>
#        <HostName>MyMachine1</HostName>
#        <SSH>
#          <PublicKeys>
#            <PublicKey>
#              <Fingerprint>EB0C0AB4B2D5FC35F2F0658D19F44C8283E2DD62</Fingerprint>
#              <Path>/etc/ssh/guest</Path>
#            </PublicKey>
#          </PublicKeys>
#          <KeyPairs>
#            <KeyPair>
#              <Fingerprint>EB0C0AB4B2D5FC35F2F0658D19F44C8283E2DD62</Fingerprint>
#              <Path>/etc/ssh/root</Path>
#            </KeyPair>
#          </KeyPairs>
#        </SSH>
#      </LinuxProvisioningConfigurationSet>
#    </wa:ProvisioningSection>
# </Environment>
#
    def __init__(self):
        self.reinitialize()

    def reinitialize(self):
        self.Version = None
        self.ComputerName = None
        self.AdminPassword = None
        self.UserName = None
        self.UserPassword = None
        self.DisableSshPasswordAuthentication = False
        self.SshPublicKeys = []
        self.SshKeyPairs = []

    def Parse(self, xmlText):
        self.reinitialize()
        dom = xml.dom.minidom.parseString(xmlText)
        node = dom.childNodes[0]
        if node.localName != "Environment":
            return Error("root not Environment")
        if node.childNodes[1].nodeName == "rdfe:ProvisioningSection":
            self.ComputerName = dom.getElementsByTagName("ComputerName")[0].childNodes[0].data
            self.AdminPassword = dom.getElementsByTagName("AdministratorPassword")[0].childNodes[0].data
        else:
            self.Version = dom.getElementsByTagName("Version")[0].childNodes[0].data
            self.ComputerName = dom.getElementsByTagName("HostName")[0].childNodes[0].data
            self.UserName = dom.getElementsByTagName("UserName")[0].childNodes[0].data
            self.UserPassword = dom.getElementsByTagName("UserPassword")[0].childNodes[0].data
            self.DisableSshPasswordAuthentication = (dom.getElementsByTagName("DisableSshPasswordAuthentication")[0].childNodes[0].data.lower() == "true")
            for pkey in dom.getElementsByTagName("PublicKey"):
                fp = None
                path = None
                for c in pkey.childNodes:
                    if (c.nodeName == "Fingerprint"): fp = c.childNodes[0].data
                    if (c.nodeName == "Path"): path = c.childNodes[0].data
                self.SshPublicKeys += [[fp, path]]
            for keyp in dom.getElementsByTagName("KeyPair"):
                fp = None
                path = None
                for c in keyp.childNodes:
                    if (c.nodeName == "Fingerprint"): fp = c.childNodes[0].data
                    if (c.nodeName == "Path"): path = c.childNodes[0].data
                self.SshKeyPairs += [[fp, path]]
        return self

    def Process(self):
        Log("Computer Name = " + self.ComputerName)
        UpdateAndPublishHostName(self.ComputerName)
        if self.DisableSshPasswordAuthentication:
            filepath = "/etc/ssh/sshd_config"
            ReplaceFileContentsAtomic(filepath,
                "\n".join(filter(lambda a: not a.startswith("PasswordAuthentication"), GetFileContents(filepath).split("\n")))
                + "PasswordAuthentication no\n")
            Log("SSH PasswordAuthentication has been disabled.")
        if self.AdminPassword != None:
            os.popen("passwd --stdin root", "w").write(self.AdminPassword + "\n")
        if self.UserName != None:
            CreateAccount(self.UserName, self.UserPassword, None, None)
        for pkey in self.SshPublicKeys:
            Run("ssh-keygen -y -f " + pkey[0] + ".pem > " + pkey[1])
        for keyp in self.SshKeyPairs:
            Run("mkdir -p " + pkey[1].rsplit('/', 1)[0])
            Run("cp -f " + pkey[0] + ".pem " + pkey[1])
            Run("chmod 600 " + pkey[1])
            Run("ssh-keygen -y -f " + pkey[0] + ".pem > " + pkey[1] + ".pub")
        ReloadSshd()

class Agent(Util):
    def __init__(self):
        self.GoalState = None
        self.Endpoint = None
        self.LoadBalancerProbeServer = None
        self.HealthReportCounter = 0
        self.TransportCert = ""

    def CheckVersions(self):
        global ProtocolVersion
        protocolVersionSeen = False
#<?xml version="1.0" encoding="utf-8"?>
#<Versions>
#  <Preferred>
#    <Version>2010-12-15</Version>
#  </Preferred>
#  <Supported>
#    <Version>2010-12-15</Version>
#    <Version>2010-28-10</Version>
#  </Supported>
#</Versions>
        node = xml.dom.minidom.parseString(self.HttpGetWithoutHeaders("/?comp=versions")).childNodes[0]
        if node.localName != "Versions":
            return Error("root not Versions")
        for a in node.childNodes:
            if a.nodeType == node.ELEMENT_NODE:
                if a.localName == "Supported":
                    for b in a.childNodes:
                        if b.nodeType == node.ELEMENT_NODE:
                            if b.localName == "Version":
                                for c in b.childNodes:
                                    LogIfVerbose("hostSupportedVersion:" + c.data)
                                    if c.data == ProtocolVersion:
                                        protocolVersionSeen = True
        if not protocolVersionSeen:
             ProtocolVersion = "2011-08-31"
#            return Error("5")
        Log("Negotiated wire protocol version: " + ProtocolVersion)
        return True

    def UpdateGoalState(self):
        #
        # Error 410 "gone" and possibly 403 "forbidden" are common here.
        #
        goalStateXml = None
        maxRetry = 9
        log = NoLog
        for retry in range(1, maxRetry + 1):
            strRetry = str(retry)
            try:
                log("retry UpdateGoalState,retry=" + strRetry)
                goalStateXml = self.HttpGetWithHeaders("/machine/?comp=goalstate")
                break
            except Exception, e:
                log = Log
                if retry < maxRetry:
                    Log("report error and sleep(retry) UpdateGoalState,retry=" + strRetry)
                    Log(e)
                    Log(traceback.format_exc())
                    time.sleep(retry)
                    pass
                else:
                    Log("raise UpdateGoalState,retry=" + strRetry)
                    raise
        if not goalStateXml:
            Error("UpdateGoalState failed")
            return
        log("parse UpdateGoalState")
        self.GoalState = GoalState(self).Parse(goalStateXml)
        log("return UpdateGoalState")
        return self.GoalState

    def ReportHealth(self):
        counter = (self.HealthReportCounter + 1) % 1000000
        self.HealthReportCounter = counter
        healthReport = ("<?xml version=\"1.0\" encoding=\"utf-8\"?><Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GoalStateIncarnation>"
                        + self.GoalState.Incarnation 
                        + "</GoalStateIncarnation><Container><ContainerId>"
                        + self.GoalState.ContainerId
                        + "</ContainerId><RoleInstanceList><Role><InstanceId>"
                        + self.GoalState.RoleInstanceId
                        + "</InstanceId><Health><State>Ready</State></Health></Role></RoleInstanceList></Container></Health>")
        a = self.HttpPost("/machine?comp=health", healthReport)
        b = a.getheader("x-ms-latest-goal-state-incarnation-number")
        return b

    def ReportProvisioning(self):
        healthReport = ("<?xml version=\"1.0\" encoding=\"utf-8\"?><Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GoalStateIncarnation>"
                        + self.GoalState.Incarnation 
                        + "</GoalStateIncarnation><Container><ContainerId>"
                        + self.GoalState.ContainerId
                        + "</ContainerId><RoleInstanceList><Role><InstanceId>"
                        + self.GoalState.RoleInstanceId
                        + "</InstanceId><Health><State>NotReady</State>"
                        + "<Details><SubStatus>Provisioning</SubStatus><Description>Starting</Description></Details>"
                        + "</Health></Role></RoleInstanceList></Container></Health>")
        return self.HttpPost("/machine?comp=health", healthReport)

    def LoadBalancerProbeServer_Shutdown(self):
        if self.LoadBalancerProbeServer != None:
            self.LoadBalancerProbeServer.shutdown()
            self.LoadBalancerProbeServer = None

    def Run(self):
        if (GetIpv4Address() == None):
            Log("Waiting for network.")
            while(GetIpv4Address() == None):
                time.sleep(10)

        Log("IPv4 address: " + GetIpv4Address())
        Log("MAC  address: " + str(":".join(["%02X" % Ord(a) for a in GetMacAddress()])))

        self.UdevRulesWatcher = UdevRulesWatcher()

        Log("Probing for Windows Azure environment.")
        self.Endpoint = DoDhcpWork()

        if not self.Endpoint:
            Log("Windows Azure environment not detected.")
            while True:
                time.sleep(60)

        Log("Discovered Windows Azure endpoint: " + self.Endpoint)
        if not self.CheckVersions():
            Error("Agent.CheckVersions failed")
            sys.exit(1)

        self.TransportCert = GenerateTransportCert()

        incarnation = None # goalStateIncarnationFromHealthReport
        currentPort = None # loadBalancerProbePort
        goalState = None # self.GoalState, instance of GoalState
        provisioned = os.path.exists(LibDir + "/provisioned")
        while True:
            if (goalState == None) or (incarnation == None) or (goalState.Incarnation != incarnation):
                goalState = self.UpdateGoalState()

                if provisioned == False:
                    self.ReportProvisioning()

                goalState.Process()

                if provisioned == False:
                    SshHostKeyThumbprint = Provision()
                    if SshHostKeyThumbprint != None:
                        self.RoleProperties = RoleProperties(self, goalState.ContainerId, goalState.RoleInstanceId, SshHostKeyThumbprint)
                        self.RoleProperties.post()
                    program = Config.get("Role.StateConsumer")
                    if program != None and program != "None":
                        os.spawnl(os.P_NOWAIT, program, program, "Ready")
                    provisioned = True

                #
                # only one port supported
                # restart server if new port is different than old port
                # stop server if no longer a port
                #
                goalPort = goalState.LoadBalancerProbePort
                if currentPort != goalPort:
                    self.LoadBalancerProbeServer_Shutdown()
                    currentPort = goalPort
                    if currentPort != None:
                        self.LoadBalancerProbeServer = LoadBalancerProbeServer(currentPort)
            if goalState.ExpectedState == "Stopped":
                program = Config.get("Role.StateConsumer")
                if program != None and program != "None":
                    Run(program + " Shutdown")
                command = ["/sbin/shutdown -hP now", "shutdown /s /t 5"][IsWindows()]
                self.LoadBalancerProbeServer_Shutdown()
                Run(command)
                return

            sleepToReduceAccessDenied = 3
            time.sleep(sleepToReduceAccessDenied)
            incarnation = self.ReportHealth()
            time.sleep(30 - sleepToReduceAccessDenied)

Init_Suse = """\
#! /bin/sh

### BEGIN INIT INFO
# Provides: WindowsAzureGuestAgent
# Required-Start: $network sshd
# Required-Stop: $network sshd
# Default-Start: 3 5
# Default-Stop: 0 1 2 6
# Description: Start the WindowsAzureGuestAgent
### END INIT INFO

WAZD_BIN=/usr/sbin/waagent
test -x $WAZD_BIN || exit 5

WAZD_PIDFILE=/var/run/waagent.init.pid

. /etc/rc.status

# First reset status of this service
rc_reset

case "$1" in
    start)
        echo -n "Starting WindowsAzureGuestAgent"
        ## Start daemon with startproc(8). If this fails
        ## the echo return value is set appropriate.

        startproc -f -p $WAZD_PIDFILE $WAZD_BIN

        # Remember status and be verbose
        rc_status -v
        ;;
    stop)
        echo -n "Shutting down WindowsAzureGuestAgent"
        ## Stop daemon with killproc(8) and if this fails
        ## set echo the echo return value.

        killproc -p $WAZD_PIDFILE -TERM $WAZD_BIN

        # Remember status and be verbose
        rc_status -v
        ;;
    try-restart)
        ## Stop the service and if this succeeds (i.e. the 
        ## service was running before), start it again.
        $0 status >/dev/null &&  $0 restart

        # Remember status and be quiet
        rc_status
        ;;
    restart)
        ## Stop the service and regardless of whether it was
        ## running or not, start it again.
        $0 stop
        $0 start

        # Remember status and be quiet
        rc_status
        ;;
    force-reload|reload)
        ;;
    status)
        echo -n "Checking for service WindowsAzureGuestAgent "
        ## Check status with checkproc(8), if process is running
        ## checkproc will return with exit status 0.

        # Status has a slightly different for the status command:
        # 0 - service running
        # 1 - service dead, but /var/run/  pid  file exists
        # 2 - service dead, but /var/lock/ lock file exists
        # 3 - service not running

        checkproc -p $WAZD_PIDFILE $WAZD_BIN

        rc_status -v
        ;;
    probe)
        ;;
    *)
        echo "Usage: $0 {start|stop|status|try-restart|restart|force-reload|reload|probe}"
        exit 1
        ;;
esac
rc_exit
"""

Init_RedHat = """\
#!/bin/bash
#
# Init file for WindowsAzureGuestAgent.
#
# chkconfig: 2345 60 80
# description: WindowsAzureGuestAgent
#

# source function library
. /etc/rc.d/init.d/functions

RETVAL=0
FriendlyName="WindowsAzureGuestAgent"
WAZD_BIN=/usr/sbin/waagent

start()
{
    echo -n $"Starting $FriendlyName: "
    $WAZD_BIN &
}

stop()
{
    echo -n $"Stopping $FriendlyName: "
    killproc $WAZD_BIN
    RETVAL=$?
    echo
    return $RETVAL
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    reload)
        ;;
    report)
        ;;
    status)
        status $WAZD_BIN
        RETVAL=$?
        ;;
    *)
        echo $"Usage: $0 {start|stop|restart|status}"
        RETVAL=1
esac
exit $RETVAL
"""

Init_Ubuntu = """\
#!/bin/sh
### BEGIN INIT INFO
# Provides:          WindowsAzureGuestAgent
# Required-Start:    $network $syslog
# Required-Stop:     $network $syslog
# Should-Start:      $network $syslog
# Should-Stop:       $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: WindowsAzureGuestAgent
# Description:       WindowsAzureGuestAgent
### END INIT INFO

. /lib/lsb/init-functions

OPTIONS=""
WAZD_BIN=/usr/sbin/waagent

case "$1" in
    start)
        log_begin_msg "Starting WindowsAzureGuestAgent..."
        pid=$( pidofproc $WAZD_BIN )
        if [ -n "$pid" ] ; then
              log_begin_msg "Already running."
              log_end_msg 0
              exit 0
        fi
        start-stop-daemon --start --quiet --oknodo --background --exec $WAZD_BIN -- $OPTIONS
        log_end_msg $?
        ;;

    stop)
        log_begin_msg "Stopping WindowsAzureGuestAgent..."
        start-stop-daemon --stop --quiet --oknodo --exec $WAZD_BIN
        log_end_msg $?
        ;;
    force-reload)
        $0 restart
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    status)
        status_of_proc $WAZD_BIN && exit 0 || exit $?
        ;;
    *)
        log_success_msg "Usage: /etc/init.d/waagent {start|stop|force-reload|restart|status}"
        exit 1
        ;;
esac

exit 0
"""

WaagentConf = """\
#
# Windows Azure Guest Agent Configuration
#

Role.StateConsumer=None                 # Specified program is invoked with "Ready" or "Shutdown". 
                                        # Shutdown will be initiated only after the program returns. Windows Azure will 
                                        # power off the VM if shutdown is not completed within ?? minutes.
Role.ConfigurationConsumer=None         # Specified program is invoked with XML file argument specifying role configuration.
Role.TopologyConsumer=None              # Specified program is invoked with XML file argument specifying role topology.

Provisioning.Enabled=y                  #
Provisioning.DeleteRootPassword=n       # Password authentication for root account will be unavailable.
Provisioning.RegenerateSshHostKeyPair=y # If an RSA keypair is supplied in the ISO, that will be used instead.
Provisioning.SshHostKeyPairType=rsa     # Supported values are "rsa", "dsa" and "ecdsa".
Provisioning.RunPrograms=y              # Run additional code that may be present on the ISO.

ResourceDisk.Format=y                   # Format if unformatted. If 'n', resource disk will not be mounted.
ResourceDisk.Filesystem=ext4            #
ResourceDisk.MountPoint=/mnt/resource   #
ResourceDisk.EnableSwap=n               # Create and use swapfile on resource disk.
ResourceDisk.SwapSizeMB=0               # Size of the swapfile.

LBProbeResponder=y                      #

Logs.Verbose=n                          #
"""

WaagentLogrotate = """\
/var/log/waagent.log {
    monthly
    rotate 6
    notifempty
    missingok
}
"""

def AddToLinuxKernelCmdline(options):
    if os.path.isfile("/boot/grub/menu.lst"):
        Run("sed -i '/kernel/s|$| " + options + " |' /boot/grub/menu.lst")
    filepath = "/etc/default/grub"
    if os.path.isfile(filepath):
        filecontents = GetFileContents(filepath).split("\n")
        current = filter(lambda a: a.startswith("GRUB_CMDLINE_LINUX"), filecontents)
        ReplaceFileContentsAtomic(filepath,
            "\n".join(filter(lambda a: not a.startswith("GRUB_CMDLINE_LINUX"), filecontents))
            + current[0][:-1] + " " + options + "\"\n")
        Run("update-grub")


def ApplyVNUMAWorkaround():
    VersionParts = platform.release().replace("-", ".").split(".")
    if int(VersionParts[0]) > 2:
        return
    if int(VersionParts[1]) > 6:
        return
    if int(VersionParts[2]) > 37:
        return
    AddToLinuxKernelCmdline("numa=off")
    print("Your kernel version " + platform.release() + " has a NUMA-related bug: NUMA has been disabled.")

def RevertVNUMAWorkaround():
    print("Automatic reverting of GRUB configuration is not yet supported. Please edit by hand.")

def Install():
    if IsWindows():
        print("ERROR: -install invalid for windows, see waagent_service.exe")
        return 0
    Run("chmod +x " + sys.argv[0])
    SwitchCwd()
    requiredDeps = [ "/sbin/route", "/sbin/shutdown" ]
    if IsUbuntu() or IsSuse():
        requiredDeps += [ "/sbin/insserv" ]
    for a in requiredDeps:
        if not os.path.isfile(a):
            Error("missing required dependency: " + a)
            Error("Setup Failure")
            return 1
    missing = False
    for a in [ "ssh-keygen", "useradd", "openssl", "sfdisk",
               "fdisk", "mkfs", "passwd", "sed",
               "tr", "grep", "cut" ]:
        if Run("which " + a + " > /dev/null 2>&1"):
            Warn("missing dependency: " + a)
            missing = True
    if missing == True:
        print("WARNING! Please resolve missing dependencies listed for full functionality.")
    print("WARNING! Will overwrite /etc/waagent.conf.")
    print("WARNING! Will delete udev persistent networking rules.")
    if not raw_input('Do you want to proceed (y/n)? ').startswith('y'):
        return 0
    for a in RulesFiles:
        if os.path.isfile(a):
            if os.path.isfile(GetLastPathElement(a)):
                os.remove(GetLastPathElement(a))
            shutil.move(a, ".")
            Log("Installer: Moved " + a + " -> " + LibDir)
    filename = "waagent"
    filepath = "/etc/init.d/" + filename
    a = IsRedHat() + IsUbuntu() * 2 + IsSuse() * 3
    if a == 0:
        print("distribution not detected")
        return 1
    a = [[Init_RedHat, "chkconfig --add " + filename],
         [Init_Ubuntu, "insserv " + filename + " > /dev/null 2>&1"],
         [Init_Suse, "insserv " + filename]][a - 1]
    SetFileContents(filepath, a[0])
    Run("chmod +x " + filepath)
    Run(a[1])
    SetFileContents("/etc/waagent.conf", WaagentConf)
    SetFileContents("/etc/logrotate.d/waagent", WaagentLogrotate)
    ApplyVNUMAWorkaround()
    return 0

def Uninstall():
    if IsWindows():
        print("ERROR: -uninstall invalid for windows, see waagent_service.exe")
        return 0
    SwitchCwd()
    for a in RulesFiles:
        if os.path.isfile(GetLastPathElement(a)):
            try:
                shutil.move(GetLastPathElement(a), a)
            except:
                pass
    filename = "waagent"
    a = IsRedHat() + IsUbuntu() * 2 + IsSuse() * 3
    if a == 0:
        print("distribution not detected")
        return 1
    a = ["chkconfig --del " + filename,
         "insserv -r " + filename + " > /dev/null 2>&1",
         "insserv -r " + filename][a - 1]
    Run(a)
    os.remove("/etc/init.d/" + filename)
    os.remove("/etc/waagent.conf")
    os.remove("/etc/logrotate.d/waagent")
    RevertVNUMAWorkaround()
    return 0

def DeleteRootPassword():
    Run("touch /etc/shadow-temp")
    Run("chmod a-rwx /etc/shadow-temp")
    Run("(echo root:*LOCK*:14600:::::: && grep -v ^root /etc/shadow ) > /etc/shadow-temp")
    Run("mv -f /etc/shadow-temp /etc/shadow")
    Log("Root password deleted.")

def GeneralizeWindows():
    Run(os.environ["windir"] + "\\system32\\sysprep\\sysprep.exe /generalize")
    return 0

def GeneralizeLinux():
    print("WARNING! SSH host RSA and DSA keys will be deleted.")
    print("WARNING! Nameserver configuration in /etc/resolv.conf will be deleted.")
    print("WARNING! root password may be disabled. You will not be able to login as root.")
    print("WARNING! Cached DHCP leases will be deleted.")
    if not raw_input('Do you want to proceed (y/n)? ').startswith('y'):
        return 0

    # Clear Provisioned Flag
    os.remove(LibDir + "/provisioned")

    # Remove SSH host keys
    regenerateKeys = Config.get("Provisioning.RegenerateSshHostKeyPair")
    if regenerateKeys == None or regenerateKeys.lower().startswith("y"):
        Run("rm -f /etc/ssh/ssh_host_ecdsa_key*")
        Run("rm -f /etc/ssh/ssh_host_dsa_key*")
        Run("rm -f /etc/ssh/ssh_host_rsa_key*")
        Run("rm -f /etc/ssh/ssh_host_key*")

    # Remove nameserver
    os.remove("/etc/resolv.conf")

    # Remove root password
    delRootPass = Config.get("Provisioning.DeleteRootPassword")
    if delRootPass != None and delRootPass.lower().startswith("y"):
        DeleteRootPassword()

    # Remove distribution specific networking configuration

    UpdateAndPublishHostNameCommon("localhost.localdomain")

    # RedHat, Suse, Ubuntu
    for a in VarLibDhcpDirectories:
        Run("rm -f " + a + "/*")    

    if not (IsUbuntu() or IsRedHat() or IsSuse()):
        print("distribution not detected")
        return 1
    return 0

def Generalize():
    if IsWindows():
        GeneralizeWindows()
    else:
        GeneralizeLinux()

def SwitchCwd():
    if not IsWindows():
        try:
            os.mkdir(LibDir, 0700)
        except:
            pass
        os.chdir(LibDir)

def Usage():
    print("usage: " + sys.argv[0] + " [-verbose] [-help|-install|-uninstall|-generalize|-version|-serialconsole|-test-*]")
    sys.exit(0)

if GuestAgentVersion == "":
    print("WARNING! This is a non-standard agent that does not include a valid version string.")
if IsLinux() and not DetectLinuxDistro():
    print("WARNING! Unable to detect Linux distribution. Some functionality may be broken.")

Config = ConfigurationProvider()

verbose = Config.get("Logs.Verbose")
if verbose != None and verbose.lower().startswith("y"):
    Global.Verbose = True

if len(sys.argv) > 1:
    for a in sys.argv[1:]:
        if re.match("^([-/]*)(help|usage|\?)", a):
            Usage()
    for a in sys.argv[1:]:
        if re.match("^([-/]*)test$", a):
            for a in [ "IsWindows()",
                       "IsLinux()",
                       "IsSuse()",
                       "IsUbuntu()",
                       "IsRedHat()",
                     ]:
                sys.stdout.write(a + ":")
                print(str(eval(a)))
            sys.exit(0)
        if re.match("^([-/]*)(help|usage|\?)", a):
            pass
        elif re.match("^([-/]*)(setup|install)", a):
            sys.exit(Install())
        elif re.match("^([-/]*)(uninstall)", a):
            sys.exit(Uninstall())
        elif re.match("^([-/]*)generalize", a):
            sys.exit(Generalize())
        elif re.match("^([-/]*)verbose", a):
            Global.Verbose = True
        elif re.match("^([-/]*)version", a):
            print(GuestAgentVersion + " running on " + LinuxDistro)
            sys.exit(0)
        elif re.match("^([-/]*)serialconsole", a):
            AddToLinuxKernelCmdline("console=ttyS0 earlyprintk=ttyS0")
            Log("Configured kernel to use ttyS0 as the boot console.")
            sys.exit(0)
        else:
            print("invalid command line parameter:" + a)
            sys.exit(1)

try:
    SwitchCwd()
    Log("Windows Azure Linux Guest Agent version: " + GuestAgentVersion)
    if IsLinux():
        Log("Linux Distribution Detected            : " + LinuxDistro)
    Agent().Run()
except Exception, e:
    Error("exiting due to:" + str(e))
    Error(traceback.format_exc())
    sys.exit(1)
=======
#!/usr/bin/python

#
# Windows Azure Guest Agent
#
# Requires Python 2.4+ and Openssl 1.0+
#
# Implements parts of RFC 2131, 1541, 1497 and
# http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
# http://msdn.microsoft.com/en-us/library/cc227259%28PROT.13%29.aspx
#

#import array

import array
#import array
import base64
import httplib
import os
import os.path
import platform
import re
import shutil
import socket
import SocketServer
import struct
import sys
import tempfile
import textwrap
import threading
import time
import traceback
import xml.dom.minidom

GuestAgentName = "LinuxAgent"
GuestAgentVersion = "" # filled in by build; be careful with this line and GuestAgentVersion
ProtocolVersion = "2011-12-31"
Config = None
LinuxDistro = None

class Global:
    Verbose = False
    ShortSleep = 0 # good for testing/debugging
    SendData = None
    DhcpResponse = None

class WindowsClass:
    def Detect(self):
        return (platform.uname()[0] == "Windows")
Windows = WindowsClass()

class LinuxClass:
    def Detect(self):
        return (platform.uname()[0] == "Linux")
Linux = LinuxClass()

class UbuntuClass:
    HostnameFile = "/etc/hostname"
    def Detect(self):
        return os.path.isfile("/etc/lsb-release") and "Ubuntu" in GetFileContents("/etc/lsb-release")
Ubuntu = UbuntuClass()

class SuseClass:
    HostnameFile = "/etc/HOSTNAME"
    def Detect(self):
        return os.path.isfile("/etc/SuSE-release")
Suse = SuseClass()

class RedHatClass:
    def Detect(self):
        return os.path.isfile("/etc/redhat-release")
RedHat = RedHatClass()

PossibleEthernetInterfaces = ["seth0", "seth1", "eth0", "eth1"]
RulesFiles = [ "/lib/udev/rules.d/75-persistent-net-generator.rules",
               "/etc/udev/rules.d/70-persistent-net.rules" ]
VarLibDhcpDirectories = ["/var/lib/dhclient", "/var/lib/dhcpcd", "/var/lib/dhcp"]
EtcDhcpClientConfFiles = ["/etc/dhcp/dhclient.conf", "/etc/dhcp3/dhclient.conf"]
LibDir = "/var/lib/waagent"

# This lets us index into a string or an array of integers transparently.
def Ord(a):
    if type(a) == type("a"):
        a = ord(a)
    return a

def IsWindows():
    return Windows.Detect()

def IsLinux():
    return Linux.Detect()

def DetectLinuxDistro():
    global LinuxDistro
    if RedHat.Detect():
        LinuxDistro = "RedHat"
        return 1
    if Ubuntu.Detect():
        LinuxDistro = "Ubuntu"
        return 1
    if Suse.Detect():
        LinuxDistro = "Suse"
        return 1
    return 0

def IsRedHat():
    return "RedHat" in LinuxDistro

def IsUbuntu():
    return "Ubuntu" in LinuxDistro

def IsSuse():
    return "Suse" in LinuxDistro

def GetLastPathElement(path):
    return path.rsplit('/', 1)[1]

def GetFileContents(filepath):
    file = open(filepath)
    try:
        return file.read()
    finally:
        file.close()

def SetFileContents(filepath, contents):
    file = open(filepath, "w")
    try:
        file.write(contents)
    finally:
        file.close()

def ReplaceFileContentsAtomic(filepath, contents):
    handle, temp = tempfile.mkstemp(dir = os.path.dirname(filepath))
    try:
        os.write(handle, contents)
    finally:
        os.close(handle)
    try:
        os.rename(temp, filepath)
        return
    except:
        pass
    os.remove(filepath)
    os.rename(temp, filepath)

def Run(a):
    LogIfVerbose(a)
    return os.system(a)

def GenerateTransportCert():
    Run("openssl req -x509 -nodes -subj /CN=LinuxTransport -days 32768 -newkey rsa:2048 -keyout TransportPrivate.pem -out TransportCert.pem")
    cert = ""
    for line in GetFileContents("TransportCert.pem").split("\n"):
        if not "CERTIFICATE" in line: 
            cert += line.rstrip()
    return cert

def DecryptPassword(e):
    SetFileContents("password.p7m",
        "MIME-Version: 1.0\n"
        + "Content-Disposition: attachment; filename=\"password.p7m\"\n"
        + "Content-Type: application/x-pkcs7-mime; name=\"password.p7m\"\n"
        + "Content-Transfer-Encoding: base64\n\n"
        + textwrap.fill(e, 64))
    return os.popen("openssl cms -decrypt -in password.p7m -inkey Certificates.pem -recip Certificates.pem").read()

def CreateAccount(user, password, expiration, thumbprint):
    if IsWindows():
        Log("skipping CreateAccount on Windows")
        return
    group = "wheel"
    if IsUbuntu():
        group = "admin"
    command = "useradd " + user + " -G " + group
    if expiration != None:
        command += " -e " + expiration.split(".")[0]
    Run(command)
    Run("echo " + password + " | passwd --stdin " + user)
    if (thumbprint != None):
        Run("rm -f /home/" + user + "/.ssh/id_rsa*")
        Run("mkdir /home/" + user + "/.ssh")
        Run("chmod 600 " + thumbprint + ".pem")
        Run("ssh-keygen -y -f " + thumbprint + ".pem > /home/" + user + "/.ssh/id_rsa.pub")
        Run("cp " + thumbprint + ".pem /home/" + user + "/.ssh/id_rsa")
        Run("chmod 600 /home/" + user + "/.ssh/id_rsa*")
        Run("chown " + user + " /home/" + user + "/.ssh/id_rsa*")
        Run("cp -f /home/" + user + "/.ssh/id_rsa.pub /home/" + user + "/.ssh/authorized_keys")
    Log("Created user account: " + user)

def ActivateResourceDisk():
    if IsWindows():
        Log("skipping ActivateResourceDisk on Windows")
        return
    format = Config.get("ResourceDisk.Format")
    if format != None and format.lower().startswith("n"):
        return
    device = "/dev/hdb"
    if Run("ls -R /sys/devices/ | grep vmbus | grep hdb > /dev/null"):
        if Run("ls -R /sys/devices/ | grep vmbus | grep sdb > /dev/null"):
            Log("Skipping ActivateResourceDisk: Unable to detect disk topology")
            return
        else:
            device = "/dev/sdb"
    if not Run("mount | grep ^" + device + "1"):
        Log(device + "1 is already mounted.")
        return
    mountpoint = Config.get("ResourceDisk.MountPoint")
    if mountpoint == None:
        mountpoint = "/mnt/resource"
    Run("mkdir " + mountpoint)
    if Run("mount " + device + "1 " + mountpoint):
        if os.popen("sfdisk -q -c " + device + " 1").read().rstrip() == "7":
            Run("sfdisk -c " + device + " 1 83")
        else:
            Log("Failed to mount " + device + "1 and partition type is not NTFS. Will not reformat.")
            return
        fs = Config.get("ResourceDisk.Filesystem")
        if fs == None:
            fs = "ext3"
        Run("mkfs." + fs + " " + device + "1")
        if Run("mount " + device + "1 " + mountpoint):
            Log("Unexpected failure to mount after formatting")
            return
    swap = Config.get("ResourceDisk.EnableSwap")
    if swap != None and swap.lower().startswith("y"):
        sizeKB = int(Config.get("ResourceDisk.SwapSizeMB")) * 1024
        if os.path.isfile(mountpoint + "/swapfile") and os.path.getsize(mountpoint + "/swapfile") != (sizeKB * 1024):
            os.remove(mountpoint + "/swapfile")
        if not os.path.isfile(mountpoint + "/swapfile"):
            Run("dd if=/dev/zero of=" + mountpoint + "/swapfile bs=1024 count=" + str(sizeKB))
            Run("mkswap " + mountpoint + "/swapfile")
        Run("swapon " + mountpoint + "/swapfile")
        Log("Enabled " + str(sizeKB) + " KB of swap at " + mountpoint + "/swapfile")
    Log("Resource disk (" + device + "1) is mounted at " + mountpoint)

def ReloadSshd():
    name = None
    if IsRedHat() or IsSuse():
        name = "sshd"
    if IsUbuntu():
        name = "ssh"
    if name == None:
        return
    if not Run("service " + name + " status | grep running"):
        Run("service " + name + " reload")

def Provision():
    if IsWindows():
        Log("skipping Provision on Windows")
        return None
    enabled = Config.get("Provisioning.Enabled")
    if enabled != None and enabled.lower().startswith("n"):
        return None
    Log("Provisioning image started.")
    regenerateKeys = Config.get("Provisioning.RegenerateSshHostKeyPair")
    type = Config.get("Provisioning.SshHostKeyPairType")
    if regenerateKeys == None or regenerateKeys.lower().startswith("y"):
        Run("rm -f /etc/ssh/ssh_host_ecdsa_key*")
        Run("rm -f /etc/ssh/ssh_host_dsa_key*")
        Run("rm -f /etc/ssh/ssh_host_rsa_key*")
        Run("rm -f /etc/ssh/ssh_host_key*")
        Log("Generating SSH host " + type + " keypair.")
        Run("ssh-keygen -N '' -t " + type + " -f /etc/ssh/ssh_host_" + type + "_key")
        ReloadSshd()
    Run("touch " + LibDir + "/provisioned")
    dvd = "/dev/hdc"
    if os.path.exists("/dev/scd0"):
        dvd = "/dev/scd0"
    if Run("fdisk -l " + dvd + " | grep Disk"):
        return None
    os.makedirs("/mnt/cdrom/secure", 0700)
    Run("mount " + dvd + " /mnt/cdrom/secure")
    ovfxml = GetFileContents("/mnt/cdrom/secure/ovf-env.xml")
    SetFileContents("ovf-env.xml", ovfxml)
    runProgs = Config.get("Provisioning.RunPrograms")
    auxProg = "/mnt/cdrom/secure/waagent-aux.sh"
    if runProgs != None and runProgs.lower().startswith("y") and os.path.isfile(auxProg):
        Log("Running auxillary programs from the DVD.")
        Run(auxProg)
    ovfxml = GetFileContents("ovf-env.xml")
    Run("umount /mnt/cdrom/secure")
    if ovfxml != None:
        Log("Provisioning image from OVF data in the DVD.")
        ovfobj = OvfEnv().Parse(ovfxml)
        ovfobj.Process()
    delRootPass = Config.get("Provisioning.DeleteRootPassword")
    if delRootPass != None and delRootPass.lower().startswith("y"):
        DeleteRootPassword()
    Log("Provisioning image completed.")
    return os.popen("ssh-keygen -lf /etc/ssh/ssh_host_" + type + "_key.pub  | cut -f 2 -d ' ' | tr -d :").read()

def IsInRangeInclusive(a, low, high):
    return (a >= low and a <= high)

def IsPrintable(ch):
    return IsInRangeInclusive(ch, Ord('A'), Ord('Z')) or IsInRangeInclusive(ch, Ord('a'), Ord('z')) or IsInRangeInclusive(ch, Ord('0'), Ord('9'))

def HexDump(buffer, size):
    if size < 0:
        size = len(buffer)
    result = ""
    for i in range(0, size):
        if (i % 16) == 0:
            result += "%06X: " % i
        byte = struct.unpack("B", buffer[i])[0]
        result += "%02X " % byte
        if (i & 15) == 7:
            result += " "
        if ((i + 1) % 16) == 0 or (i + 1) == size:
            j = i
            while ((j + 1) % 16) != 0:
                result += "   "
                if (j & 7) == 7:
                    result += " "
                j += 1
            result += " "
            for j in range(i - (i % 16), i + 1):
                byte = struct.unpack("B", buffer[j])[0]
                k = '.'
                if IsPrintable(byte):
                    k = chr(byte)
                result += k
            if (i + 1) != size:
                result += "\n"
    return result

def HexDump2(buffer):
    return HexDump3(buffer, 0, len(buffer))

def HexDump3(buffer, offset, length):
    return ''.join(['%02X' % Ord(char) for char in buffer[offset:offset + length]])
    
def ThrottleLog(counter):
    # Log everything up to 10, every 10 up to 100, then every 100.
    return (counter < 10) or ((counter < 100) and ((counter % 10) == 0)) or ((counter % 100) == 0)

def IntegerToIpAddressV4String(a):
    return "%u.%u.%u.%u" % ((a >> 24) & 0xFF, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF)

def Logger():

    class T(object):

        def __init__(self):
            self.File = None

    self = T()

    def LogToFile(message):
        FilePath = ["/var/log/waagent.log", "waagent.log"][IsWindows()]
        if not os.path.isfile(FilePath) and self.File != None:
            self.File.close()
            self.File = None
        if self.File == None:
            self.File = open(FilePath, "a")
        self.File.write(message + "\n")
        self.File.flush()

    def Log(message):
        LogWithPrefix("", message)

    def LogWithPrefix(prefix, message):
        t = time.localtime()
        t = "%04u/%02u/%02u %02u:%02u:%02u " % (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        t += prefix
        for line in message.split("\n"):
            line = t + line
            print(line)
            LogToFile(line)

    return Log, LogWithPrefix

Log, LogWithPrefix = Logger()

def NoLog(message):
    pass

def LogIfVerbose(message):
    if Global.Verbose == True:
        Log(message)

def LogWithPrefixIfVerbose(prefix, message):
    if Global.Verbose == True:
        LogWithPrefix(prefix, message)

def Debug(message):
    LogWithPrefix("Debug:", message)

def Warn(message):
    LogWithPrefix("WARNING:", message)

def WarnWithPrefix(prefix, message):
    LogWithPrefix("WARNING:" + prefix, message)

def Error(message):
    LogWithPrefix("ERROR:", message)

def ErrorWithPrefix(prefix, message):
    LogWithPrefix("ERROR:" + prefix, message)

def GetHttpDateTimeNow():
    # Date: Fri, 25 Mar 2011 04:53:10 GMT
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

def linux_ioctl_GetIpv4Address(ifname):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

def linux_ioctl_GetInterfaceMac(ifname):
    import fcntl
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ''.join(['%02X' % Ord(char) for char in info[18:24]])

def GetIpv4Address():
    if IsLinux():
        for ifname in PossibleEthernetInterfaces:
            try:
                return linux_ioctl_GetIpv4Address(ifname)
            except IOError, e:
                #ErrorWithPrefix("GetIpv4Address:", str(e))
                #ErrorWithPrefix("GetIpv4Address:", traceback.format_exc())
                pass
    else:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception, e:
            ErrorWithPrefix("GetIpv4Address:", str(e))
            ErrorWithPrefix("GetIpv4Address:", traceback.format_exc())

def GetMacAddress():
    if IsWindows():
        # Windows:   Physical Address. . . . . . . . . : 00-15-17-79-00-7F\n
        a = "ipconfig /all | findstr /c:\"Physical Address\" | findstr /v \"00-00-00-00-00-00-00\""
        a = os.popen(a).read()
        a = re.sub("\s+$", "", a)
        a = re.sub(".+ ", "", a)
        a = re.sub(":", "", a)
        a = re.sub("-", "", a)
    else:
        for ifname in PossibleEthernetInterfaces:
            try:
                a = linux_ioctl_GetInterfaceMac(ifname)
                break
            except IOError, e:
                #ErrorWithPrefix("GetMacAddress:", str(e))
                #ErrorWithPrefix("GetMacAddress:", traceback.format_exc())
                pass
    return HexStringToByteArray(a)

def Network_Route_SetDefaultGateway(gateway):
    if IsWindows():
        return
    Run("/sbin/route add -net 0.0.0.0 netmask 0.0.0.0 gw " + gateway)

def Network_Route_Add(net, mask, gateway):
    if IsWindows():
        return
    net = IntegerToIpAddressV4String(net)
    mask = IntegerToIpAddressV4String(mask)
    gateway = IntegerToIpAddressV4String(gateway)    
    Run("/sbin/route add -net " + net + " netmask " + mask + " gw " + gateway)

def HexStringToByteArray(a):
    b = ""
    for c in range(0, len(a) / 2):
        b += struct.pack("B", int(a[c * 2:c * 2 + 2], 16))
    return b

class Util(object):
    def _HttpGet(self, url, headers):
        LogIfVerbose("HttpGet(" + url + ")")
        maxRetry = 2
        if url.startswith("http://"):
            url = url[7:]
            url = url[url.index("/"):]
        for retry in range(0, maxRetry + 1):
            strRetry = str(retry)
            log = [NoLog, Log][retry > 0]
            log("retry HttpGet(" + url + "),retry=" + strRetry)
            response = None
            strStatus = "None"
            try:
                httpConnection = httplib.HTTPConnection(self.Endpoint)
                if headers == None:
                    request = httpConnection.request("GET", url)
                else:
                    request = httpConnection.request("GET", url, None, headers)
                response = httpConnection.getresponse()
                strStatus = str(response.status)
            except:
                pass
            log("response HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
            if response == None or response.status != httplib.OK:
                Error("HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                if retry == maxRetry:
                    Log("raise HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                    raise response
                else:
                    Log("sleep 10 seconds HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                    time.sleep(10)
            else:
                log("return HttpGet(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                return response.read()

    def HttpGetWithoutHeaders(self, url):
        return self._HttpGet(url, None)

    def HttpGetWithHeaders(self, url):
        return self._HttpGet(url, {"x-ms-agent-name": GuestAgentName, "x-ms-version": ProtocolVersion})

    def HttpSecureGetWithHeaders(self, url, transportCert):
        return self._HttpGet(url, {"x-ms-agent-name": GuestAgentName,
                                   "x-ms-version": ProtocolVersion,
                                   "x-ms-cipher-name": "DES_EDE3_CBC",
                                   "x-ms-guest-agent-public-x509-cert": transportCert})

    def HttpPost(self, url, data):
        LogIfVerbose("HttpPost(" + url + ")")
        maxRetry = 2
        for retry in range(0, maxRetry + 1):
            strRetry = str(retry)
            log = [NoLog, Log][retry > 0]
            log("retry HttpPost(" + url + "),retry=" + strRetry)
            response = None
            strStatus = "None"
            try:
                httpConnection = httplib.HTTPConnection(self.Endpoint)
                request = httpConnection.request("POST", url, data, {"x-ms-agent-name": GuestAgentName,
                                                                     "Content-Type": "text/xml; charset=utf-8",
                                                                     "x-ms-version": ProtocolVersion})
                response = httpConnection.getresponse()
                strStatus = str(response.status)
            except:
                pass
            log("response HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
            if response == None or (response.status != httplib.OK and response.status != httplib.ACCEPTED):
                Error("HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                if retry == maxRetry:
                    Log("raise HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                    raise response
                else:
                    Log("sleep 10 seconds HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                    time.sleep(10)
            else:
                log("return HttpPost(" + url + "),retry=" + strRetry + ",status=" + strStatus)
                return response

def LoadBalancerProbeServer(port):

    class T(object):
        def __init__(self, port):
            enabled = Config.get("LBProbeResponder")
            if enabled != None and enabled.lower().startswith("n"):
                return
            self.ProbeCounter = 0
            self.server = SocketServer.TCPServer((GetIpv4Address(), port), TCPHandler)
            self.server_thread = threading.Thread(target = self.server.serve_forever)
            self.server_thread.setDaemon(True)
            self.server_thread.start()

        def shutdown(self):
            global EnableLoadBalancerProbes
            if not EnableLoadBalancerProbes:
                return
            self.server.shutdown()

    class TCPHandler(SocketServer.BaseRequestHandler):
        def handle(self):
            context.ProbeCounter = (context.ProbeCounter + 1) % 1000000
            log = [NoLog, LogIfVerbose][ThrottleLog(context.ProbeCounter)]
            strCounter = str(context.ProbeCounter)
            log("load balancer probe " + strCounter)
            self.request.recv(1024)
            self.request.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/html\r\nDate: " + GetHttpDateTimeNow() + "\r\n\r\nOK")

    context = T(port)
    return context

class ConfigurationProvider(object):
    def __init__(self):
        self.values = dict()
        if os.path.isfile("/etc/waagent.conf") == False:
            return
        for line in GetFileContents("/etc/waagent.conf").split("\n"):
            if not line.startswith("#") and "=" in line:
                parts = line.split()[0].split('=')
                self.values[parts[0]] = parts[1].strip("\" ")

    def get(self, key):
        return self.values.get(key)

class UdevRulesWatcher(object):
    def __init__(self):
        self.shutdown = False
        self.server_thread = threading.Thread(target = self.watch_forever)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

    def watch_forever(self):
        while not self.shutdown:
            for a in RulesFiles:
                if os.path.isfile(a):
                    if os.path.isfile(GetLastPathElement(a)):
                        os.remove(GetLastPathElement(a))
                    shutil.move(a, ".")
                    Log("UdevRulesWatcher: Moved " + a + " -> " + LibDir)
            time.sleep(5)

    def shutdown(self):
        self.shutdown = True
        self.server_thread.join()


class RoleProperties(Util):
    def __init__(self, Agent, ContainerId, RoleInstanceId, Thumbprint):
        self.Agent = Agent
        self.Endpoint = Agent.Endpoint
        self.ContainerId = ContainerId
        self.RoleInstanceId = RoleInstanceId
        self.Thumbprint = Thumbprint

    def post(self):
        roleProperties = ("<?xml version=\"1.0\" encoding=\"utf-8\"?><RoleProperties><Container>"
                        + "<ContainerId>" + self.ContainerId + "</ContainerId>"
                        + "<RoleInstances><RoleInstance>"
                        + "<Id>" + self.RoleInstanceId + "</Id>"
                        + "<Properties><Property name=\"CertificateThumbprint\" value=\"" + self.Thumbprint + "\" /></Properties>"
                        + "</RoleInstance></RoleInstances></Container></RoleProperties>")
        a = self.HttpPost("/machine?comp=roleProperties", roleProperties)
        Log("Posted Role Properties. CertificateThumbprint=" + self.Thumbprint)
        return a


class Certificates(object):
#
# <CertificateFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="certificates10.xsd">
#  <Version>2010-12-15</Version>
#  <Incarnation>2</Incarnation>
#  <Format>Pkcs7BlobWithPfxContents</Format>
#  <Data>MIILTAY...
#  </Data>
# </CertificateFile>
#
    def __init__(self):
        self.reinitialize()

    def reinitialize(self):
        self.Incarnation = None
        self.Role = None

    def Parse(self, xmlText):
        self.reinitialize()
        SetFileContents("Certificates.xml", xmlText)
        dom = xml.dom.minidom.parseString(xmlText)
        for a in [ "CertificateFile", "Version", "Incarnation",
                   "Format", "Data", ]:
            if not dom.getElementsByTagName(a):
                return Error("ERROR: missing " + a)
        node = dom.childNodes[0]
        if node.localName != "CertificateFile":
            return Error("root not CertificateFile")
        SetFileContents("Certificates.p7m",
            "MIME-Version: 1.0\n"
            + "Content-Disposition: attachment; filename=\"Certificates.p7m\"\n"
            + "Content-Type: application/x-pkcs7-mime; name=\"Certificates.p7m\"\n"
            + "Content-Transfer-Encoding: base64\n\n"
            + dom.getElementsByTagName("Data")[0].childNodes[0].data)
        Run("openssl cms -decrypt -in Certificates.p7m -inkey TransportPrivate.pem -recip TransportCert.pem | openssl pkcs12 -nodes -password pass: -out Certificates.pem")
        # There may be multiple certificates in this package. Split them.
        file = open("Certificates.pem")
        index = 1
        output = open(str(index) + ".pem", "w")
        prvDone = False
        for line in file.readlines():
            output.write(line)
            if line.startswith("-----END PRIVATE KEY-----"):
                output.close()
                index += 1
                output = open(str(index) + ".pem", "w")
            if line.startswith("-----END CERTIFICATE-----"):
                output.close()
                if prvDone == False:
                    prvDone = True
                    input = open(str(index) + ".pem")
                    output = open("1.pem", "a")
                    output.write(input.read())
                    input.close()
                    output.close()
                    os.remove(str(index) + ".pem")
                    index = 1
                index += 1
                if os.path.isfile(str(index) + ".pem"):
                    output = open(str(index) + ".pem", "a")
        index = 1
        filename = str(index) + ".pem"
        while os.path.isfile(filename):
            thumbprint = os.popen("openssl x509 -in " + filename + " -fingerprint -noout | cut -f 2 -d = | tr -d :").read()
            os.rename(filename, thumbprint + ".pem")
            index += 1
            filename = str(index) + ".pem"
        return self

class SharedConfig(object):
#
# <SharedConfig version="1.0.0.0" goalStateIncarnation="1">
#   <Deployment name="db00a7755a5e4e8a8fe4b19bc3b330c3" guid="{ce5a036f-5c93-40e7-8adf-2613631008ab}" incarnation="2">
#     <Service name="MyVMRoleService" guid="{00000000-0000-0000-0000-000000000000}" />
#     <ServiceInstance name="db00a7755a5e4e8a8fe4b19bc3b330c3.1" guid="{d113f4d7-9ead-4e73-b715-b724b5b7842c}" />
#   </Deployment>
#   <Incarnation number="1" instance="MachineRole_IN_0" guid="{a0faca35-52e5-4ec7-8fd1-63d2bc107d9b}" />
#   <Role guid="{73d95f1c-6472-e58e-7a1a-523554e11d46}" name="MachineRole" settleTimeSeconds="10" />
#   <LoadBalancerSettings timeoutSeconds="0" waitLoadBalancerProbeCount="8">
#     <Probes>
#       <Probe name="MachineRole" />
#       <Probe name="55B17C5E41A1E1E8FA991CF80FAC8E55" />
#       <Probe name="3EA4DBC19418F0A766A4C19D431FA45F" />
#     </Probes>
#   </LoadBalancerSettings>
#   <OutputEndpoints>
#     <Endpoint name="MachineRole:Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" type="SFS">
#       <Target instance="MachineRole_IN_0" endpoint="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" />
#     </Endpoint>
#   </OutputEndpoints>
#   <Instances>
#     <Instance id="MachineRole_IN_0" address="10.115.153.75">
#       <FaultDomains randomId="0" updateId="0" updateCount="0" />
#       <InputEndpoints>
#         <Endpoint name="a" address="10.115.153.75:80" protocol="http" isPublic="true" loadBalancedPublicAddress="70.37.106.197:80" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
#           <LocalPorts>
#             <LocalPortRange from="80" to="80" />
#           </LocalPorts>
#         </Endpoint>
#         <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp" address="10.115.153.75:3389" protocol="tcp" isPublic="false" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
#           <LocalPorts>
#             <LocalPortRange from="3389" to="3389" />
#           </LocalPorts>
#         </Endpoint>
#         <Endpoint name="Microsoft.WindowsAzure.Plugins.RemoteForwarder.RdpInput" address="10.115.153.75:20000" protocol="tcp" isPublic="true" loadBalancedPublicAddress="70.37.106.197:3389" enableDirectServerReturn="false" isDirectAddress="false" disableStealthMode="false">
#           <LocalPorts>
#             <LocalPortRange from="20000" to="20000" />
#           </LocalPorts>
#         </Endpoint>
#       </InputEndpoints>
#     </Instance>
#   </Instances>
# </SharedConfig>
#
    def __init__(self):
        self.reinitialize()

    def reinitialize(self):
        self.Deployment = None
        self.Incarnation = None
        self.Role = None
        self.LoadBalancerSettings = None
        self.OutputEndpoints = None
        self.Instances = None

    def Parse(self, xmlText):
        self.reinitialize()
        SetFileContents("SharedConfig.xml", xmlText)
        dom = xml.dom.minidom.parseString(xmlText)
        for a in [ "SharedConfig", "Deployment", "Service",
                   "ServiceInstance", "Incarnation", "Role", ]:
            if not dom.getElementsByTagName(a):
                return Error("ERROR: missing " + a)
        node = dom.childNodes[0]
        if node.localName != "SharedConfig":
            return Error("root not SharedConfig")
        program = Config.get("Role.TopologyConsumer")
        if program != None and program != "None":
            os.spawnl(os.P_NOWAIT, program, program, LibDir + "/SharedConfig.xml")
        return self

class HostingEnvironmentConfig(object):
#
# <HostingEnvironmentConfig version="1.0.0.0" goalStateIncarnation="1">
#   <StoredCertificates>
#     <StoredCertificate name="Stored0Microsoft.WindowsAzure.Plugins.RemoteAccess.PasswordEncryption" certificateId="sha1:C093FA5CD3AAE057CB7C4E04532B2E16E07C26CA" storeName="My" configurationLevel="System" />
#   </StoredCertificates>
#   <Deployment name="db00a7755a5e4e8a8fe4b19bc3b330c3" guid="{ce5a036f-5c93-40e7-8adf-2613631008ab}" incarnation="2">
#     <Service name="MyVMRoleService" guid="{00000000-0000-0000-0000-000000000000}" />
#     <ServiceInstance name="db00a7755a5e4e8a8fe4b19bc3b330c3.1" guid="{d113f4d7-9ead-4e73-b715-b724b5b7842c}" />
#   </Deployment>
#   <Incarnation number="1" instance="MachineRole_IN_0" guid="{a0faca35-52e5-4ec7-8fd1-63d2bc107d9b}" />
#   <Role guid="{73d95f1c-6472-e58e-7a1a-523554e11d46}" name="MachineRole" hostingEnvironmentVersion="1" software="" softwareType="ApplicationPackage" entryPoint="" parameters="" settleTimeSeconds="10" />
#   <HostingEnvironmentSettings name="full" Runtime="rd_fabric_stable.110217-1402.RuntimePackage_1.0.0.8.zip">
#     <CAS mode="full" />
#     <PrivilegeLevel mode="max" />
#     <AdditionalProperties><CgiHandlers></CgiHandlers></AdditionalProperties>
#   </HostingEnvironmentSettings>
#   <ApplicationSettings>
#     <Setting name="__ModelData" value="&lt;m role=&quot;MachineRole&quot; xmlns=&quot;urn:azure:m:v1&quot;>&lt;r name=&quot;MachineRole&quot;>&lt;e name=&quot;a&quot; />&lt;e name=&quot;b&quot; />&lt;e name=&quot;Microsoft.WindowsAzure.Plugins.RemoteAccess.Rdp&quot; />&lt;e name=&quot;Microsoft.WindowsAzure.Plugins.RemoteForwarder.RdpInput&quot; />&lt;/r>&lt;/m>" />
#     <Setting name="Microsoft.WindowsAzure.Plugins.Diagnostics.ConnectionString" value="DefaultEndpointsProtocol=http;AccountName=osimages;AccountKey=DNZQ..." />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountEncryptedPassword" value="MIIBnQYJKoZIhvcN..." />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountExpiration" value="2022-07-23T23:59:59.0000000-07:00" />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountUsername" value="test" />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteAccess.Enabled" value="true" />
#     <Setting name="Microsoft.WindowsAzure.Plugins.RemoteForwarder.Enabled" value="true" />
#     <Setting name="Certificate|Microsoft.WindowsAzure.Plugins.RemoteAccess.PasswordEncryption" value="sha1:C093FA5CD3AAE057CB7C4E04532B2E16E07C26CA" />
#   </ApplicationSettings>
#   <ResourceReferences>
#     <Resource name="DiagnosticStore" type="directory" request="Microsoft.Cis.Fabric.Controller.Descriptions.ServiceDescription.Data.Policy" sticky="true" size="1" path="db00a7755a5e4e8a8fe4b19bc3b330c3.MachineRole.DiagnosticStore\" disableQuota="false" />
#   </ResourceReferences>
# </HostingEnvironmentConfig>
#
    def __init__(self):
        self.reinitialize()

    def reinitialize(self):
        self.StoredCertificates = None
        self.Deployment = None
        self.Incarnation = None
        self.Role = None
        self.HostingEnvironmentSettings = None
        self.ApplicationSettings = None
        self.Certificates = None
        self.ResourceReferences = None

    def Parse(self, xmlText):
        self.reinitialize()
        SetFileContents("HostingEnvironmentConfig.xml", xmlText)
        dom = xml.dom.minidom.parseString(xmlText)
        for a in [ "HostingEnvironmentConfig", "Deployment", "Service",
                   "ServiceInstance", "Incarnation", "Role", ]:
            if not dom.getElementsByTagName(a):
                return Error("ERROR: missing " + a)
        node = dom.childNodes[0]
        if node.localName != "HostingEnvironmentConfig":
            return Error("root not HostingEnvironmentConfig")
        self.ApplicationSettings = dom.getElementsByTagName("Setting")
        self.Certificates = dom.getElementsByTagName("StoredCertificate")
        return self

    def Process(self):
        ActivateResourceDisk()
        User = None
        Pass = None
        Expiration = None
        Thumbprint = None
        for b in self.ApplicationSettings:
            sname = b.getAttribute("name")
            svalue = b.getAttribute("value")
            if sname == "Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountEncryptedPassword":
                Pass = DecryptPassword(svalue)
            elif sname == "Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountUsername":
                User = svalue
            elif sname == "Microsoft.WindowsAzure.Plugins.RemoteAccess.AccountExpiration":
                Expiration = svalue
            elif sname == "Certificate|Microsoft.WindowsAzure.Plugins.RemoteAccess.PasswordEncryption":
                Thumbprint = svalue.split(':')[1].upper()
        if User != None and User != "root":
            CreateAccount(User, Pass, Expiration, Thumbprint)
        for c in self.Certificates:
            cname = c.getAttribute("name")
            csha1 = c.getAttribute("certificateId").split(':')[1].upper()
            cpath = c.getAttribute("storeName")
            clevel = c.getAttribute("configurationLevel")
            if not os.path.isfile(csha1 + ".pem"):
                Log("Certificate with thumbprint: " + csha1 + " was not retrieved.")
        program = Config.get("Role.ConfigurationConsumer")
        if program != None and program != "None":
            os.spawnl(os.P_NOWAIT, program, program, LibDir + "/HostingEnvironmentConfig.xml")

class GoalState(Util):
#
# <GoalState xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="goalstate10.xsd">
#   <Version>2010-12-15</Version>
#   <Incarnation>1</Incarnation>
#   <Machine>
#     <ExpectedState>Started</ExpectedState>
#     <LBProbePorts>
#       <Port>16001</Port>
#     </LBProbePorts>
#   </Machine>
#   <Container>
#     <ContainerId>c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2</ContainerId>
#     <RoleInstanceList>
#       <RoleInstance>
#         <InstanceId>MachineRole_IN_0</InstanceId>
#         <State>Started</State>
#         <Configuration>
#           <HostingEnvironmentConfig>http://10.115.153.40:80/machine/c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2/MachineRole%5FIN%5F0?comp=config&amp;type=hostingEnvironmentConfig&amp;incarnation=1</HostingEnvironmentConfig>
#           <SharedConfig>http://10.115.153.40:80/machine/c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2/MachineRole%5FIN%5F0?comp=config&amp;type=sharedConfig&amp;incarnation=1</SharedConfig>
#           <Certificates>http://10.115.153.40:80/machine/c6d5526c-5ac2-4200-b6e2-56f2b70c5ab2/MachineRole%5FIN%5F0?comp=certificates&amp;incarnation=1</Certificates>
#         </Configuration>
#       </RoleInstance>
#     </RoleInstanceList>
#   </Container>
# </GoalState>
#
# There is only one Role for VM images.
#
# Of primary interest is:
#  Machine/ExpectedState -- this is how shutdown is requested
#  LBProbePorts -- an http server needs to run here
#  We also note Container/ContainerID and RoleInstance/InstanceId to form the health report.
#  And of course, Incarnation
#
    def __init__(self, Agent):
        self.Agent = Agent
        self.Endpoint = Agent.Endpoint
        self.TransportCert = Agent.TransportCert
        self.reinitialize()

    def reinitialize(self):
        self.Incarnation = None # integer
        self.ExpectedState = None # "Started" or "Stopped"
        self.HostingEnvironmentConfigUrl = None
        self.HostingEnvironmentConfigXml = None
        self.HostingEnvironmentConfig = None
        self.SharedConfigUrl = None
        self.SharedConfigXml = None
        self.SharedConfig = None
        self.CertificatesUrl = None
        self.CertificatesXml = None
        self.Certificates = None
        self.RoleInstanceId = None
        self.ContainerId = None
        self.LoadBalancerProbePort = None # integer, ?list of integers
        self.RoleProperties = None

    def Parse(self, xmlText):
        self.reinitialize()
        node = xml.dom.minidom.parseString(xmlText).childNodes[0]
        if node.localName != "GoalState":
            return Error("root not GoalState")
        for a in node.childNodes:
            if a.nodeType == node.ELEMENT_NODE:
                if a.localName == "Incarnation":
                    for b in a.childNodes:
                        self.Incarnation = b.data
                        Log("GoalState.Incarnation:" + self.Incarnation)
                elif a.localName == "Machine":
                    for b in a.childNodes:
                        if b.nodeType == node.ELEMENT_NODE:
                            if b.localName == "ExpectedState":
                                for c in b.childNodes:
                                    self.ExpectedState = c.data
                                    Log("GoalState.Machine.ExpectedState:" + self.ExpectedState)
                            elif b.localName == "LBProbePorts":
                                for c in b.childNodes:
                                    if c.nodeType == node.ELEMENT_NODE:
                                        if c.localName == "Port":
                                            for d in c.childNodes:
                                                self.LoadBalancerProbePort = int(d.data)
                                                Log("Machine.LBProbePorts.Port:" + str(self.LoadBalancerProbePort))
                elif a.localName == "Container":
                    for b in a.childNodes:
                        if b.nodeType == node.ELEMENT_NODE:
                            if b.localName == "ContainerId":
                                self.ContainerId = b.childNodes[0].data
                                Log("ContainerId:" + self.ContainerId)
                            elif b.localName == "RoleInstanceList":
                                for c in b.childNodes:
                                    if c.localName == "RoleInstance":
                                        for d in c.childNodes:
                                            if d.nodeType == node.ELEMENT_NODE:
                                                if d.localName == "InstanceId":
                                                    self.RoleInstanceId = d.childNodes[0].data
                                                    Log("RoleInstanceId:" + self.RoleInstanceId)
                                                elif d.localName == "State":
                                                    pass
                                                elif d.localName == "Configuration":
                                                    for e in d.childNodes:
                                                        if e.nodeType == node.ELEMENT_NODE:
                                                            if e.localName == "HostingEnvironmentConfig":
                                                                self.HostingEnvironmentConfigUrl = e.childNodes[0].data
                                                                LogIfVerbose("HostingEnvironmentConfigUrl:" + self.HostingEnvironmentConfigUrl)
                                                                self.HostingEnvironmentConfigXml = self.HttpGetWithHeaders(self.HostingEnvironmentConfigUrl)
                                                                self.HostingEnvironmentConfig = HostingEnvironmentConfig().Parse(self.HostingEnvironmentConfigXml)
                                                            elif e.localName == "SharedConfig":
                                                                self.SharedConfigUrl = e.childNodes[0].data
                                                                LogIfVerbose("SharedConfigUrl:" + self.SharedConfigUrl)
                                                                self.SharedConfigXml = self.HttpGetWithHeaders(self.SharedConfigUrl)
                                                                self.SharedConfig = SharedConfig().Parse(self.SharedConfigXml)
                                                            elif e.localName == "Certificates":
                                                                self.CertificatesUrl = e.childNodes[0].data
                                                                LogIfVerbose("CertificatesUrl:" + self.CertificatesUrl)
                                                                self.CertificatesXml = self.HttpSecureGetWithHeaders(self.CertificatesUrl, self.TransportCert)
                                                                self.Certificates = Certificates().Parse(self.CertificatesXml)
        if self.Incarnation == None:
            return Error("Incarnation missing")
        if self.ExpectedState == None:
            return Error("ExpectedState missing")
        if self.RoleInstanceId == None:
            return Error("RoleInstanceId missing")
        if self.ContainerId == None:
            return Error("ContainerId missing")
        SetFileContents("GoalState." + self.Incarnation + ".xml", xmlText)
        return self

    def Process(self):
        self.HostingEnvironmentConfig.Process()

def Unpack(buffer, offset, range):
    result = 0
    for i in range:
        result = (result << 8) | Ord(buffer[offset + i])
    return result

def UnpackLittleEndian(buffer, offset, length):
    return Unpack(buffer, offset, range(length - 1, -1, -1))

def UnpackBigEndian(buffer, offset, length):
    return Unpack(buffer, offset, range(0, length))

def BuildDhcpRequest():
#
# typedef struct _DHCP {
#     UINT8   Opcode;                     /* op:     BOOTREQUEST or BOOTREPLY */
#     UINT8   HardwareAddressType;        /* htype:  ethernet */
#     UINT8   HardwareAddressLength;      /* hlen:   6 (48 bit mac address) */
#     UINT8   Hops;                       /* hops:   0 */
#     UINT8   TransactionID[4];           /* xid:    random */
#     UINT8   Seconds[2];                 /* secs:   0 */
#     UINT8   Flags[2];                   /* flags:  0 or 0x8000 for broadcast */
#     UINT8   ClientIpAddress[4];         /* ciaddr: 0 */
#     UINT8   YourIpAddress[4];           /* yiaddr: 0 */
#     UINT8   ServerIpAddress[4];         /* siaddr: 0 */
#     UINT8   RelayAgentIpAddress[4];     /* giaddr: 0 */
#     UINT8   ClientHardwareAddress[16];  /* chaddr: 6 byte ethernet MAC address */
#     UINT8   ServerName[64];             /* sname:  0 */
#     UINT8   BootFileName[128];          /* file:   0  */
#     UINT8   MagicCookie[4];             /*   99  130   83   99 */
#                                         /* 0x63 0x82 0x53 0x63 */
#     /* options -- hard code ours */
#
#     UINT8 MessageTypeCode;              /* 53 */
#     UINT8 MessageTypeLength;            /* 1 */
#     UINT8 MessageType;                  /* 1 for DISCOVER */
#     UINT8 End;                          /* 255 */
# } DHCP;
#

    LogIfVerbose("BuildDhcpRequest")

    # tuple of 244 zeros
    # (struct.pack_into would be good here, but requires Python 2.5)
    sendData = [0] * 244

    transactionID = os.urandom(4)
    macAddress = GetMacAddress()

    # Opcode = 1
    # HardwareAddressType = 1 (ethernet/MAC)
    # HardwareAddressLength = 6 (ethernet/MAC/48 bits)
    for a in range(0, 3):
        sendData[a] = [1, 1, 6][a]

    # fill in transaction id (random number to ensure response matches request)
    for a in range(0, 4):
        sendData[4 + a] = Ord(transactionID[a])

    # fill in ClientHardwareAddress
    for a in range(0, 6):
        sendData[0x1C + a] = Ord(macAddress[a])

    LogIfVerbose("BuildDhcpRequest:transactionId:%s,%04X" % (HexDump2(transactionID), UnpackBigEndian(sendData, 4, 4)))
    LogIfVerbose("BuildDhcpRequest:ClientHardwareAddress:%s,%012X" % (HexDump2(macAddress), UnpackBigEndian(sendData, 0x1C, 6)))

    # DHCP Magic Cookie: 99, 130, 83, 99
    # MessageTypeCode = 53 DHCP Message Type
    # MessageTypeLength = 1
    # MessageType = DHCPDISCOVER
    # End = 255 DHCP_END
    for a in range(0, 8):
        sendData[0xEC + a] = [99, 130, 83, 99, 53, 1, 1, 255][a]
    return array.array("c", map(chr, sendData))

def HandleDhcpResponse(sendData, receiveBuffer):

    LogIfVerbose("HandleDhcpResponse")
    bytesReceived = len(receiveBuffer)
    if bytesReceived < 0xF6:
        Error("too few bytes received " + str(bytesReceived))
        return False

    LogIfVerbose("bytesReceived: " + hex(bytesReceived))
    LogWithPrefixIfVerbose("DHCP response:", HexDump(receiveBuffer, bytesReceived))

    # check transactionId, cookie, MAC address
    # cookie should never mismatch
    # transactionId and MAC address I believe can mismatch -- we got the response meant from another machine

    LogIfVerbose("    sent cookie(0xEC:4):" + HexDump3(sendData, 0xEC, 4))
    LogIfVerbose("received cookie(0xEC:4):" + HexDump3(receiveBuffer, 0xEC, 4))
    LogIfVerbose("    sent transactionID(4:4):" + HexDump3(sendData, 4, 4))
    LogIfVerbose("received transactionID(4:4):" + HexDump3(receiveBuffer, 4, 4))
    LogIfVerbose("    sent ClientHardwareAddress(0x1C:6):" + HexDump3(sendData, 0x1C, 6))
    LogIfVerbose("received ClientHardwareAddress(0x1C:6):" + HexDump3(receiveBuffer, 0x1C, 6))

    LogIfVerbose("checking transactionId, cookie, MAC address")
    for offsets in [range(4, 4 + 4), range(0x1C, 0x1C + 6), range(0xEC, 0xEC + 4)]:
        for offset in offsets:
            sentByte = Ord(sendData[offset])
            receivedByte = Ord(receiveBuffer[offset])
            if sentByte != receivedByte:
                Error("HandleDhcpResponse:    sentByte[0x%02X]:0x%02X" % (offset, sentByte))
                Error("HandleDhcpResponse:recievedByte[0x%02X]:0x%02X" % (offset, receivedByte))
                Error("HandleDhcpResponse:    sent cookie:" + HexDump3(sendData, 0xEC, 4))
                Error("HandleDhcpResponse:received cookie:" + HexDump3(receiveBuffer, 0xEC, 4))
                Error("HandleDhcpResponse:    sent transactionID:" + HexDump3(sendData, 4, 4))
                Error("HandleDhcpResponse:received transactionID:" + HexDump3(receiveBuffer, 4, 4))
                Error("HandleDhcpResponse:    sent ClientHardwareAddress:" + HexDump3(sendData, 0x1C, 6))
                Error("HandleDhcpResponse:received ClientHardwareAddress:" + HexDump3(receiveBuffer, 0x1C, 6))
                Error("HandleDhcpResponse:transactionId, cookie, or MAC address mismatch")
                return False
    endpoint = None

    #
    # Walk all the returned options, parsing out what we need, ignoring the others.
    # We need the custom option 245 to find the the endpoint we talk to,
    # as well as, to handle some Linux DHCP client incompatibilities,
    # options 3 for default gateway and 249 for routes. And 255 is end.
    #

    i = 0xF0 # offset to first option
    while i < bytesReceived:
        option = Ord(receiveBuffer[i])
        length = 0
        if (i + 1) < bytesReceived:
            length = Ord(receiveBuffer[i + 1])
        LogIfVerbose("DHCP option " + hex(option) + " at offset:" + hex(i) + " with length:" + hex(length))
        if option == 255:
            LogIfVerbose("DHCP packet ended at offset " + hex(i))
            break
        elif option == 249:
            # http://msdn.microsoft.com/en-us/library/cc227282%28PROT.10%29.aspx
            LogIfVerbose("routes at offset:" + hex(i) + " with length:" + hex(length))
            if length < 5:
                Error("routes too small")
                return False # or hope the DHCP client worked?
            j = i + 2
            while j < (i + length + 2):
                maskLengthBits = Ord(receiveBuffer[j])
                maskLengthBytes = (((maskLengthBits + 7) & ~7) >> 3)
                mask = 0xFFFFFFFF & (0xFFFFFFFF << (32 - maskLengthBits))
                j += 1
                net = UnpackBigEndian(receiveBuffer, j, maskLengthBytes)
                net <<= (32 - maskLengthBytes * 8)
                net &= mask
                j += maskLengthBytes
                gateway = UnpackBigEndian(receiveBuffer, j, 4)
                j += 4
                Network_Route_Add(net, mask, gateway)
            if j != (i + length + 2):
                Error("trouble parsing routes")
                return False # or hope the DHCP client worked?

        elif option == 3 or option == 245:
            if i + 5 < bytesReceived:
                if length != 4:
                    Error("endpoint or defaultGateway not 4 bytes")
                    return False # or hope the DHCP client worked? (for option 3)
                IpAddress = "%u.%u.%u.%u" % (Ord(receiveBuffer[i + 2]), Ord(receiveBuffer[i + 3]), Ord(receiveBuffer[i + 4]), Ord(receiveBuffer[i + 5]))
                if option == 3:
                    Network_Route_SetDefaultGateway(IpAddress)
                    name = "defaultGateway"
                else:
                    endpoint = IpAddress
                    name = "endpoint"
                LogIfVerbose(name + ": " + IpAddress + " at " + hex(i))
            else:
                Error(name + " data too small")
                return False # or hope the DHCP client worked? (for option 3)
        else:
            LogIfVerbose("skipping DHCP option " + hex(option) + " at " + hex(i) + " with length " + hex(length))
        i += length + 2
    return endpoint

def DoDhcpWork():
    #
    # Discover the wire server via DHCP option 245.
    # And default gateway via option 3, for Linux, to workaround incompatibility with fabric DHCP configuration,
    # and handle Microsoft extension option 249.
    #

    if not IsWindows():
        Run("iptables -D INPUT -p udp --dport 68 -j ACCEPT")
        Run("iptables -I INPUT -p udp --dport 68 -j ACCEPT")

    sleepDurations = [0, 5, 10, 30, 60, 60, 60, 60]
    maxRetry = len(sleepDurations)
    lastTry = (maxRetry - 1)
    for retry in range(0, maxRetry):
        try:
            strRetry = str(retry)
            prefix = "DoDhcpWork,try=" + strRetry
            LogIfVerbose(prefix)
            sendData = BuildDhcpRequest()
            LogWithPrefixIfVerbose("DHCP request:", HexDump(sendData, len(sendData)))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((GetIpv4Address(), 68))
            bytesSent = sock.sendto(sendData, ("<broadcast>", 67))
            receiveBuffer = sock.recv(1024)
            endpoint = HandleDhcpResponse(sendData, receiveBuffer)
            if not endpoint:
                LogIfVerbose("No endpoint found")
            if endpoint or retry == lastTry:
                if endpoint:
                    Global.SendData = sendData
                    Global.DhcpResponse = receiveBuffer
                if retry == lastTry:
                    LogIfVerbose("DoDhcpWork,try=" + strRetry + ",=>lastTry")
                return endpoint
            productionSleepDuration = sleepDurations[retry % len(sleepDurations)]
            sleepDuration = [productionSleepDuration, retry, 1][Global.ShortSleep % 3]
            LogIfVerbose("DoDhcpWork,sleep=" + str(sleepDuration))
            time.sleep(sleepDuration)
        except Exception, e:
            ErrorWithPrefix(prefix, str(e))
            ErrorWithPrefix(prefix, traceback.format_exc())
    return False

def UpdateAndPublishHostNameCommon(name):

    replaceFiles = dict()
    setFiles = dict()

    # RedHat
    if IsRedHat():
        filepath = "/etc/sysconfig/network"
        if os.path.isfile(filepath):
            replaceFiles[filepath] = (
                "HOSTNAME=" + name + "\n"
                + "\n".join(filter(lambda a: not a.startswith("HOSTNAME"), GetFileContents(filepath).split("\n"))))

        for ethernetInterface in PossibleEthernetInterfaces:
            filepath = "/etc/sysconfig/network-scripts/ifcfg-" + ethernetInterface
            if os.path.isfile(filepath):
                replaceFiles[filepath] = (
                    "DHCP_HOSTNAME=" + name + "\n"
                    + "\n".join(filter(lambda a: not a.startswith("DHCP_HOSTNAME"), GetFileContents(filepath).split("\n"))))

    # Ubuntu
    if IsUbuntu():
        setFiles[Ubuntu.HostnameFile] = name

    # Suse
    if IsSuse():
        setFiles[Suse.HostnameFile] = name

    for filepath in EtcDhcpClientConfFiles:
        if os.path.isfile(filepath):
            replaceFiles[filepath] = (
                "send host-name \"" + name + "\";\n"
                + "\n".join(filter(lambda a: not a.startswith("send host-name"), GetFileContents(filepath).split("\n"))))

    for path, contents in replaceFiles.iteritems():
        ReplaceFileContentsAtomic(path, contents)

    for path, contents in setFiles.iteritems():
        SetFileContents(path, contents)

def UpdateAndPublishHostName(name):
    # Set hostname locally and publish to iDNS

    Run("hostname " + name)

    UpdateAndPublishHostNameCommon(name)

    for ethernetInterface in PossibleEthernetInterfaces:
        Run("ifdown " + ethernetInterface + " && ifup " + ethernetInterface)
    if Global.SendData != None and Global.DhcpResponse != None:
        HandleDhcpResponse(Global.SendData, Global.DhcpResponse)

    # Important: We do not restore routes if the in-box DHCP client wipes out routes again.
    # Leases in Azure don't require renewal and don't expire. Nothing will break
    # as long as the DHCP client is not restarted. This will be fixed when Azure DHCP servers
    # implement option 121 for classless static routes and include the default route in the
    # option to conform with RFC 3442.

class OvfEnv(object):
#
# OLD:
# <?xml version="1.0" encoding="utf-8"?>
# <Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" xmlns:rdfe="http://schemas.microsoft.com/2009/05/WindowsAzure/ServiceManagement" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
#   <rdfe:ProvisioningSection>
#     <OSDParameters xmlns="http://schemas.microsoft.com/2009/05/WindowsAzure/ServiceManagement" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
#         <ComputerName>LinuxAgent</ComputerName>
#         <AdministratorPassword>something</AdministratorPassword>
#     </OSDParameters>
#   </rdfe:ProvisioningSection>
# </Environment>
#
# NEW:
# <?xml version="1.0" encoding="utf-8"?>
# <Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1" xmlns:wa="http://schemas.microsoft.com/windowsazure" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
#    <wa:ProvisioningSection>
#      <LinuxProvisioningConfigurationSet xmlns="http://schemas.microsoft.com/windowsazure" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
#        <ConfigurationSetType>LinuxProvisioningConfiguration</ConfigurationSetType>
#        <HostName>MyMachine1</HostName>
#        <SSH>
#          <PublicKeys>
#            <PublicKey>
#              <Fingerprint>EB0C0AB4B2D5FC35F2F0658D19F44C8283E2DD62</Fingerprint>
#              <Path>/etc/ssh/guest</Path>
#            </PublicKey>
#          </PublicKeys>
#          <KeyPairs>
#            <KeyPair>
#              <Fingerprint>EB0C0AB4B2D5FC35F2F0658D19F44C8283E2DD62</Fingerprint>
#              <Path>/etc/ssh/root</Path>
#            </KeyPair>
#          </KeyPairs>
#        </SSH>
#      </LinuxProvisioningConfigurationSet>
#    </wa:ProvisioningSection>
# </Environment>
#
    def __init__(self):
        self.reinitialize()

    def reinitialize(self):
        self.Version = None
        self.ComputerName = None
        self.AdminPassword = None
        self.UserName = None
        self.UserPassword = None
        self.DisableSshPasswordAuthentication = False
        self.SshPublicKeys = []
        self.SshKeyPairs = []

    def Parse(self, xmlText):
        self.reinitialize()
        dom = xml.dom.minidom.parseString(xmlText)
        node = dom.childNodes[0]
        if node.localName != "Environment":
            return Error("root not Environment")
        if node.childNodes[1].nodeName == "rdfe:ProvisioningSection":
            self.ComputerName = dom.getElementsByTagName("ComputerName")[0].childNodes[0].data
            self.AdminPassword = dom.getElementsByTagName("AdministratorPassword")[0].childNodes[0].data
        else:
            self.Version = dom.getElementsByTagName("Version")[0].childNodes[0].data
            self.ComputerName = dom.getElementsByTagName("HostName")[0].childNodes[0].data
            self.UserName = dom.getElementsByTagName("UserName")[0].childNodes[0].data
            self.UserPassword = dom.getElementsByTagName("UserPassword")[0].childNodes[0].data
            self.DisableSshPasswordAuthentication = (dom.getElementsByTagName("DisableSshPasswordAuthentication")[0].childNodes[0].data.lower() == "true")
            for pkey in dom.getElementsByTagName("PublicKey"):
                fp = None
                path = None
                for c in pkey.childNodes:
                    if (c.nodeName == "Fingerprint"): fp = c.childNodes[0].data
                    if (c.nodeName == "Path"): path = c.childNodes[0].data
                self.SshPublicKeys += [[fp, path]]
            for keyp in dom.getElementsByTagName("KeyPair"):
                fp = None
                path = None
                for c in keyp.childNodes:
                    if (c.nodeName == "Fingerprint"): fp = c.childNodes[0].data
                    if (c.nodeName == "Path"): path = c.childNodes[0].data
                self.SshKeyPairs += [[fp, path]]
        return self

    def Process(self):
        Log("Computer Name = " + self.ComputerName)
        UpdateAndPublishHostName(self.ComputerName)
        if self.DisableSshPasswordAuthentication:
            filepath = "/etc/ssh/sshd_config"
            ReplaceFileContentsAtomic(filepath,
                "\n".join(filter(lambda a: not a.startswith("PasswordAuthentication"), GetFileContents(filepath).split("\n")))
                + "PasswordAuthentication no\n")
            Log("SSH PasswordAuthentication has been disabled.")
        if self.AdminPassword != None:
            os.popen("passwd --stdin root", "w").write(self.AdminPassword + "\n")
        if self.UserName != None:
            CreateAccount(self.UserName, self.UserPassword, None, None)
        for pkey in self.SshPublicKeys:
            Run("ssh-keygen -y -f " + pkey[0] + ".pem > " + pkey[1])
        for keyp in self.SshKeyPairs:
            Run("mkdir -p " + pkey[1].rsplit('/', 1)[0])
            Run("cp -f " + pkey[0] + ".pem " + pkey[1])
            Run("chmod 600 " + pkey[1])
            Run("ssh-keygen -y -f " + pkey[0] + ".pem > " + pkey[1] + ".pub")
        ReloadSshd()

class Agent(Util):
    def __init__(self):
        self.GoalState = None
        self.Endpoint = None
        self.LoadBalancerProbeServer = None
        self.HealthReportCounter = 0
        self.TransportCert = ""

    def CheckVersions(self):
        global ProtocolVersion
        protocolVersionSeen = False
#<?xml version="1.0" encoding="utf-8"?>
#<Versions>
#  <Preferred>
#    <Version>2010-12-15</Version>
#  </Preferred>
#  <Supported>
#    <Version>2010-12-15</Version>
#    <Version>2010-28-10</Version>
#  </Supported>
#</Versions>
        node = xml.dom.minidom.parseString(self.HttpGetWithoutHeaders("/?comp=versions")).childNodes[0]
        if node.localName != "Versions":
            return Error("root not Versions")
        for a in node.childNodes:
            if a.nodeType == node.ELEMENT_NODE:
                if a.localName == "Supported":
                    for b in a.childNodes:
                        if b.nodeType == node.ELEMENT_NODE:
                            if b.localName == "Version":
                                for c in b.childNodes:
                                    LogIfVerbose("hostSupportedVersion:" + c.data)
                                    if c.data == ProtocolVersion:
                                        protocolVersionSeen = True
        if not protocolVersionSeen:
             ProtocolVersion = "2011-08-31"
#            return Error("5")
        Log("Negotiated wire protocol version: " + ProtocolVersion)
        return True

    def UpdateGoalState(self):
        #
        # Error 410 "gone" and possibly 403 "forbidden" are common here.
        #
        goalStateXml = None
        maxRetry = 9
        log = NoLog
        for retry in range(1, maxRetry + 1):
            strRetry = str(retry)
            try:
                log("retry UpdateGoalState,retry=" + strRetry)
                goalStateXml = self.HttpGetWithHeaders("/machine/?comp=goalstate")
                break
            except Exception, e:
                log = Log
                if retry < maxRetry:
                    Log("report error and sleep(retry) UpdateGoalState,retry=" + strRetry)
                    Log(e)
                    Log(traceback.format_exc())
                    time.sleep(retry)
                    pass
                else:
                    Log("raise UpdateGoalState,retry=" + strRetry)
                    raise
        if not goalStateXml:
            Error("UpdateGoalState failed")
            return
        log("parse UpdateGoalState")
        self.GoalState = GoalState(self).Parse(goalStateXml)
        log("return UpdateGoalState")
        return self.GoalState

    def ReportHealth(self):
        counter = (self.HealthReportCounter + 1) % 1000000
        self.HealthReportCounter = counter
        healthReport = ("<?xml version=\"1.0\" encoding=\"utf-8\"?><Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GoalStateIncarnation>"
                        + self.GoalState.Incarnation 
                        + "</GoalStateIncarnation><Container><ContainerId>"
                        + self.GoalState.ContainerId
                        + "</ContainerId><RoleInstanceList><Role><InstanceId>"
                        + self.GoalState.RoleInstanceId
                        + "</InstanceId><Health><State>Ready</State></Health></Role></RoleInstanceList></Container></Health>")
        a = self.HttpPost("/machine?comp=health", healthReport)
        b = a.getheader("x-ms-latest-goal-state-incarnation-number")
        return b

    def ReportProvisioning(self):
        healthReport = ("<?xml version=\"1.0\" encoding=\"utf-8\"?><Health xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><GoalStateIncarnation>"
                        + self.GoalState.Incarnation 
                        + "</GoalStateIncarnation><Container><ContainerId>"
                        + self.GoalState.ContainerId
                        + "</ContainerId><RoleInstanceList><Role><InstanceId>"
                        + self.GoalState.RoleInstanceId
                        + "</InstanceId><Health><State>NotReady</State>"
                        + "<Details><SubStatus>Provisioning</SubStatus><Description>Starting</Description></Details>"
                        + "</Health></Role></RoleInstanceList></Container></Health>")
        return self.HttpPost("/machine?comp=health", healthReport)

    def LoadBalancerProbeServer_Shutdown(self):
        if self.LoadBalancerProbeServer != None:
            self.LoadBalancerProbeServer.shutdown()
            self.LoadBalancerProbeServer = None

    def Run(self):
        if (GetIpv4Address() == None):
            Log("Waiting for network.")
            while(GetIpv4Address() == None):
                time.sleep(10)

        Log("IPv4 address: " + GetIpv4Address())
        Log("MAC  address: " + str(":".join(["%02X" % Ord(a) for a in GetMacAddress()])))

        self.UdevRulesWatcher = UdevRulesWatcher()

        Log("Probing for Windows Azure environment.")
        self.Endpoint = DoDhcpWork()

        if not self.Endpoint:
            Log("Windows Azure environment not detected.")
            while True:
                time.sleep(60)

        Log("Discovered Windows Azure endpoint: " + self.Endpoint)
        if not self.CheckVersions():
            Error("Agent.CheckVersions failed")
            sys.exit(1)

        self.TransportCert = GenerateTransportCert()

        incarnation = None # goalStateIncarnationFromHealthReport
        currentPort = None # loadBalancerProbePort
        goalState = None # self.GoalState, instance of GoalState
        provisioned = os.path.exists(LibDir + "/provisioned")
        while True:
            if (goalState == None) or (incarnation == None) or (goalState.Incarnation != incarnation):
                goalState = self.UpdateGoalState()

                if provisioned == False:
                    self.ReportProvisioning()

                goalState.Process()

                if provisioned == False:
                    SshHostKeyThumbprint = Provision()
                    if SshHostKeyThumbprint != None:
                        self.RoleProperties = RoleProperties(self, goalState.ContainerId, goalState.RoleInstanceId, SshHostKeyThumbprint)
                        self.RoleProperties.post()
                    program = Config.get("Role.StateConsumer")
                    if program != None and program != "None":
                        os.spawnl(os.P_NOWAIT, program, program, "Ready")
                    provisioned = True

                #
                # only one port supported
                # restart server if new port is different than old port
                # stop server if no longer a port
                #
                goalPort = goalState.LoadBalancerProbePort
                if currentPort != goalPort:
                    self.LoadBalancerProbeServer_Shutdown()
                    currentPort = goalPort
                    if currentPort != None:
                        self.LoadBalancerProbeServer = LoadBalancerProbeServer(currentPort)
            if goalState.ExpectedState == "Stopped":
                program = Config.get("Role.StateConsumer")
                if program != None and program != "None":
                    Run(program + " Shutdown")
                command = ["/sbin/shutdown -hP now", "shutdown /s /t 5"][IsWindows()]
                self.LoadBalancerProbeServer_Shutdown()
                Run(command)
                return

            sleepToReduceAccessDenied = 3
            time.sleep(sleepToReduceAccessDenied)
            incarnation = self.ReportHealth()
            time.sleep(30 - sleepToReduceAccessDenied)

Init_Suse = """\
#! /bin/sh

### BEGIN INIT INFO
# Provides: WindowsAzureGuestAgent
# Required-Start: $network sshd
# Required-Stop: $network sshd
# Default-Start: 3 5
# Default-Stop: 0 1 2 6
# Description: Start the WindowsAzureGuestAgent
### END INIT INFO

WAZD_BIN=/usr/sbin/waagent
test -x $WAZD_BIN || exit 5

WAZD_PIDFILE=/var/run/waagent.init.pid

. /etc/rc.status

# First reset status of this service
rc_reset

case "$1" in
    start)
        echo -n "Starting WindowsAzureGuestAgent"
        ## Start daemon with startproc(8). If this fails
        ## the echo return value is set appropriate.

        startproc -f -p $WAZD_PIDFILE $WAZD_BIN

        # Remember status and be verbose
        rc_status -v
        ;;
    stop)
        echo -n "Shutting down WindowsAzureGuestAgent"
        ## Stop daemon with killproc(8) and if this fails
        ## set echo the echo return value.

        killproc -p $WAZD_PIDFILE -TERM $WAZD_BIN

        # Remember status and be verbose
        rc_status -v
        ;;
    try-restart)
        ## Stop the service and if this succeeds (i.e. the 
        ## service was running before), start it again.
        $0 status >/dev/null &&  $0 restart

        # Remember status and be quiet
        rc_status
        ;;
    restart)
        ## Stop the service and regardless of whether it was
        ## running or not, start it again.
        $0 stop
        $0 start

        # Remember status and be quiet
        rc_status
        ;;
    force-reload|reload)
        ;;
    status)
        echo -n "Checking for service WindowsAzureGuestAgent "
        ## Check status with checkproc(8), if process is running
        ## checkproc will return with exit status 0.

        # Status has a slightly different for the status command:
        # 0 - service running
        # 1 - service dead, but /var/run/  pid  file exists
        # 2 - service dead, but /var/lock/ lock file exists
        # 3 - service not running

        checkproc -p $WAZD_PIDFILE $WAZD_BIN

        rc_status -v
        ;;
    probe)
        ;;
    *)
        echo "Usage: $0 {start|stop|status|try-restart|restart|force-reload|reload|probe}"
        exit 1
        ;;
esac
rc_exit
"""

Init_RedHat = """\
#!/bin/bash
#
# Init file for WindowsAzureGuestAgent.
#
# chkconfig: 2345 60 80
# description: WindowsAzureGuestAgent
#

# source function library
. /etc/rc.d/init.d/functions

RETVAL=0
FriendlyName="WindowsAzureGuestAgent"
WAZD_BIN=/usr/sbin/waagent

start()
{
    echo -n $"Starting $FriendlyName: "
    $WAZD_BIN &
}

stop()
{
    echo -n $"Stopping $FriendlyName: "
    killproc $WAZD_BIN
    RETVAL=$?
    echo
    return $RETVAL
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    reload)
        ;;
    report)
        ;;
    status)
        status $WAZD_BIN
        RETVAL=$?
        ;;
    *)
        echo $"Usage: $0 {start|stop|restart|status}"
        RETVAL=1
esac
exit $RETVAL
"""

Init_Ubuntu = """\
#!/bin/sh
### BEGIN INIT INFO
# Provides:          WindowsAzureGuestAgent
# Required-Start:    $network $syslog
# Required-Stop:     $network $syslog
# Should-Start:      $network $syslog
# Should-Stop:       $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: WindowsAzureGuestAgent
# Description:       WindowsAzureGuestAgent
### END INIT INFO

. /lib/lsb/init-functions

OPTIONS=""
WAZD_BIN=/usr/sbin/waagent

case "$1" in
    start)
        log_begin_msg "Starting WindowsAzureGuestAgent..."
        pid=$( pidofproc $WAZD_BIN )
        if [ -n "$pid" ] ; then
              log_begin_msg "Already running."
              log_end_msg 0
              exit 0
        fi
        start-stop-daemon --start --quiet --oknodo --background --exec $WAZD_BIN -- $OPTIONS
        log_end_msg $?
        ;;

    stop)
        log_begin_msg "Stopping WindowsAzureGuestAgent..."
        start-stop-daemon --stop --quiet --oknodo --exec $WAZD_BIN
        log_end_msg $?
        ;;
    force-reload)
        $0 restart
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    status)
        status_of_proc $WAZD_BIN && exit 0 || exit $?
        ;;
    *)
        log_success_msg "Usage: /etc/init.d/waagent {start|stop|force-reload|restart|status}"
        exit 1
        ;;
esac

exit 0
"""

WaagentConf = """\
#
# Windows Azure Guest Agent Configuration
#

Role.StateConsumer=None                 # Specified program is invoked with "Ready" or "Shutdown". 
                                        # Shutdown will be initiated only after the program returns. Windows Azure will 
                                        # power off the VM if shutdown is not completed within ?? minutes.
Role.ConfigurationConsumer=None         # Specified program is invoked with XML file argument specifying role configuration.
Role.TopologyConsumer=None              # Specified program is invoked with XML file argument specifying role topology.

Provisioning.Enabled=y                  #
Provisioning.DeleteRootPassword=n       # Password authentication for root account will be unavailable.
Provisioning.RegenerateSshHostKeyPair=y # If an RSA keypair is supplied in the ISO, that will be used instead.
Provisioning.SshHostKeyPairType=rsa     # Supported values are "rsa", "dsa" and "ecdsa".
Provisioning.RunPrograms=y              # Run additional code that may be present on the ISO.

ResourceDisk.Format=y                   # Format if unformatted. If 'n', resource disk will not be mounted.
ResourceDisk.Filesystem=ext4            #
ResourceDisk.MountPoint=/mnt/resource   #
ResourceDisk.EnableSwap=n               # Create and use swapfile on resource disk.
ResourceDisk.SwapSizeMB=0               # Size of the swapfile.

LBProbeResponder=y                      #

Logs.Verbose=n                          #
"""

WaagentLogrotate = """\
/var/log/waagent.log {
    monthly
    rotate 6
    notifempty
    missingok
}
"""

def AddToLinuxKernelCmdline(options):
    if os.path.isfile("/boot/grub/menu.lst"):
        Run("sed -i '/kernel/s|$| " + options + " |' /boot/grub/menu.lst")
    filepath = "/etc/default/grub"
    if os.path.isfile(filepath):
        filecontents = GetFileContents(filepath).split("\n")
        current = filter(lambda a: a.startswith("GRUB_CMDLINE_LINUX"), filecontents)
        ReplaceFileContentsAtomic(filepath,
            "\n".join(filter(lambda a: not a.startswith("GRUB_CMDLINE_LINUX"), filecontents))
            + current[0][:-1] + " " + options + "\"\n")
        Run("update-grub")


def ApplyVNUMAWorkaround():
    VersionParts = platform.release().replace("-", ".").split(".")
    if int(VersionParts[0]) > 2:
        return
    if int(VersionParts[1]) > 6:
        return
    if int(VersionParts[2]) > 37:
        return
    AddToLinuxKernelCmdline("numa=off")
    print("Your kernel version " + platform.release() + " has a NUMA-related bug: NUMA has been disabled.")

def RevertVNUMAWorkaround():
    print("Automatic reverting of GRUB configuration is not yet supported. Please edit by hand.")

def Install():
    if IsWindows():
        print("ERROR: -install invalid for windows, see waagent_service.exe")
        return 0
    Run("chmod +x " + sys.argv[0])
    SwitchCwd()
    requiredDeps = [ "/sbin/route", "/sbin/shutdown" ]
    if IsUbuntu() or IsSuse():
        requiredDeps += [ "/sbin/insserv" ]
    for a in requiredDeps:
        if not os.path.isfile(a):
            Error("missing required dependency: " + a)
            Error("Setup Failure")
            return 1
    missing = False
    for a in [ "ssh-keygen", "useradd", "openssl", "sfdisk",
               "fdisk", "mkfs", "passwd", "sed",
               "tr", "grep", "cut" ]:
        if Run("which " + a + " > /dev/null 2>&1"):
            Warn("missing dependency: " + a)
            missing = True
    if missing == True:
        print("WARNING! Please resolve missing dependencies listed for full functionality.")
    print("WARNING! Will overwrite /etc/waagent.conf.")
    print("WARNING! Will delete udev persistent networking rules.")
    if not raw_input('Do you want to proceed (y/n)? ').startswith('y'):
        return 0
    for a in RulesFiles:
        if os.path.isfile(a):
            if os.path.isfile(GetLastPathElement(a)):
                os.remove(GetLastPathElement(a))
            shutil.move(a, ".")
            Log("Installer: Moved " + a + " -> " + LibDir)
    filename = "waagent"
    filepath = "/etc/init.d/" + filename
    a = IsRedHat() + IsUbuntu() * 2 + IsSuse() * 3
    if a == 0:
        print("distribution not detected")
        return 1
    a = [[Init_RedHat, "chkconfig --add " + filename],
         [Init_Ubuntu, "insserv " + filename + " > /dev/null 2>&1"],
         [Init_Suse, "insserv " + filename]][a - 1]
    SetFileContents(filepath, a[0])
    Run("chmod +x " + filepath)
    Run(a[1])
    SetFileContents("/etc/waagent.conf", WaagentConf)
    SetFileContents("/etc/logrotate.d/waagent", WaagentLogrotate)
    ApplyVNUMAWorkaround()
    return 0

def Uninstall():
    if IsWindows():
        print("ERROR: -uninstall invalid for windows, see waagent_service.exe")
        return 0
    SwitchCwd()
    for a in RulesFiles:
        if os.path.isfile(GetLastPathElement(a)):
            try:
                shutil.move(GetLastPathElement(a), a)
            except:
                pass
    filename = "waagent"
    a = IsRedHat() + IsUbuntu() * 2 + IsSuse() * 3
    if a == 0:
        print("distribution not detected")
        return 1
    a = ["chkconfig --del " + filename,
         "insserv -r " + filename + " > /dev/null 2>&1",
         "insserv -r " + filename][a - 1]
    Run(a)
    os.remove("/etc/init.d/" + filename)
    os.remove("/etc/waagent.conf")
    os.remove("/etc/logrotate.d/waagent")
    RevertVNUMAWorkaround()
    return 0

def DeleteRootPassword():
    Run("touch /etc/shadow-temp")
    Run("chmod a-rwx /etc/shadow-temp")
    Run("(echo root:*LOCK*:14600:::::: && grep -v ^root /etc/shadow ) > /etc/shadow-temp")
    Run("mv -f /etc/shadow-temp /etc/shadow")
    Log("Root password deleted.")

def GeneralizeWindows():
    Run(os.environ["windir"] + "\\system32\\sysprep\\sysprep.exe /generalize")
    return 0

def GeneralizeLinux():
    print("WARNING! SSH host RSA and DSA keys will be deleted.")
    print("WARNING! Nameserver configuration in /etc/resolv.conf will be deleted.")
    print("WARNING! root password may be disabled. You will not be able to login as root.")
    print("WARNING! Cached DHCP leases will be deleted.")
    if not raw_input('Do you want to proceed (y/n)? ').startswith('y'):
        return 0

    # Clear Provisioned Flag
    os.remove(LibDir + "/provisioned")

    # Remove SSH host keys
    regenerateKeys = Config.get("Provisioning.RegenerateSshHostKeyPair")
    if regenerateKeys == None or regenerateKeys.lower().startswith("y"):
        Run("rm -f /etc/ssh/ssh_host_ecdsa_key*")
        Run("rm -f /etc/ssh/ssh_host_dsa_key*")
        Run("rm -f /etc/ssh/ssh_host_rsa_key*")
        Run("rm -f /etc/ssh/ssh_host_key*")

    # Remove nameserver
    os.remove("/etc/resolv.conf")

    # Remove root password
    delRootPass = Config.get("Provisioning.DeleteRootPassword")
    if delRootPass != None and delRootPass.lower().startswith("y"):
        DeleteRootPassword()

    # Remove distribution specific networking configuration

    UpdateAndPublishHostNameCommon("localhost.localdomain")

    # RedHat, Suse, Ubuntu
    for a in VarLibDhcpDirectories:
        Run("rm -f " + a + "/*")    

    if not (IsUbuntu() or IsRedHat() or IsSuse()):
        print("distribution not detected")
        return 1
    return 0

def Generalize():
    if IsWindows():
        GeneralizeWindows()
    else:
        GeneralizeLinux()

def SwitchCwd():
    if not IsWindows():
        try:
            os.mkdir(LibDir, 0700)
        except:
            pass
        os.chdir(LibDir)

def Usage():
    print("usage: " + sys.argv[0] + " [-verbose] [-help|-install|-uninstall|-generalize|-version|-serialconsole|-test-*]")
    sys.exit(0)

if GuestAgentVersion == "":
    print("WARNING! This is a non-standard agent that does not include a valid version string.")
if IsLinux() and not DetectLinuxDistro():
    print("WARNING! Unable to detect Linux distribution. Some functionality may be broken.")

Config = ConfigurationProvider()

verbose = Config.get("Logs.Verbose")
if verbose != None and verbose.lower().startswith("y"):
    Global.Verbose = True

if len(sys.argv) > 1:
    for a in sys.argv[1:]:
        if re.match("^([-/]*)(help|usage|\?)", a):
            Usage()
    for a in sys.argv[1:]:
        if re.match("^([-/]*)test$", a):
            for a in [ "IsWindows()",
                       "IsLinux()",
                       "IsSuse()",
                       "IsUbuntu()",
                       "IsRedHat()",
                     ]:
                sys.stdout.write(a + ":")
                print(str(eval(a)))
            sys.exit(0)
        if re.match("^([-/]*)(help|usage|\?)", a):
            pass
        elif re.match("^([-/]*)(setup|install)", a):
            sys.exit(Install())
        elif re.match("^([-/]*)(uninstall)", a):
            sys.exit(Uninstall())
        elif re.match("^([-/]*)generalize", a):
            sys.exit(Generalize())
        elif re.match("^([-/]*)verbose", a):
            Global.Verbose = True
        elif re.match("^([-/]*)version", a):
            print(GuestAgentVersion + " running on " + LinuxDistro)
            sys.exit(0)
        elif re.match("^([-/]*)serialconsole", a):
            AddToLinuxKernelCmdline("console=ttyS0 earlyprintk=ttyS0")
            Log("Configured kernel to use ttyS0 as the boot console.")
            sys.exit(0)
        else:
            print("invalid command line parameter:" + a)
            sys.exit(1)

try:
    SwitchCwd()
    Log("Windows Azure Linux Guest Agent version: " + GuestAgentVersion)
    if IsLinux():
        Log("Linux Distribution Detected            : " + LinuxDistro)
    Agent().Run()
except Exception, e:
    Error("exiting due to:" + str(e))
    Error(traceback.format_exc())
    sys.exit(1)
>>>>>>> 8c7767881eac51351f6bb2056921b0fb55d58c48
