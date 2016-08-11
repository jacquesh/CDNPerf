import subprocess
import socket
import sys
import re

if sys.platform == 'win32':
    dumptool = 'windump'
else:
    dumptool = 'tcpdump'

def getPrimaryNetworkDevice():
    deviceListLines = subprocess.Popen([dumptool, '-D'], stdout=subprocess.PIPE).stdout.readlines()
    deviceCount = len(deviceListLines)
    packetSniffProcList = []
    for deviceID in range(deviceCount):
        packetSniffProc = subprocess.Popen([dumptool, '-n', '-c 1', '-i %s' % str(deviceID+1), 'icmp'])
        packetSniffProcList.append(packetSniffProc)

    subprocess.Popen(['ping', 'www.google.com']).wait()
    validIDList = []
    for deviceID in range(deviceCount):
        if packetSniffProcList[deviceID].poll() is not None:
            validIDList.append(deviceID+1)
        else:
            packetSniffProcList[deviceID].kill()

    if len(validIDList) == 0:
        print('ERROR: No network devices detected the ICMP request')
        return -1
    elif len(validIDList) == 1:
        return validIDList[0]
    else:
        print('Multiple network devices detected the ICMP request, returning the first one')
        return validIDList[0]

def getLocalIP():
    ipconfigLines = subprocess.Popen(['ipconfig'], stdout=subprocess.PIPE).stdout.readlines()
    localIP = '(Unkown)'
    for line in ipconfigLines:
        lineStr = str(line.strip())
        if not lineStr.startswith('IPv4 Address'):
            continue
        localIP = lineStr[lineStr.find(':')+2:]
    return localIP

def getContentURL(targetURL):
    return str(subprocess.Popen(['youtube-dl', '-g', targetURL], stdout=subprocess.PIPE).stdout.read())

def getHostFromURL(targetURL):
    hostStartIndex = targetURL.find('//')
    if(hostStartIndex >= 0):
        hostStartIndex += 2
    else:
        hostStartIndex = 0
    hostEndIndex = targetURL.find('/', hostStartIndex)
    return targetURL[hostStartIndex:hostEndIndex]

def getIPFromHost(targetHost):
    return socket.gethostbyname(targetHost)

def getContentIP(targetURL, localIP, networkDeviceID):
    downloadProcess = subprocess.Popen(['youtube-dl', targetURL])
    """
    We're using WinDump, a Windows port of tcpdump (available at https://www.winpcap.org/windump/)
    -n stops it from resolving hostnames (which makes it much faster and we only want IPs anyways)
    -v makes the output more verbose
    -S prints absolute (rather than relative) tcp packet sequence numbers (Don't actually think we need this)
    -s specifies how much of the packet's contents to capture (defaults to something huge apparently)
    -i specifies which device to capture from (which, for me is 2...run windump -D to get a list)
    -c specifies how many packets to capture before stopping
    Specifying tcp just makes it filter out everything that isn't sent via TCP
    """
    dumpArgs = ['-nvS', '-s 128', '-i %d' % networkDeviceID, '-c 3000', 'tcp']
    dumpProcess = subprocess.Popen([dumptool] + dumpArgs, stdout=subprocess.PIPE)
    dumpOutput = dumpProcess.stdout.readlines()
    downloadProcess.kill()

    ipMap = {}
    ipRegex = re.compile(r'((\d+\.){3}\d+)\.\d+ > ((\d+\.){3}\d+)\.\d+')
    for line in dumpOutput:
        ipMatch = ipRegex.search(str(line))
        if not ipMatch:
            continue

        sourceIP = ipMatch.group(1)
        targetIP = ipMatch.group(3)
        if sourceIP == localIP:
            continue
        if sourceIP not in ipMap:
            ipMap[sourceIP] = 1
        else:
            ipMap[sourceIP] += 1

    maxIP = ''
    maxIPCount = 0
    for ip in ipMap:
        if ipMap[ip] > maxIPCount:
            maxIPCount = ipMap[ip]
            maxIP = ip
    if maxIPCount < len(dumpOutput)/2:
        return None
    else:
        return maxIP

def profileURL(targetURL, localIP, listenDeviceID):
    targetHost = getHostFromURL(targetURL)
    targetIP = getIPFromHost(targetHost)

    cdnURL = getContentURL(targetURL)
    cdnHost = getHostFromURL(cdnURL)
    cdnIP = getIPFromHost(cdnHost)

    contentIP = '...'
    contentIP = getContentIP(targetURL, localIP, listenDeviceID)
    print('%s (%s) refers to a CDN at %s (%s) and the actual content came from %s'
            % (targetHost, targetIP, cdnHost, cdnIP, contentIP))


def run(inputFilename):
    localIP = getLocalIP()
    listenDeviceID = getPrimaryNetworkDevice()
    inputFile = open(inputFilename, 'r')
    for url in inputFile:
        targetURL = url.strip()
        profileURL(targetURL, localIP, listenDeviceID)


# We can use https://www.reddit.com/r/unknownvideos/ as a source of probably-not-cached videos
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('No argument given, expected "findip.py <contentUrl>"')
    else:
        run(sys.argv[1])
