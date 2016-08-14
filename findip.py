import subprocess
import socket
import sys
import re
import requests
import psutil
import os
from time import sleep

# Set this to subprocess.DEVNULL for clean output, None for verbose output
verboseOutputTarget = subprocess.DEVNULL

if sys.platform == 'win32':
    dumptool = 'windump'
    traceTool = 'tracert'
else:
    dumptool = 'tcpdump'
    traceTool = 'traceroute'


def getPrimaryNetworkDevice():
    deviceListLines = subprocess.Popen([dumptool, '-D'], stdout=subprocess.PIPE, stderr=verboseOutputTarget).stdout.readlines()
    deviceCount = len(deviceListLines)
    packetSniffProcList = []
    for deviceID in range(deviceCount):
        packetSniffProc = subprocess.Popen([dumptool, '-n', '-c 1', '-i %s' % str(deviceID + 1), 'icmp'], stdout=verboseOutputTarget, stderr=subprocess.STDOUT)
        packetSniffProcList.append(packetSniffProc)

    subprocess.Popen(['ping', 'www.google.com'], stdout=verboseOutputTarget, stderr=subprocess.STDOUT).wait()
    validIDList = []
    for deviceID in range(deviceCount):
        if packetSniffProcList[deviceID].poll() is not None:
            validIDList.append(deviceID + 1)
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
    ipconfigLines = subprocess.Popen(['ipconfig'], stdout=subprocess.PIPE, stderr=verboseOutputTarget).stdout.readlines()
    localIP = '(Unknown)'
    for line in ipconfigLines:
        lineStr = str(line.strip())
        if not lineStr.startswith('IPv4 Address'):
            continue
        localIP = lineStr[lineStr.find(':') + 2:]
    return localIP


def getContentURL(targetURL):
    return str(subprocess.Popen(['youtube-dl', '-g', targetURL], stdout=subprocess.PIPE, stderr=verboseOutputTarget).stdout.read())


def getHostFromURL(targetURL):
    hostStartIndex = targetURL.find('//')
    if (hostStartIndex >= 0):
        hostStartIndex += 2
    else:
        hostStartIndex = 0
    hostEndIndex = targetURL.find('/', hostStartIndex)
    return targetURL[hostStartIndex:hostEndIndex]


def getIPFromHost(targetHost):
    return socket.gethostbyname(targetHost)


def getContentIP(targetURL, localIP, networkDeviceID):
    downloadProcess = subprocess.Popen(['youtube-dl', targetURL], stdout=verboseOutputTarget, stderr=subprocess.STDOUT)
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
    dumpProcess = subprocess.Popen([dumptool] + dumpArgs, stdout=subprocess.PIPE, stderr=verboseOutputTarget)
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
    if maxIPCount < len(dumpOutput) / 2:
        return None
    else:
        return maxIP


def profileURL(targetURL, localIP, listenDeviceID):
    targetHost = getHostFromURL(targetURL)
    targetIP = getIPFromHost(targetHost)

    cdnURL = getContentURL(targetURL)
    cdnHost = getHostFromURL(cdnURL)
    cdnIP = getIPFromHost(cdnHost)

    contentIP = getContentIP(targetURL, localIP, listenDeviceID)
    print('%s (%s) refers to a CDN at %s (%s) and the actual content came from %s'
          % (targetHost, targetIP, cdnHost, cdnIP, contentIP))

    targetIPWhoisDict = whoisIP(targetIP)
    targetIPLocation = (targetIPWhoisDict["region"] + " " + targetIPWhoisDict["country"]).strip()
    targetIPPing = pingIP(targetIP)
    targetIPRoute = traceRouteToIP(targetIP)
    print("Target IP ({0} - RTT:{3}ms - {4} hops) location is in {1} and managed by {2}".format(targetIP, targetIPLocation, targetIPWhoisDict["org"], targetIPPing, len(targetIPRoute)))

    cdnIPWhoisDict = whoisIP(cdnIP)
    cdnIPLocation = (cdnIPWhoisDict["region"] + " " + cdnIPWhoisDict["country"]).strip()
    cdnIPPing = pingIP(cdnIP)
    cdnIPRoute = traceRouteToIP(cdnIP)
    print("CDN IP ({0} - RTT:{3}ms - {4} hops) location is in {1} and managed by {2}".format(cdnIP, cdnIPLocation, cdnIPWhoisDict["org"], cdnIPPing, len(cdnIPRoute)))

    contentIPWhoisDict = whoisIP(contentIP)
    contentIPLocation = (contentIPWhoisDict["region"] + " " + contentIPWhoisDict["country"]).strip()
    contentIPPing = pingIP(contentIP)
    contentIPRoute = traceRouteToIP(contentIP)
    print("Content IP ({0} - RTT:{3}ms - {4} hops) location is in {1} and managed by {2}".format(contentIP, contentIPLocation, contentIPWhoisDict["org"], contentIPPing, len(contentIPRoute)))


def traceRouteToIP(url):
    """Executes a trace route to the argument url or ip.
    It does not resolve hostnames, is limited to maximum 20 hops
    and will wait 500 milliseconds before considering a packet dropped."""
    if sys.platform == 'win32':
        traceOutput = subprocess.check_output([traceTool, "-d", "-h", "20", "-w", "500", url])
    else:
        traceOutput = subprocess.check_output([traceTool, "-n", "-m", "20", "-w", "0.5", url, "32"])
    traceStr = traceOutput.decode()
    hopExpr = re.compile(r'^\s+\d+')
    traceLines = [l for l in traceStr.split(os.linesep) if hopExpr.match(l) is not None]
    return traceLines


def whoisIP(ip):
    whoisRequest = requests.get("http://ipinfo.io/{0}/json".format(ip))
    return whoisRequest.json()


def pingIP(ip):
    if sys.platform == 'win32':
        pingOutput = subprocess.check_output(['ping', '-n', '4', '-l', '32', '-w', '500', ip])
    else:
        pingOutput = subprocess.check_output(['ping', '-c', '4', '-s', '32', '-w', '0.5', ip])
    pingStr = pingOutput.decode().strip()
    pingResult = pingStr.split(os.linesep)[-1]
    if sys.platform == 'win32':
        avgPingExpr = re.compile(r'Average = (\d+)ms')
    else:
        avgPingExpr = re.compile(r' = \d+\.\d+/(\d+\.\d+)/')
    match = avgPingExpr.search(pingResult)
    if match is None:
        return None
    else:
        return match.group(1)


def measureExistingNetworkActivity(sleepTime = 3, thresholdRecvKBs = 100, thresholdSendKBs = 30):
    """Checks if there is existing network activity from this machine which could disrupt the measurements"""
    initialIoStat = psutil.net_io_counters(pernic=False)
    initialSent = initialIoStat[0]
    initialRecv = initialIoStat[1]
    sleep(sleepTime)
    afterIoStat = psutil.net_io_counters(pernic=False)
    afterSent = afterIoStat[0]
    afterRecv = afterIoStat[1]
    if afterRecv - initialRecv > thresholdRecvKBs * 1024 * sleepTime or afterSent - initialSent > thresholdSendKBs * 1024 * sleepTime:
        print("Existing network activity detected, ensure that there is no network activity before executing")
        sys.exit(1)


def run(inputFilename):
    measureExistingNetworkActivity()
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
