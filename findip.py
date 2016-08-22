import subprocess
import socket
import sys
import re
import requests
import psutil
import os
import csv
from time import sleep
from datetime import datetime

# Set this to subprocess.DEVNULL for clean output, None for verbose output
verboseOutputTarget = subprocess.DEVNULL

# Retry attemps
numberOfRetries = 3

# Number of test runs
numberOfRuns = 3

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

    if sys.platform == 'win32':
        subprocess.Popen(['ping', '-n', '4', '8.8.8.8'], stdout=verboseOutputTarget, stderr=subprocess.STDOUT).wait()
    else:
        subprocess.Popen(['ping', '-c', '4', '-s', '24', '8.8.8.8'], stdout=verboseOutputTarget, stderr=subprocess.STDOUT).wait()
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
    if sys.platform == 'win32':
        ipconfigLines = subprocess.Popen(['ipconfig'], stdout=subprocess.PIPE, stderr=verboseOutputTarget).stdout.readlines()
        localIP = '(Unknown)'
        for line in ipconfigLines:
            lineStr = str(line.strip())
            if not lineStr.startswith('IPv4 Address'):
                continue
            localIP = lineStr[lineStr.find(':') + 2:]
        return localIP
    else:
        ipRoute = subprocess.Popen(["ip", "route", "get", "8.8.8.8"], stdout=subprocess.PIPE)
        return subprocess.check_output(["awk", "{print $NF; exit}"], stdin=ipRoute.stdout).strip()


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
    for i in range(numberOfRetries + 1):
        try:
            return socket.gethostbyname(targetHost.strip())
        except socket.gaierror:
            if i < numberOfRetries:
                continue
            else:
                raise


def getContentIP(targetURL, localIP, networkDeviceID):
    downloadFilename = subprocess.check_output(['youtube-dl', '--get-filename', targetURL]).strip().decode()

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

    for i in range(numberOfRetries + 1):
        if i != 0:
            # Failed to obtain content IP
            print("Re-trying to obtain content IP due to noisy trace. Attempt {0} out of {1}.".format(i, numberOfRetries))

        removePartFiles(downloadFilename)

        downloadProcess = subprocess.Popen(['youtube-dl', targetURL], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        dumpProcess = subprocess.Popen([dumptool] + dumpArgs, stdout=subprocess.PIPE, stderr=verboseOutputTarget)
        dumpOutput = dumpProcess.stdout.readlines()
        downloadProcess.kill()

        downloadSpeedOutputLine = downloadProcess.stdout.readlines()[-1].decode()
        downloadSpeedFinalOutput = downloadSpeedOutputLine[downloadSpeedOutputLine.rfind('\r'):]
        downloadSpeedUnits = ("B/s", "KiB/s", "MiB/s")
        downloadKBPerSecond = -1
        unitFactor = 1.0/1024.0 # NOTE: This is the factor for B/s, and we assume the following units are the next one up each time
        for units in downloadSpeedUnits:
            patternString = r"at (\d+\.?\d*)%s ETA" % units
            downloadSpeedMatch = re.search(patternString, downloadSpeedFinalOutput)
            if not downloadSpeedMatch:
                unitFactor *= 1024
                continue
            else:
                downloadKBPerSecond = float(downloadSpeedMatch.group(1)) * unitFactor
                break
        if downloadKBPerSecond == -1:
            print("ERROR: Unable to extract download speed from final output line: %s" % downloadSpeedOutputLine)

        ipMap = {}
        ipRegex = re.compile(r'((\d+\.){3}\d+)\.\d+ > ((\d+\.){3}\d+)\.\d+')
        nonMatches = 0
        for line in dumpOutput:
            ipMatch = ipRegex.search(str(line))
            if not ipMatch:
                nonMatches += 1
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
        if maxIPCount > (len(dumpOutput) - nonMatches) / 2:
            removePartFiles(downloadFilename)
            return maxIP, downloadKBPerSecond

    # If we are unable to determine the content IP after the retry attempts, we raise a RunTime exception
    raise RuntimeError("The network trace is too noisy in order to determine the content IP")


def profileURL(targetURL, localIP, listenDeviceID):
    targetHost = getHostFromURL(targetURL)
    targetIP = getIPFromHost(targetHost)

    cdnURL = getContentURL(targetURL)
    cdnHost = getHostFromURL(cdnURL)
    cdnIP = getIPFromHost(cdnHost)

    contentIP, contentKBPerSecond = getContentIP(targetURL, localIP, listenDeviceID)
    print('%s (%s) refers to a CDN at %s (%s) and the actual content came from %s'
          % (targetHost, targetIP, cdnHost, cdnIP, contentIP))

    targetIPWhoisDict = whoisIP(targetIP)
    targetIPLocation = (targetIPWhoisDict["region"] + " " + targetIPWhoisDict["country"]).strip()
    targetIPOwner = targetIPWhoisDict["org"]
    targetIPPing = pingIP(targetIP)
    targetIPRoute = traceRouteToIP(targetIP)
    targetData = (targetIP, targetIPLocation, targetIPOwner, targetIPPing, len(targetIPRoute))
    print("Target IP ({0} - RTT:{3}ms - {4} hops) location is in {1} and managed by {2}".format(targetIP, targetIPLocation, targetIPOwner, targetIPPing, len(targetIPRoute)))

    cdnIPWhoisDict = whoisIP(cdnIP)
    cdnIPLocation = (cdnIPWhoisDict["region"] + " " + cdnIPWhoisDict["country"]).strip()
    cdnIPOwner = cdnIPWhoisDict["org"]
    cdnIPPing = pingIP(cdnIP)
    cdnIPRoute = traceRouteToIP(cdnIP)
    cdnData = (cdnIP, cdnIPLocation, cdnIPOwner, cdnIPPing, len(cdnIPRoute))
    print("CDN IP ({0} - RTT:{3}ms - {4} hops) location is in {1} and managed by {2}".format(cdnIP, cdnIPLocation, cdnIPOwner, cdnIPPing, len(cdnIPRoute)))

    contentIPWhoisDict = whoisIP(contentIP)
    contentIPLocation = (contentIPWhoisDict["region"] + " " + contentIPWhoisDict["country"]).strip()
    contentIPOwner = contentIPWhoisDict["org"]
    contentIPPing = pingIP(contentIP)
    contentIPRoute = traceRouteToIP(contentIP)
    contentData = (contentIP, contentIPLocation, contentIPOwner, contentIPPing, len(contentIPRoute), contentKBPerSecond)
    print("Content IP ({0} - RTT:{3}ms - {4} hops) location is in {1} and managed by {2}\n".format(contentIP, contentIPLocation, contentIPOwner, contentIPPing, len(contentIPRoute)))
    return (targetData, cdnData, contentData)


def traceRouteToIP(url):
    """Executes a trace route to the argument url or ip.
    It does not resolve hostnames, is limited to maximum 30 hops
    and will wait a maximum of 1500 milliseconds before moving to the next hop."""
    if sys.platform == 'win32':
        traceOutput = subprocess.check_output([traceTool, "-d", "-h", "30", "-w", "1500", url])
    else:
        traceOutput = subprocess.check_output([traceTool, "-n", "-m", "30", "-w", "1.5", url, "32"])
    traceStr = traceOutput.decode()
    hopExpr = re.compile(r'^\s+\d+')
    traceLines = [l for l in traceStr.split(os.linesep) if hopExpr.match(l) is not None]
    return traceLines


def whoisIP(ip):
    for i in range(numberOfRetries + 1):
        whoisRequest = requests.get("http://ipinfo.io/{0}/json".format(ip))
        whoisJson = whoisRequest.json()
        if "country" in whoisJson and "org" in whoisJson:
            if "region" in whoisJson:
                return whoisJson
            else:
                whoisJson["region"] = ""
                return whoisJson

        sleep(1)

    raise RuntimeError("Unable to successfully execute whois on {0}".format(ip))


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
        raise RuntimeError("Existing network activity detected, ensure that there is no network activity before executing")

    localPing = pingIP("8.8.8.8")
    if float(localPing) > 150:
        raise RuntimeError("Ping to google DNS is higher than expected, ensure network is stable before executing measurement")


def run(inputFilename):
    measureExistingNetworkActivity()
    localIP = getLocalIP()
    listenDeviceID = getPrimaryNetworkDevice()
    with open(inputFilename) as f:
        content = f.readlines()

    currentTime = datetime.now().strftime('%H-%M-%S_%d-%m-%Y')
    outputFile = open("data-{0}.csv".format(currentTime), "w", newline="")
    csvWriter = csv.writer(outputFile, delimiter=",", quoting=csv.QUOTE_MINIMAL)
    titleRow = []
    titleRow += ["targetIP", "targetLoc", "targetOwner", "targetPing", "targetHops"]
    titleRow += ["cdnIP", "cdnLoc", "cdnOwner", "cdnPing", "cdnHops"]
    titleRow += ["contentIP", "contentLoc", "contentOwner", "contentPing", "contentHops", "contentThroughput(KB/s)"]
    titleRow += ["targetURL"]
    csvWriter.writerow(titleRow)
    for i in range(numberOfRuns):
        print("Run {0} of {1}".format(i+1, numberOfRuns))
        for url in content:
            if url.strip() != '' and not url.startswith('#'):
                targetURL = url.strip()
                urlMetrics = profileURL(targetURL, localIP, listenDeviceID)
                csvWriter.writerow(urlMetrics[0] + urlMetrics[1] + urlMetrics[2] + (targetURL,))
    outputFile.close()


def verbosePrint(message):
    if verboseOutputTarget is None:
        print(message)


def removePartFiles(downloadFilename):
    currentDir = os.getcwd()
    files = os.listdir(currentDir)
    for file in files:
        if file.endswith(".part") or file == downloadFilename or ".part-" in file:
            os.remove(os.path.join(currentDir, file))


# We can use https://www.reddit.com/r/unknownvideos/ as a source of probably-not-cached videos
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('No argument given, expected "findip.py <contentUrl>"')
    else:
        run(sys.argv[1])
