import subprocess
import socket
import sys
import re

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
    return subprocess.Popen(['youtube-dl', '-g', targetURL], stdout=subprocess.PIPE).stdout.read()

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

def getContentIP(targetURL):
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
    dumpArgs = ['-nvS', '-s', '128', '-i', '2', '-c', '5000', 'tcp']
    dumpProcess = subprocess.Popen(['windump'] + dumpArgs, stdout=subprocess.PIPE)
    dumpOutput = dumpProcess.stdout.readlines()
    downloadProcess.kill()

    ipMap = {}
    ipRegex = re.compile(r'((\d+\.){3}\d+)\.\d+ > ((\d+\.){3}\d+)\.\d+')
    for line in dumpOutput:
        ipMatch = ipRegex.search(line)
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


# We can use https://www.reddit.com/r/unknownvideos/ as a source of probably-not-cached videos
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('No argument given, expected "findip.py <contentUrl>"')
    else:
        targetURL = sys.argv[1]
        localIP = getLocalIP()
        targetHost = getHostFromURL(targetURL)
        targetIP = getIPFromHost(targetHost)

        cdnURL = getContentURL(targetURL)
        cdnHost = getHostFromURL(cdnURL)
        cdnIP = getIPFromHost(cdnHost)

        contentIP = '...'
        #contentIP = getContentIP(targetURL)
        print('%s (%s) refers to a CDN at %s (%s) which delivers content from %s'
                % (targetHost, targetIP, cdnHost, cdnIP, contentIP))
