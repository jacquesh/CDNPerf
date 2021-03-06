# CDN-Perf
A project for a course titled "Measuring Internet Performance".
The focus is on comparing the performance characteristics of websites such as YouTube to that of the servers which deliver their actual content.

## Requirements
### Ubuntu
  - ```sudo apt-get build-essential traceroute tcpdump python3-dev python3-pip```
  - ```pip install -r requirements.txt``` (virtual environment suggested: [link](http://stackoverflow.com/a/23842752))
  - Ensure that tcpdump has permissions to access network device: [instructions](http://askubuntu.com/a/632189) (N.B. requires reboot after the steps are complete)
  - Ensure traceroute has permissions to send ICMP packets: ``` sudo chmod u+s `which traceroute` ``` and similarly for ```ping``` if necessary.

### Windows
  - [WinDump](https://www.winpcap.org/windump/install/default.htm) installed or in the current directory
  - [Python 3] (https://www.python.org/downloads/)
  - ```pip install -r requirements.txt``` (virtual environment suggested: [link](http://stackoverflow.com/a/23842752))

### Python modules
The tests were run with the following version of each module (should the tests need to be replicated):
  - psutil==4.3.0
  - requests==2.11.1
  - youtube-dl==2016.8.13

## To run
  - ```source <path_to_virtual_environment>/bin/activate``` if using a virtual environment
  - Ensure all the URLs of the videos you want to test are in a text file (see urls.txt for an example)
  - ```python cdn_perf.py <path_to_urls_file>```

## Output
  - A file ```data-<timestamp>.csv``` will be created which contains all test results.
