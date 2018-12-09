# sniff
[![Build Status](https://travis-ci.com/stephengroat/sniff.svg?branch=master)](https://travis-ci.com/stephengroat/sniff)

Command line HTTP sniffer and alerter for Python 3.5

## Installation

```
git clone https://github.com/stephengroat/sniff
cd sniff
pip install -r requirements.txt
sudo python3 sniff.py --help
usage: sniff.py [-h] --alertsection ALERTSECTION --alertsize ALERTSIZE

Sniff HTTP traffic for sections and alert

optional arguments:
  -h, --help            show this help message and exit
  --alertsection ALERTSECTION
                        website section for alert (i.e. test.com/test or
                        test.com)
  --alertsize ALERTSIZE
                        number of hits within 2 minutes to generate alert
```

## Usage

Example:

```
sudo python3 sniff.py --alertsection=www.bbc.com --alertsize=2
```

**NOTE** Set with BPF to monitor `(tcp and dst port 80) or (tcp and src port 80)` for speed (avoiding unnecessary traffic). If HTTP traffic is be sent over a non-standard port, this filter should be reconfigured.

**NOTE** `maxcachesize` is currently set to 1024 for performance, allowing for that many hits in 10 seconds or alert hits in 2 minutes. If a more hits to track are required, the value should be modified

**NOTE** `sudo` or other root access may be required for network interface sniffing

## TODO

- [ ] 
- [ ] create a `setup.py` for better installation methods
- [ ] fix python2 floating point division issue for cross compatability
- [ ] try to get https://github.com/stephengroat/cachetools/commit/0b4337076b642857cb4ecd63ffe4fe3bec53bf2c push to upstream project
