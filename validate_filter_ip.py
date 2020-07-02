#!/usr/bin/env python
#
#    Initial code from does_it_live.py...
#      Version 1.0 2018-10-15
#      Written by:
#         Alexis Dacquay, ad@arista.com
#      https://github.com/alexisdacquay/does_it_live
#    validate_filter_ip.py 1.0 2020-06-30 by Brice Cox, bcox@arista.com

import argparse
import logging
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import syslog
import time
from jsonrpclib import Server

# Global configuration settings
# logStr is a formatting pattern used by str.format() to align outputs
logStr = '{:27} {}'
# syslogFormat can be customised to match syslog preference
syslogFormat = '%VALIDATE_FILTER_IP-5-LOG'
prefix_list_name = 'SCRIPTED_ROUTE_FILTER'

def setLogging(args):
    # The log level sets the amount of information displayed (error<info<debug)
    logLevel = logging.ERROR
    if args.verbose:
        logLevel = logging.INFO
    if args.veryverbose:
        logLevel = logging.DEBUG
    logging.basicConfig(level=logLevel,
                        format='%(levelname)-8s %(message)s')


def parseArgs():
    parser = argparse.ArgumentParser(
        description='Checks whether a destination is alive')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='activates verbose output')

    parser.add_argument('-V', '--veryverbose', action='store_true',
                        help='activates very verbose output')

    parser.add_argument('-i', '--interval', type=int, default=1,
                        help='Interval of polls. Default is 1')

    parser.add_argument('-t', '--timeout', type=int, default=1,
                        help='Amount of seconds to wait for a response')

    parser.add_argument('-m', '--mode', default='icmp',
                        help='detection mode: ICMP \
                                Default is ICMP')

    parser.add_argument('-s', '--source',
                        help='source IP address to reach')

    parser.add_argument('-D', '--dampening', type=int, default=3,
                        help='Dampening amount of fail/success for target to\
                                be considered switching status')

    parser.add_argument('host', nargs='+',
                        help='FQDN or IP address of the destination(s) to \
                                check')

    args = parser.parse_args()
    if args.veryverbose:
        args.verbose = True

    return args


def argsDisplay(args):
    # For debug purpose or curiosity
    logging.info('')
    logging.info('########### Your settings: ###########')
    logging.debug(logStr.format('Args are:', args))
    logging.info(logStr.format('Verbose:', args.verbose))
    logging.info(logStr.format('VeryVerbose:', args.veryverbose))
    logging.info(logStr.format('Interval:', args.interval))
    logging.info(logStr.format('Timeout:', args.timeout))
    logging.info(logStr.format('Mode:', args.mode))
    logging.info(logStr.format('Source IP:', args.source))
    logging.info(logStr.format('Dampening amount:', args.dampening))
    logging.info(logStr.format('Target Host:', args.host))
    logging.info('#######################################')
    logging.info('')


def checkOS():
    # Different OS have diferring PING options. This fuction standardises
    os = platform.system()
    osSettings = {}
    timeUnit = 1
    sourceSetting = '-I'
    if os == 'Linux':
        # On EOS Linux kernel timeout is in second and IP source as '-I'
        timeUnit = 1
        sourceSetting = '-I'
    elif os == 'Darwin':
        # On MACOS timeout is in msec (want it in sec) and IP source as '-S'
        timeUnit = 1000
        sourceSetting = '-S'
    else:
        logging.error('Error - Unsupported OS')
    osSettings['timeUnit'] = timeUnit
    osSettings['sourceSetting'] = sourceSetting
    return osSettings


class checkICMP:
    # Verifies a reachability by ICMP and records the response latency
    def __init__(self, osSettings, host):

        self.timeUnit = osSettings['timeUnit']
        self.sourceSetting = osSettings['sourceSetting']
        self.host = host

    def getLatency(self, output):
        # Must first get an output to parse, used after/with isAlive()
        outputLines = output.split('\n')
        lastNonEmpty = [i for i in outputLines if i][-1]
        logging.debug(logStr.format('Ping result:', lastNonEmpty))
        timingData = lastNonEmpty.split('=')[1]
        timingStats = timingData.split('/')
        pingAvg = timingStats[1]
        return pingAvg + ' ms'

    def isAlive(self):
        result = ''
        output = ''
        latency = 0
        pythonVersion = sys.version_info[0]
        logging.debug(logStr.format('Python version:', pythonVersion))

        src_exists = True if args.source else False
        command = ['ping'] + \
                  ['-n'] + \
                  ['-c 1'] + \
                  ['-t 1'] + \
                  ['-W ' + str(args.timeout * self.timeUnit)] + \
                  [self.sourceSetting + str(args.source)] * src_exists + \
                  [self.host]
        logging.debug(logStr.format('The command is:', str(command)))

        # Python 2 compatibility for running on EOS
        if sys.version_info[0] < 3:
            proc = subprocess.Popen(command,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            returncode = proc.wait()
            if returncode == 0:
                rawOutput = proc.communicate()
                output = rawOutput[0].decode('ascii')
                result = True
            else:
                error = 'The ICMP check did not succeed'
                logging.info(error)
                result = False

        # Python 3
        if sys.version_info[0] >= 3:
            proc = subprocess.run(command, capture_output=True)
            if proc.returncode == 0:
                output = proc.stdout.decode('ascii')
                result = True
            else:
                # If proc.returncode != 0 it means an error occured.
                # We get a clean line for the error message
                error = proc.stderr.decode('ascii').split('\n')[0]
                if error == '':
                    error = 'The ICMP check did not succeed'
                logging.info(error)
                result = False

        if output:
            logging.debug(logStr.format('The output is:', output))
            latency = self.getLatency(output)
        return result, latency


class Notice():
    # Sends messages out by Syslog or potentially other future methods
    def __init__(self):
        pass

    def syslog(self, msg):
        name = 'validate_filter_ip'
        syslog.openlog(name, 0, syslog.LOG_LOCAL4)
        syslog.syslog(syslogFormat + ': Log msg: %s' % msg)

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True
#

def network_s31(address):
    if ":" in address:
        exit("IPv6 not currently supported")
    else:
        if not is_valid_ipv4_address(address):
            exit("address " + address + " does not appear to be valid")
        parts = address.split(".")
        if (int(parts[3]) % 2 == 1):
            return parts[0] + '.' + parts[1] + '.' + parts[2] + '.' + str(int(parts[3])-1) + '/31'
        else:
            return address + '/31'
#

def check_filter(net31, prefix_list_name):
    #open api connection
    switch_api = build_connection()
    #read filter
    cmd = 'show ip prefix-list ' + prefix_list_name
    result = switch_api.runCmds(1,[cmd])[0]['ipPrefixLists']
    switch_api('close')()
    if result.has_key(prefix_list_name):
        result = result[prefix_list_name]['ipPrefixEntries']
        while result:
            iterate = result.pop()
            if iterate['prefix'] == net31:
                logging.debug(logStr.format('network /31 found in:', prefix_list_name))
                logging.debug(logStr.format('sequence number:', iterate['seqno']))
                return True, iterate['seqno']
    else:
        logging.debug(logStr.format('prefix-list does not exist:', prefix_list_name))
    return False, 0
#

def add_filter(net31, prefix_list_name):
    #open api connection and add the line to the prefix-list
    switch_api = build_connection()
    cmd = [
        'enable',
        'configure',
        'ip prefix-list ' + prefix_list_name + ' permit ' + net31,
        'end'
        ]
    result = switch_api.runCmds(1,cmd)
    switch_api('close')()
#

def remove_filter(seqno, prefix_list_name):
    #open api connection and add the line to the prefix-list
    switch_api = build_connection()
    cmd = [
        'enable',
        'configure',
        'no ip prefix-list ' + prefix_list_name + ' seq ' + str(seqno),
        'end'
        ]
    result = switch_api.runCmds(1,cmd)
    switch_api('close')()
#

def build_connection():
    ### Build connection to api
    if os.path.exists('/var/run/command-api.sock'):
        switch_api = Server( "unix:/var/run/command-api.sock")
        return switch_api
    else:
        exit("Socket API not available: enable it via...\n  management api http-commands\n    protocol unix-socket\n    no shutdown")
#

def main():
    global args
    dampeningDead = 0
    dampeningAlive = 0
    wasAlive = True

    args = parseArgs()
    setLogging(args)
    argsDisplay(args)
    osSettings = checkOS()
    net31 = network_s31(args.host[0])
    logging.debug(logStr.format('network /31 for host:', net31))
    filtered, seqno = check_filter(net31, prefix_list_name)
    if filtered:
        if wasAlive:
            logging.info(logStr.format('Target already filtered ', prefix_list_name))
            wasAlive = False

    try:
        while True:
            if args.mode == 'icmp':
                check = checkICMP(osSettings, args.host[0])

            # Check alive (True/False) and response (ICMP latency)
            alive, response = check.isAlive()

            send = Notice()
            if alive:
                logging.info(logStr.format('Target alive. Response:', response))
                # Dead dampening count re-initializing
                dampeningDead = 0

                if not wasAlive:
                    # Was dead, is now coming back to life. Dampening kicks in.
                    if (dampeningAlive < args.dampening):
                        dampeningAlive += 1
                        logging.info('Dampening in progress')
                        logging.debug(logStr.format(
                            'Remaining successes before assuming resurrection:',
                            dampeningAlive))
                    elif (dampeningAlive == args.dampening):
                        # The dampening is completed, target considered resurrected
                        wasAlive = True
                        dampeningAlive = 0
                        logging.error('Target resurrected!')
                        send.syslog('Target {} is available'.format(
                                    args.host[0], args.mode))
                        # remove filter if in place
                        ### Insert extra code here for further verifacation service is up steps
                        filtered, seqno = check_filter(net31, prefix_list_name)
                        if filtered:
                            remove_filter(seqno, prefix_list_name)
                            logging.error(logStr.format('Target removed from prefix-list:', prefix_list_name))
                            send.syslog('Target {} removed from {} prefix-list'.format(
                                    args.host[0], prefix_list_name))

            else:
                # Looks like dead. Dampening in progress
                dampeningDead += 1
                # Alive dampening count re-initializing
                dampeningAlive = 0

                if wasAlive and (dampeningDead >= args.dampening):
                    logging.error(logStr.format('Warning:', 'Target is dead'))
                    send.syslog('Target {} is dead - added to {} prefix-list'.format(
                                args.host[0], prefix_list_name))
                    ### Insert extra code here for further verifacation service is down steps
                    # Set filter
                    add_filter(net31, prefix_list_name)

                    # Death tracker
                    wasAlive = False
                else:
                    # Either the target is already dead or Dampening is going on
                    # Dampening at failure is silent (intuitive enough?)
                    pass
            logging.debug('')
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(' Interrupted! Exiting...')


if __name__ == '__main__':
    main()
