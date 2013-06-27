__author__ = 'Parag Baxi'
#!/usr/bin/env python

'''Trend IGs from scheduled scans.

Provide operational context on why vulnerability numbers are fluctuating.
Audits scan trends and accuracy across various scan segments and scan time.
At some point, it will hopefully have the following.
1. # of hosts live.
2. Scan time difference.
3. # of unique hosts found in later scan exceeds some % (new hosts)
4. # of unique hosts not found in later scan exceeds some % (hosts dropped off)
5. # of unique hosts not found was within a CIDR, this is important dropped
6. # of unique hosts not found was within an asset group, this is important dropped



'''

import argparse
import csv
import datetime
import logging
# import logging.config
import os
import sqlite3
import string
import sys
from collections import defaultdict
from lxml import objectify, etree
from qualysconnect.util import build_v1_connector, build_v2_connector

def load_scan(scan_ref):
    """ Returns an objectified QualysGuard scan report of QualysGuard's scan's scan_ref.

    """
    global qgc
    scan_filename = scan_ref.replace('/', '_')
    scan_filename = 'scans/' + scan_filename + '.xml'
    try:
        logger.info('Trying to open scan report %s' % (scan_ref))
        with open(scan_filename):
            report_xml_file = open(scan_filename,'r')
            return objectify.parse(report_xml_file).getroot()
    except IOError:
        # Download XML.
        logger.info('Downloading scan report %s' % (scan_ref))
        print 'Downloading scan report %s ...' % (scan_ref),
        report_xml = qgc.request('scan_report.php','ref=%s' % (scan_ref))
        print 'done.'
        # Store XML.
        with open(scan_filename, 'w') as text_file:
            text_file.write(report_xml)
        # Return objectified XML.
        return objectify.fromstring(report_xml)


def scan_report_ips(scan_root):
    """ Returns a dict of live IPs discovered from objectified QualysGuard scan report with dict of notable attributes.

    """
    live_ips = defaultdict(lambda : defaultdict(str))
    for ip in scan_root.IP:
        ip_address = ip.get("value")
        # Store duration, which is part of scan_host_time, QID 45038.
        try:
            scan_host_time = ip.INFOS.xpath('CAT[@value="Information gathering"]')[0]\
                .xpath('INFO[@number="45038"]')[0].RESULT.text
            live_ips[ip_address]['duration'] = scan_host_time[15:scan_host_time.index(' seconds')]
        except AttributeError, e:
            # Host was discovered via DNS table lookup.
            # IP not actually scanned because it did not respond to discovery.
            pass
    logger.debug(live_ips)
    return live_ips

# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(description = 'Trend IG information from scans.')
parser.add_argument('-a', '--asset_group',
    help = 'FUTURE: Asset group to filter against.')
parser.add_argument('-d', '--days', default='60',
    help = 'Number of days to process. Default: 60.')
parser.add_argument('-f', '--force_download_scans', action = 'store_true',
                    help = 'Delete existing scan XML and download scan XML.')
parser.add_argument('-m', '--include_manual_scans', action = 'store_true',
    help = 'FUTURE: Process adhoc scans. By default, I only process scheduled scans')
parser.add_argument('--scan_files',
                    help = 'Two scan XML files to be compared, separated by a comma (,)')
parser.add_argument('-t', '--scan_title',
                    help = 'Scan title to filter.')
parser.add_argument('-v', '--verbose', action = 'store_true',
                    help = 'Outputs additional information to log.')
# Parse arguments.
c_args = parser.parse_args()
if c_args.asset_group or c_args.include_manual_scans:
    print 'For thousands more years the mighty ships tore across the empty wastes of space and finally dived\
 screaming on to the first planet they came across - which happened to be the Earth - where due to a terrible\
 miscalculation of scale the entire battle fleet was accidentally swallowed by a small dog.'
    exit(1)
# Set log directory.
PATH_LOG = 'log'
if not os.path.exists(PATH_LOG):
    os.makedirs(PATH_LOG)
LOG_FILENAME = '%s/%s.log' % (PATH_LOG, datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))
# Set log options.
logger_qc = logging.getLogger('qualysconnect.util')
logger_qc.setLevel(logging.ERROR)
# My logging.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False
# # Import logging configuration.
# logging.config.fileConfig('logging.conf')
# Create file handler logger.
logger_file = logging.FileHandler(LOG_FILENAME)
logging_level = logging.DEBUG
if not c_args.verbose:
    logging_level = logging.INFO
logger_file.setLevel(logging_level)
logger_file.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)s %(funcName)s %(lineno)d %(message)s','%m-%d %H:%M'))
logger.addHandler(logger_file)
# Define a Handler which writes WARNING messages or higher to the sys.stderr
logger_console = logging.StreamHandler()
logger_console.setLevel(logging.ERROR)
# Set a format which is simpler for console use.
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
# Tell the handler to use this format.
logger_console.setFormatter(formatter)
# Add the handler to the root logger
logger.addHandler(logger_console)
# Start coding.
# Create/Replace sqlite db.
try:
    os.remove('scan_trend.sqlite')
    logger.debug('Removed existing SQLite file.')
except:
    pass
conn = sqlite3.connect('scan_trend.sqlite')
c = conn.cursor()
# Create table
c.execute('''CREATE TABLE if not exists scan_data
             (scan_title text, ip text, duration_1 integer, duration_2 integer)''')
# Primary key are a combination of the scan_title & ip being unique.
c.execute('CREATE UNIQUE INDEX scan_data_scan_title_ip_index ON scan_data (scan_title, ip)')
# Download scan list
# Connect to QualysGuard API v2.
qgc = build_v1_connector()
qgc2 = build_v2_connector()
# Store each unique scan separately in order of newest scan to oldest scan.
# scans is each scan organized by title.
# scans['scan title'] = [scan_ref_latest, scan_ref_2nd_latest, ..., scan_ref_oldest]
scans = defaultdict(list)
if c_args.scan_files:
    scans['Manual'] = c_args.scan_files.split(',')
else:
    # Set log directory.
    PATH_SCANS = 'scans'
    if not os.path.exists(PATH_SCANS):
        os.makedirs(PATH_SCANS)
    # Find start date of scans to download/process.
    start_date=datetime.date.today()-datetime.timedelta(days=int(c_args.days))
    # Include manual scans?
    # type={On-Demand|Scheduled|API}&
    scan_type = 'Scheduled'
    # Build request.
    request = 'scan/?action=list&state=Finished&show_ags=1&show_op=1&type=%s&launched_after_datetime=%s' % (scan_type, str(start_date))
    # Download scan list
    xml_output = qgc2.request(request)
    # Write scan list XML.
    with open('scans/%s_scan_list.xml' % (datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')), "w") as text_file:
        text_file.write(xml_output)
    # Process XML.
    root = objectify.fromstring(xml_output)
    # Parse scan list for scan references. Scan list is in order from newest scan to oldest scan.
    logging.info('Processing scan list.')
    for scan in root.RESPONSE.SCAN_LIST.SCAN:
        # Stringify scan title.
        this_scan_title = str(scan.TITLE)
        # Scope to title if parameter enabled.
        if c_args.scan_title:
            if this_scan_title != c_args.scan_title:
                continue
        if len(scans[this_scan_title]) < 2:
            # We only care about the last two scans.
            logger.info('%s: %s' % (this_scan_title, scan.REF))
            scans[this_scan_title].append(str(scan.REF))
# Download & convert each scheduled scan XML to scans_data dict.
for scan_title in scans:
    scan_number = 1
    for scan_ref in scans[scan_title]:
        # Force download new scan?
        if c_args.force_download_scans:
            try:
                os.remove(scan_ref)
            except:
                # Scan XML does not exist.
                pass
        # Fetch and/or open, and save scan.
        scan_root = load_scan(scan_ref)
        logging.info('Processing scan %s.' % (scan_ref))
        # Store pertinent IGs for later processing.
        scan_time = scan_root.xpath('//KEY[@value="DURATION"]/text()')[0]
        logger.debug(scan_time)
        # Parse individual IPs
        for ip in scan_root.IP:
            ip_address = str(ip.get("value"))
            # Store duration, which is part of scan_host_time, QID 45038.
            try:
                scan_host_time = ip.INFOS.xpath('CAT[@value="Information gathering"]')[0].xpath('INFO[@number="45038"]')[0].RESULT.text
                scan_host_time = str(scan_host_time)
                scan_host_time = scan_host_time[15:scan_host_time.index(' seconds')]
                scan_host_time = int(scan_host_time)
            except AttributeError, e:
                # Host was discovered via DNS table lookup.
                # IP not actually scanned because it did not respond to discovery.
                pass
            # Insert individual IP info.
            if scan_number == 1:
                logger.debug('insert %s, %s, %s' % (scan_title, ip_address, scan_host_time))
                c.execute("INSERT INTO scan_data VALUES (?, ?, ?, null)", (scan_title, ip_address, scan_host_time))
            else:
                logger.debug('update %s, %s, %s' % (scan_title, ip_address, scan_host_time))
                c.execute('''REPLACE INTO scan_data (scan_title, ip, duration_1, duration_2)
                    VALUES (?,
                    ?,
                    (SELECT duration_1 FROM scan_data WHERE (scan_title = ? AND ip = ?)),
                    ?
                    );''',(scan_title, ip_address, scan_title, ip_address, scan_host_time))
                # c.execute("UPDATE scan_data SET duration_2=? WHERE (scan_title = ? AND ip = ?);", (scan_host_time, scan_title, ip_address))
            conn.commit()
        # Increment scan number to track duration column.
        scan_number += 1
with open('scan_trend.csv', 'wb') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['Scan title', 'Host', 'Duration 1', 'Duration 2', 'New host', 'Lost host', '% duration difference'])
    with conn:
        c.execute("SELECT * FROM scan_data")
        while True:
            row = c.fetchone()
            if row == None:
                break
            # Calculate metrics
            latest_scan = row[3]
            previous_scan = row[2]
            new_host = latest_scan and not previous_scan
            # Prefer blanks in CSV versus False.
            if not new_host:
                new_host = None
            lost_host = previous_scan and not latest_scan
            if not lost_host:
                lost_host = None
            percent_difference = None
            try:
                percent_difference = round(abs(1.0-float(previous_scan)/float(latest_scan))*100.0, 2)
            except TypeError, e:
                logging.debug('Host not in both scans.')
                pass
            row = row + (new_host,) + (lost_host,) + (percent_difference,)
            csv_writer.writerow(row)
# Save SQLite DB.
conn.close()

