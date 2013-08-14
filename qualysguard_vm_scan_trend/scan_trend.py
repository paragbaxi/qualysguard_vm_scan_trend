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

import datetime
import logging
import os
import argparse, ConfigParser
import csv
import datetime
import logging
import os
import qualysapi
import sqlite3
import string
import sys
import time
import types
from collections import defaultdict
from lxml import objectify, etree

def load_scan(scan_ref, report_template=None):
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
        if not report_template:
            # Download complete scan.
            print 'Downloading scan report %s ...' % (scan_ref),
            request_parameters = {'ref': scan_ref}
            logger.debug(request_parameters)
            report_xml = qgc.request('scan_report.php', request_parameters)
        else:
            # Generate report.
            print 'Generating report against %s ...' % (scan_ref),
            request_parameters = {'action': 'launch', 'template_id': str(report_template), 'report_type': 'Scan', 'output_format': 'xml', 'report_refs': scan_ref}
            logger.debug(request_parameters)
            xml_output = qgc.request('api/2.0/fo/report', request_parameters)
            report_id = etree.XML(xml_output).find('.//VALUE').text
            logger.debug('report_id: %s' % (report_id))
            # Wait for report to finish spooling.
            # Time in seconds to wait between checks.
            POLLING_DELAY = 30
            # Time in seconds to wait before checking.
            STARTUP_DELAY = 30
            # Maximum number of times to check for report.  About 10 minutes.
            MAX_CHECKS = 10
            print 'Report sent to spooler. Checking for report in %s seconds.' % (STARTUP_DELAY)
            time.sleep(STARTUP_DELAY)
            for n in range(0, MAX_CHECKS):
                # Check to see if report is done.
                xml_output = qgc.request('api/2.0/fo/report', {'action': 'list', 'id': report_id})
                tag_status = etree.XML(xml_output).findtext(".//STATE")
                logger.debug('tag_status: %s' % (tag_status))
                tag_status = etree.XML(xml_output).findtext(".//STATE")
                logger.debug('tag_status: %s' % (tag_status))
                if not type(tag_status) == types.NoneType:
                    # Report is showing up in the Report Center.
                    if tag_status == 'Finished':
                        # Report creation complete.
                        break
                # Report not finished, wait.
                print 'Report still spooling. Trying again in %s seconds.' % (POLLING_DELAY)
                time.sleep(POLLING_DELAY)
            # We now have to fetch the report.  Use the report id.
            report_xml = qgc.request('api/2.0/fo/report', {'action': 'fetch', 'id': report_id})
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
# parser.add_argument('-a', '--asset_group',
#     help = 'FUTURE: Asset group to filter against.')
parser.add_argument('-d', '--days', default='10',
    help = 'Number of days to process. Default: 10.')
parser.add_argument('-f', '--force_download_scans', action = 'store_true',
                    help = 'Delete existing scan XML and download scan XML.')
# parser.add_argument('-m', '--include_manual_scans', action = 'store_true',
#     help = 'FUTURE: Process adhoc scans. By default, I only process scheduled scans.')
parser.add_argument('-r', '--report_template',
    help = '''Generate reports against REPORT_TEMPLATE's ID to parse data to save time and space.
            \nThis report template should only include QID 45038, Host Scan Time.''')
parser.add_argument('--scan_files',
                    help = 'Two scan XML files to be compared, separated by a comma (,).')
parser.add_argument('-t', '--scan_title',
                    help = 'Scan title to filter.')
parser.add_argument('-v', '--verbose', action = 'store_true',
                    help = 'Outputs additional information to log.')
# Parse arguments.
c_args = parser.parse_args()
# Set log directory.
PATH_LOG = 'log'
if not os.path.exists(PATH_LOG):
    os.makedirs(PATH_LOG)
LOG_FILENAME = '%s/%s.log' % (PATH_LOG, datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))
# My logging.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# logger.propagate = False
# Set log options.
logging_level = logging.INFO
# Log qualysapi.
logger_qc = logging.getLogger('qualysapi.connector')
if c_args.verbose:
    logging_level = logging.DEBUG
logger_qc.setLevel(logging_level)
# Create file handler logger.
logger_file = logging.FileHandler(LOG_FILENAME)
logger_file.setLevel(logging_level)
logger_file.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)s %(funcName)s %(lineno)d %(message)s','%m-%d %H:%M'))
# Define a Handler which writes WARNING messages or higher to the sys.stderr
logger_console = logging.StreamHandler()
logger_console.setLevel(logging.ERROR)
# Set a format which is simpler for console use.
# Tell the handler to use this format.
logger_console.setFormatter(logging.Formatter('%(name)-12s: %(levelname)-8s %(lineno)d %(message)s'))
# Add the handlers to the loggers
logger.addHandler(logger_file)
logger.addHandler(logger_console)
logger_qc.addHandler(logger_file)
logger_qc.addHandler(logger_console)
# Start coding.
# Create/Replace sqlite db.
conn = sqlite3.connect('scan_trend.sqlite')
c = conn.cursor()
# Create tables
c.execute('''CREATE TABLE IF NOT EXISTS scan_xmls
          (schedule_title text, scan_ref text, scan_date text);''')
c.execute('DROP TABLE IF EXISTS scan_data;')
c.execute('''CREATE TABLE scan_data
             (scan_title text, ip text, duration_1 integer, duration_2 integer);''')
# Primary key are a combination of the scan_title & ip being unique.
c.execute('CREATE UNIQUE INDEX scan_data_scan_title_ip_index ON scan_data (scan_title, ip);')
# Download scan list
# Connect to QualysGuard API.
qgc = qualysapi.connect()
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
    url = 'api/2.0/fo/scan/'
    parameters = {'action': 'list', 'state': 'Finished', 'show_ags': '1', 'show_op': '1', 'type': scan_type, 'launched_after_datetime': str(start_date)}
    # Download scan list
    logger.info('Downloading scan list.')
    print 'Downloading scan list ...',
    xml_output = qgc.request(url, parameters)
    print 'done.'
    # Write scan list XML if debug.
    if c_args.verbose:
        with open('scans/%s_scan_list.xml' % (datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')), "w") as text_file:
            text_file.write(xml_output)
    # Process XML.
    root = objectify.fromstring(xml_output)
    # Parse scan list for scan references. Scan list is in order from newest scan to oldest scan.
    logger.info('Processing scan list.')
    for scan in root.RESPONSE.SCAN_LIST.SCAN:
        # Stringify scan title.
        this_scan_title = scan.TITLE.text
        # Scope to title if parameter enabled.
        if c_args.scan_title:
            if this_scan_title != c_args.scan_title:
                continue
        this_scan_date = scan.LAUNCH_DATETIME.text
        this_scan_date_time = datetime.datetime.strptime( this_scan_date[:-1], "%Y-%m-%dT%H:%M:%S" )
        this_scan_ref = scan.REF.text
        # Add to scan_xmls table.
        c.execute("INSERT INTO scan_xmls VALUES (?, ?, ?);", (this_scan_title, this_scan_ref, this_scan_date_time))
        # Check to see if we have too many older scan XMLs.
        c.execute("SELECT * FROM scan_xmls WHERE schedule_title = ?;", (this_scan_title,))
        all_saved_scans = c.fetchall()
        # logger.debug(str(all_saved_scans), len(all_saved_scans))
        # Delete oldest scan XML if we have more than 2 of the same scheduled scans.
        if len(all_saved_scans) > 2:
            logger.debug('Deleting oldest scan.')
            # Sort list, get oldest scan, get tuple, get scan_ref of that.
            oldest_scan_ref = sorted(all_saved_scans,key=lambda x: x[2])[0:1][0][1]
            # Delete oldest XML file.
            c.execute("DELETE FROM scan_xmls WHERE scan_ref = ?", (oldest_scan_ref,))
            try:
                os.remove('scans/%s' % oldest_scan_ref.replace('/','_'))
            except:
                # Scan XML does not exist.
                pass
        if len(scans[this_scan_title]) < 2:
            # We only care about the last two scans.
            logger.info('%s: %s' % (this_scan_title, this_scan_ref))
            scans[this_scan_title].append(this_scan_ref)
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
        scan_root = load_scan(scan_ref, c_args.report_template)
        logger.info('Processing scan %s.' % (scan_ref))
        # Store pertinent IGs for later processing.
        scan_time = scan_root.xpath('//KEY[@value="DURATION"]/text()')[0]
        logger.debug(scan_time)
        # Parse individual IPs
        try:
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
                    c.execute("INSERT INTO scan_data VALUES (?, ?, ?, null);", (scan_title, ip_address, scan_host_time))
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
        except AttributeError, e:
            # No IPs discovered in this scan.
            # Do not increment scan number.
            scan_number -= 1
            pass
        # Increment scan number to track duration column for DB.
        scan_number += 1
# Write CSV.
csv_filename = '%s_scan_trend.csv' % (datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S'))
with open(csv_filename, 'wb') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['Scan title', 'Host', 'Latest duration', 'Older duration', 'New host', 'Lost host', 'Duration % difference'])
    with conn:
        c.execute("SELECT * FROM scan_data;")
        while True:
            row = c.fetchone()
            if row == None:
                break
            # Calculate metrics
            latest_scan = row[2]
            previous_scan = row[3]
            new_host = latest_scan and not previous_scan
            lost_host = previous_scan and not latest_scan
            # Prefer blanks in CSV versus False.
            if not new_host:
                new_host = None
            if not lost_host:
                lost_host = None
            percent_difference = None
            try:
                percent_difference = round(abs(1.0-float(previous_scan)/float(latest_scan))*100.0, 2)
            except TypeError, e:
                logger.debug('Host not in both scans.')
                pass
            row = row + (new_host,) + (lost_host,) + (percent_difference,)
            csv_writer.writerow(row)
# Save SQLite DB.
conn.close()
# Notify user it's complete.
print 'Successfully wrote scan trending data to %s file.' % (csv_filename)

