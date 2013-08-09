qualysguard_vm_scan_trend
=========================

Provide operational context on why vulnerability numbers are fluctuating in QualysGuard. Audits scan trends and accuracy across various scan segments and scan time.

Automatically downloads scheduled scans to show differene in live hosts and host scan times.

Important
=========

It is highly recommended to generate reports against each scan versus having the script download the actual scan data.

The following is required for this feature:

1. Create a static search list (VM > Reports > Search Lists > New > Static Lists... ) containing QID 45038 (Host Scan Time). 
   
   ![ScreenShot](https://raw.github.com/paragbaxi/qualysguard_vm_scan_trend/master/images/screenshot-static-search-list.png)
   
Create a report template (VM > Reports > Templates > New > Scan Template... ) with the following configuration:

1. Scan Results Section > Run Time: Select individual scan results at run time (Manual)
   
   ![ScreenShot](https://raw.github.com/paragbaxi/qualysguard_vm_scan_trend/master/images/screenshot-report-template-run-time.png)
   
2. Filter > Selective Vulnerability Reporting > Custom > Add Lists > Add search list
   
   ![ScreenShot](https://raw.github.com/paragbaxi/qualysguard_vm_scan_trend/master/images/screenshot-report-template-filter-custom.png)
   
3. Filter > Vulnerability Filters
   
   ![ScreenShot](https://raw.github.com/paragbaxi/qualysguard_vm_scan_trend/master/images/screenshot-report-template-filter-IG.png)
   
This report_template ID should be inputted in the "--report_template" parameter. You can find the report template ID by viewing the report template info:
VM > Reports > Templates > Dropdown next to report template > Info > General Information

![ScreenShot](https://raw.github.com/paragbaxi/qualysguard_vm_scan_trend/master/images/screenshot-report-template-id.png)

The report template ID is the value associated with the run_temp parameter. This setting will enable the script to generate reports against manual scans instead of downloading complete scan data (which can be hundreds of megabytes on large scans).

Usage
=====

<pre>
usage: scan_trend.py [-h] [-d DAYS] [-f] [-r REPORT_TEMPLATE]
                     [--scan_files SCAN_FILES] [-t SCAN_TITLE] [-v]

Trend IG information from scans.

optional arguments:
  -h, --help            show this help message and exit
  -d DAYS, --days DAYS  Number of days to process. Default: 10.
  -f, --force_download_scans
                        Delete existing scan XML and download scan XML.
  -r REPORT_TEMPLATE, --report_template REPORT_TEMPLATE
                        Generate reports against REPORT_TEMPLATE's ID to parse
                        data to save time and space. This report template
                        should only include QID 45038, Host Scan Time.
  --scan_files SCAN_FILES
                        Two scan XML files to be compared, separated by a
                        comma (,).
  -t SCAN_TITLE, --scan_title SCAN_TITLE
                        Scan title to filter.
  -v, --verbose         Outputs additional information to log.

</pre>

Example CSV output:
<table>
<tr><td>Scan title</td><td>Host</td><td>Duration 1</td><td>Duration 2</td><td>New host</td><td>Lost host</td><td>% duration difference</td></tr>
<tr><td>Weekly Environment Scan</td><td>10.10.10.127</td><td>657</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Weekly Environment Scan</td><td>10.10.24.69</td><td>219</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Weekly Environment Scan</td><td>10.10.24.78</td><td>209</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Seattle Data Center</td><td>10.39.106.24</td><td>229</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Seattle Data Center</td><td>10.39.106.24</td><td>235</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Seattle Data Center</td><td>10.39.106.24</td><td>609</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Seattle Data Center</td><td>10.39.106.24</td><td>550</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>DMZ daily</td><td>10.10.1.178</td><td>614</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>DMZ daily</td><td>10.0.100.10</td><td></td><td>904</td><td>TRUE</td><td></td><td></td></tr>
<tr><td>DMZ daily</td><td>10.0.100.11</td><td>934</td><td>933</td><td></td><td></td><td>0.11</td></tr>
<tr><td>DMZ daily</td><td>10.10.1.14</td><td>990</td><td>978</td><td></td><td></td><td>1.23</td></tr>
<tr><td>DMZ daily</td><td>10.10.1.15</td><td>424</td><td>412</td><td></td><td></td><td>2.91</td></tr>
<tr><td>DMZ daily</td><td>10.10.1.20</td><td>381</td><td>323</td><td></td><td></td><td>17.96</td></tr>
<tr><td>DMZ daily</td><td>10.10.1.29</td><td></td><td>1484</td><td>TRUE</td><td></td><td></td></tr>
<tr><td>DMZ daily</td><td>10.10.1.30</td><td>595</td><td>630</td><td></td><td></td><td>5.56</td></tr>
<tr><td>DMZ daily</td><td>10.10.1.31</td><td>341</td><td>552</td><td></td><td></td><td>38.22</td></tr>
<tr><td>DMZ daily</td><td>10.10.1.33</td><td>306</td><td>363</td><td></td><td></td><td>15.7</td></tr>
<tr><td>DMZ daily</td><td>10.10.1.43</td><td>262</td><td>268</td><td></td><td></td><td>2.24</td></tr>
<tr><td>DMZ daily</td><td>10.10.1.44</td><td></td><td>339</td><td>TRUE</td><td></td><td></td></tr>
<tr><td>Incremental Scan</td><td>10.10.32.93</td><td>840</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Incremental Scan</td><td>10.10.32.95</td><td>780</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Incremental Scan</td><td>10.20.30.56</td><td>997</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Incremental Scan</td><td>10.20.30.58</td><td>755</td><td></td><td></td><td>TRUE</td><td></td></tr>
<tr><td>Incremental Scan</td><td>10.20.30.59</td><td>716</td><td></td><td></td><td>TRUE</td><td></td></tr>
</table>
