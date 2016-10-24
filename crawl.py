import gzip
from StringIO import StringIO
from bs4 import BeautifulSoup
import urllib2
import requests

def ungzip(data):		
	buf = StringIO(data)		
	f = gzip.GzipFile(fileobj = buf)
	source = f.read()
	return source
	
def crawl(url):
	req_header = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',\
		'Accept':'text/html;q=0.9,*/*;q=0.8',\
		'Accept-Charset':'ISO-8859-1,utf-8;q=0.7,*;q=0.3',\
		'Accept-Encoding':'gzip',\
		'Connection':'close',\
		'Referer':None }
	req_timeout = 10
	req = urllib2.Request(url, None, req_header)
	resp = urllib2.urlopen(req, None, req_timeout)
	if resp.headers.get('content-encoding') == "gzip":
		source = ungzip(resp.read())
	else:
		source = resp.read()
	return source
def crawl_cve_info(url):
	data = urllib2.urlopen(url).read()
	soup = BeautifulSoup(data)
	# print cve_soup.select('table tbody tr td div')
	trs = soup.select('table tbody tr td div')[1].select('table tbody tr')
	values = []
	for t_id in range(0, 9):
		value = trs[t_id].select('td')[1].text
	#clean b_id <br>?
		if t_id == 2 or t_id == 8:
			cves_tmp = []
			for val in  value.split('\n\t\t\t\t\n\t\t\t\t\t'):
				val = val.replace('\t', '')
				val = val.replace('\n', '')
				if val != "":
					cves_tmp.append(val.strip())
			value = ",".join(cves_tmp)
		else:
			value = value.replace('\t', '')
			value = value.replace('\n', '')
		values.append(value)
	#exploit code

	exploit_url = url + '/exploit'
	data = urllib2.urlopen(exploit_url).read()
	soup = BeautifulSoup(data)
	exploit_info = soup.select('#vulnerability')
	# for cont in exploit_info.contents:
	# 	if cont
	values.append(exploit_info[0].contents[4])
	return values
			# break
def get_cve_url(cve):
	headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',\
		'Accept':'text/html;q=0.9,*/*;q=0.8',\
		'Accept-Charset':'ISO-8859-1,utf-8;q=0.7,*;q=0.3',\
		'Accept-Encoding':'gzip',\
		'Connection':'close',\
		'Referer':None }
	send_pkg = {'op':'display_list', 'c':12, 'vendor':'', 'title':'', 'version':''}
	send_pkg['CVE'] = cve
	url = "http://www.securityfocus.com/bid"
	resp = requests.post(url, send_pkg, headers= headers)
	soup = BeautifulSoup(resp.text)
	hrefs = soup.select('#article_list div a')
	print hrefs
	if len(hrefs) > 0:
		a_link = hrefs[1].text
#		print a_link
		result = crawl_cve_info(a_link)
		return result
	else:
		return None

def run():
		url = 'http://www.securityfocus.com/cgi-bin/index.cgi?o=330&l=100&c=12&op=display_list&vendor=&version=&title=&CVE='
		source = crawl(url)
		soup = BeautifulSoup(source,'html.parser')
		cves_ids = soup.select('div#article_list div a')
		for i in range(0, len(cves_ids), 2):
 			cve_url = cves_ids[i+1].text
 			#basic information 
			crawl_cve_info(cve_url)
			# break
tmp = ""
with open('extract_cves.csv' ,'r') as f:
	rows = f.read().strip().split('\n')
	for cve in rows:
		print "cve", cve
		result = get_cve_url(cve)
		if not result == None:
			tmp += "@:".join(result) + "\n"
			print tmp
