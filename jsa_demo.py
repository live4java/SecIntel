import json
import urllib3
import requests
import time
import subprocess
import ipcheck
import yaml
import sys
import srx_session
from srx_session import gET_ID, cLEAR_ID
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from subprocess import call
from ipcheck import is_valid_ipv4_address

SRX_IP = '10.105.5.7'
JSA_IP = '10.155.79.205'

# Open Connection to SRX
N1 = Device(host=SRX_IP,user='root',password='testing123')
N1.open()

# Disable warnings for bad server certificate
requests.packages.urllib3.disable_warnings()

cron_file = open('/root/Downloads/jsa/latest/cron_log','a')

url = 'https://%s/api/siem/offenses' % JSA_IP

response = requests.get(url, auth=('admin', 'juniper123'), verify=False)

offense = json.loads(response.text)

current_time = time.asctime(time.localtime(time.time()))
cron_file.write(current_time + '\n')


for i in offense:
	sev = i['severity']
	status = i['status']	
	source = str(i['offense_source'])
	if sev == 10 and is_valid_ipv4_address(source) and status == "OPEN":
		id = str(i['id'])

		# Call the script "jwas_submit" to block the Source IP
		subprocess.Popen(['python', '/root/Downloads/jsa/latest/jwas_submit.py', '--server', '10.105.5.223', 'qNY52Ns6xsFkygIFJczyoFAI1LSfnW0d', 'tme', 'add', source, '180', '8'])

		# Clear the event from JSA
		close_url = 'https://%s/api/siem/offenses/%d?status=CLOSED&closing_reason_id=2' % (JSA_IP, i['id'])
		post_response = requests.post(close_url, auth=('admin', 'juniper123'), verify=False)
	

		# Clear the session in SRX	
		cLEAR_ID(N1, source)
		
		cron_file.write('---' + source + ' blocked\n')

# Clean up
cron_file.close()
N1.close()

