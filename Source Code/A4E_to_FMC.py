#!/bin/env python

'''
PURPOSE:
THIS SCRIPT IMPORTS ALL THE OPERATING SYSTEMS INFORMATION AND VULNERABLE SOFTWARE DETECTIONS FROM AMP FOR ENDPOINTS (A4E) CONSOLE USING THE A4E API, 
    PRINTS THE OUTPUT TO A CSV AND THEN IMPORTS THE CSV INTO FIREPOWER MANAGEMENT CENTER USING THE HOST INPUT API OF FMC.

DEPENDENCIES / REQUIREMENTS:
1- PYTHON 2.7 OR 3.6
2- PERL 5
3- ACCOUNT ON AMP FOR ENDPOINTS PUBLIC CLOUD AND AN API KEY GENERATED. READ-ONLY API KEY IS FINE
4- FIREPOWER MANAGEMENT CENTER (FMC) 5.4+
5- 'requests' MODULE, THAT CAN BE INSTALLED BY EXECUTING THE COMMAND "python -m pip install requests"
6- UPDATE THE 'parameters.json' FILE WITH THE DETAILS BEFORE EXECUTING THIS SCRIPT
7- TCP PORT 443 TO AMP FOR ENDPOINTS API
8- TCP PORT 8307 TO FMC
9- FMC HOST INPUT API CLIENT CERTIFICATE FILE (xxxxxx.pkcs12) GENERATED FROM FMC, DOWNLOADED IN THIS SCRIPT'S LOCAL DIRECTORY.
     TO GENERATE THE CERTIFICATE, LOGIN TO FMC WEB GUI AND NAVIGATE TO SYSTEM -> INTEGRATIONS -> HOST INPUT CLIENT -> CREATE CLIENT 
     -> HOSTNAME IS THE IP OF THE HOST RUNNING THIS SCRIPT AND NO PASSWORD -> DOWNLOAD THE PKCS12 FILE IN THIS SCRIPT'S LOCAL DIRECTORY

NOTE:
All Cisco software is subject to the Supplemental End User License Agreements (SEULA) located at https://www.cisco.com/c/en/us/about/legal/cloud-and-software/software-terms.html
'''

import amp_api
import json
import sys
import subprocess
import logging
import os

auditlogfile = "AUDIT.log"

# Start Log File Handler
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler(auditlogfile)
datefmt='[%Y-%m-%d %H:%M:%S]'
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',datefmt)
handler.setFormatter(formatter)
logger.addHandler(handler)


# Import variables to get configuration
logger.info("###############################################################################")
logger.info("###############################################################################")
logger.info("Starting execution of the script")
config = ''
try:
	config = json.loads(open("parameters.json").read())
	logger.info("Found the parameters file - 'parameters.json'. Loading in parameters now....")
except Exception as err:
	logger.error("ERROR in reading the 'parameters.json' file or the file does not exist. So exiting!  Below is the exact exception message.")
	print ("ERROR in reading the 'parameters.json' file or the file does not exist. So exiting!  Below is the exact exception message.")
	logger.error(str(err))
	print (str(err))
	logger.error("Check out the sample 'parameters.json' file for example....")
	print ("Check out the sample 'parameters.json' file for example....")
	sys.exit()

csv = open("./hostinputcsv.txt", "w")

# Create dictionary of variables
var = {
	"A4E_client_id": config["A4E_client_id"],
	"A4E_api_key": config["A4E_api_key"],
	"A4E_API_hostname": config["A4E_API_hostname"],
	"A4E_group_names": config["A4E_group_names"],
	"FMC_ipaddress": config["FMC_ipaddress"],
	"FMC_host_vuln_db_overwrite_OR_update": config["FMC_host_vuln_db_overwrite_OR_update"],
	"push_changes_to_fmc": config["push_changes_to_fmc"],
	}

# Check to make sure there is data in the parameters
for key in var.keys():
	value = var[key]
	if value != "":
		if key == 'A4E_api_key':
			logger.info("Parameters {} is {}".format(key, '*******************'))
		else:
			logger.info("Parameters {} is {}".format(key, value))
	else:
		logger.error("Missing Value for the Parameter {}.... So exiting!".format(key, value))
		print ("Missing Value for the Parameter {}.... So exiting!".format(key, value))
		sys.exit()

if 'A4E_client_id' not in var.keys():
	logger.error("Missing the Parameter - 'A4E_client_id'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	print ("Missing the Parameter - 'A4E_client_id'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	sys.exit()
if 'A4E_api_key' not in var.keys():
	logger.error("Missing the Parameter - 'A4E_api_key'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	print ("Missing the Parameter - 'A4E_api_key'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	sys.exit()
if 'A4E_API_hostname' not in var.keys():
	logger.error("Missing the Parameter - 'A4E_API_hostname'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	print ("Missing the Parameter - 'A4E_API_hostname'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	sys.exit()
if 'A4E_group_names' not in var.keys():
	logger.error("Missing the Parameter - 'A4E_group_names'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	print ("Missing the Parameter - 'A4E_group_names'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	sys.exit()
# Check that var["A4E_group_names"] is a list
if type(var["A4E_group_names"]) != list:
	logger.error("Parameter 'A4E_group_names' must be an ARRAY. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	print ("Parameter 'A4E_group_names' must be an ARRAY. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	sys.exit()
if 'FMC_ipaddress' not in var.keys():
	logger.error("Missing the Parameter - 'FMC_ipaddress'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	print ("Missing the Parameter - 'FMC_ipaddress'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	sys.exit()
if 'FMC_host_vuln_db_overwrite_OR_update' not in var.keys():
	logger.error("Missing the Parameter - 'FMC_host_vuln_db_overwrite_OR_update'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	print ("Missing the Parameter - 'FMC_host_vuln_db_overwrite_OR_update'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	sys.exit()
if var['FMC_host_vuln_db_overwrite_OR_update'] != "overwrite" and var['FMC_host_vuln_db_overwrite_OR_update'] != "update":
	logger.error("Parameter - 'FMC_host_vuln_db_overwrite_OR_update' can be either set to \"update\" or \"overwrite\". Any other value is not allowed... So exiting!  Check out the sample 'parameters.json' file for example.... ")
	print ("Parameter - 'FMC_host_vuln_db_overwrite_OR_update' can be either set to \"update\" or \"overwrite\". Any other value is not allowed... So exiting!  Check out the sample 'parameters.json' file for example.... ")
	sys.exit()
if 'push_changes_to_fmc' not in var.keys():
	logger.error("Missing the Parameter - 'push_changes_to_fmc'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	print ("Missing the Parameter - 'push_changes_to_fmc'. So exiting!  Check out the sample 'parameters.json' file for example.... ")
	sys.exit()

logger.info("Parameter check complete")

amp = amp_api.amp(var["A4E_API_hostname"], var["A4E_client_id"], var["A4E_api_key"])

# Getting Groups infomation and checking if the provided group names exist on AMP for Endpoints Console
group_data = amp.get( "/v1/groups" )
if type(group_data) != dict:
	logger.error("The output of API query to GET all the Groups is not as expected. So exiting!  Below is the output.... ")
	logger.error(group_data)
	print ("The output of API query to GET all the Groups is not as expected. So exiting!  Below is the output.... ")
	print (group_data)
	sys.exit()

group_guids = []
for A4E_group_name in var["A4E_group_names"]:
	found = False
	for group in group_data["data"]:
		if group["name"] == A4E_group_name:
			group_guids.append( str(group["guid"]) )
			found = True
			logger.info("FOUND group - '{}' with ID {}".format(group["name"],str(group["guid"])))
			break
	if not found:
		logger.error("NOT FOUND group - '{}'".format(A4E_group_name))

if len(group_guids)==0:
	logger.error("FAIL - None of the given group names exist: {}. So exiting!".format(", ".join(var["A4E_group_names"])))
	print ("FAIL - None of the given group names exist: {}. So exiting!".format(", ".join(var["A4E_group_names"])))
	sys.exit()

# automate getting the id if its at all related to vulnerable endpoints pull it out
event_types = amp.get( "/v1/event_types" )
if type(event_types) != dict:
	logger.error("The output of API query to GET all the Event Types is not as expected. So exiting!  Below is the output.... ")
	logger.error(event_types)
	print ("The output of API query to GET all the Event Types is not as expected. So exiting!  Below is the output.... ")
	print (event_types)
	sys.exit()

event_type_ids = []
for event_type in event_types["data"]:
	if "Vulnerable" in event_type["name"]:
		event_type_ids.append(str(event_type["id"]))

# Usually the event_type would be "Vulnerable Application Detected" and the event_type_id would be 1107296279
# However we still search the event_type_name and event_type_id, just in case if the event_type_id is changed in the future. So the script will continue to work without requiring any modifications
# Joining the event_type_ids in case if multiple event_type_ids are found
if len(event_type_ids)>0:
	logger.info("FOUND Event Type - " + event_type["name"] + " with id " + str(event_type["id"]))
else:
	logger.error("FAIL - No event types found to be associated with Vulnerable Software Detection. So exiting!")
	print ("FAIL - No event types found to be associated with Vulnerable Software Detection. So exiting!")
	sys.exit()

# Fetch the events filtered by event_type_ids and group_guids
events = amp.get( "/v1/events?event_type[]="+"&event_type[]=".join(event_type_ids)+ "&group_guid[]="+"&group_guid[]=".join(group_guids) )
if type(events) != dict:
	logger.error("The output of API query to GET all the Events of the Given Type for the Given Groups is not as expected. So exiting!  Below is the output.... ")
	logger.error(events)
	print ("The output of API query to GET all the Events of the Given Type for the Given Groups is not as expected. So exiting!  Below is the output.... ")
	print (events)
	sys.exit()

if len(events)==0:
	logger.info("NO EVENTS FOUND of type - Vulnerable Software Detection for the provided groups. So exiting!")
	print ("NO EVENTS FOUND of type - Vulnerable Software Detection for the provided groups. So exiting!")
	sys.exit()

# Fetch the computer filtered by group_guids
computers = amp.get( "/v1/computers?group_guid[]="+"&group_guid[]=".join(group_guids) )
if type(computers) != dict:
	logger.error("The output of API query to GET all the Computers for the Given Groups is not as expected. So exiting!  Below is the output.... ")
	logger.error(computers)
	print ("The output of API query to GET all the Computers for the Given Groups is not as expected. So exiting!  Below is the output.... ")
	print (computers)
	sys.exit()

# extract the CVE details from the vulnerable software detection events
logger.info("Starting to Parse the events")
csv.write("SetSource,AMP for Endpoints\n")
vul_id = 10024
for event in events["data"]:
	connector_guid = event['computer']['connector_guid']
	isactive = event['computer']['active']
	if not isactive:
		continue
	if not 'network_addresses' in event['computer'].keys():
		continue
	network_addresses = event['computer']['network_addresses']
	file_name = event['file']['file_name']
	file_hash = event['file']['identity']['sha256']
	vulnerabilities = event['vulnerabilities']
	app_name = ''
	app_version = ''
	cve_list = []
	for vulnerability in vulnerabilities:
		if( 'name' in vulnerability.keys() ):
			app_name = vulnerability['name']
		if( 'version' in vulnerability.keys() ):
			app_version = vulnerability['version']
		if( 'cve' in vulnerability.keys() ):
			cve_list.append(vulnerability['cve'])
	app = app_name
	if( app_version != '' ):
		app = app + ' ' + app_version
	#print ( "connector_guid: {}\napplication: {}\ncve_list: {}\n".format(connector_guid,app,cve_list) )
	cve_string = " ".join(cve_list)
	ip_addresses = []
	for entry in network_addresses:
		ip = entry['ip']
		if 'mac' in entry.keys():
			mac = entry['mac']
		ip_addresses.append(ip)
		
		if not mac:
			csv.write("AddHost,{}\n".format(ip))
		else:
			csv.write("AddHost,{},{}\n".format(ip, mac))
		
		csv.write("AddScanResult,{},\"AMP for Endpoints\",{},,,\"{}\",,\"cve_ids: {}\",\"bugtraq_ids:\"\n".format(ip,vul_id,app,cve_string))
		vul_id = vul_id + 1

# Get the Operating System information from the computer details
for computer in computers["data"]:
	connector_guid = computer['connector_guid']
	isactive = computer['active']
	if not isactive:
		continue
	if not 'network_addresses' in computer.keys():
		continue
	network_addresses = computer['network_addresses']
	ip_addresses = []
	for entry in network_addresses:
		ip = entry['ip']
		if 'mac' in entry.keys():
			mac = entry['mac']
		ip_addresses.append(ip)
		
		if not mac:
			csv.write("AddHost,{}\n".format(ip))
		else:
			csv.write("AddHost,{},{}\n".format(ip, mac))
		
		opersys = computer["operating_system"].split(" ")
		if opersys[0] == ("Windows"):
			temp = " ".join(opersys[1:])
			if len(temp)>1:
				csv.write("SetOS,{},Microsoft,{},\"{}\"\n".format(ip, opersys[0], temp.split(', ')[0]))
			else:
				csv.write("SetOS,{},Microsoft,{},\"{}\"\n".format(ip, opersys[0], " ".join(opersys[1:])))
		if opersys[0] == ("OSX"):
			csv.write("SetOS,{},Mac,{},\"{}\"\n".format(ip, opersys[0], " ".join(opersys[1:])))
		if opersys[0] == ("Linux"):
			csv.write("SetOS,{},CentOS,{},\"{}\"\n".format(ip, opersys[0], " ".join(opersys[1:])))
		if opersys[0] == ("Android"):
			csv.write("SetOS,{},Google,{},\"{}\"\n".format(ip, opersys[0], " ".join(opersys[1:])))
		
if var['FMC_host_vuln_db_overwrite_OR_update'] == "overwrite":
	csv.write("ScanFlush")
else:
	csv.write("ScanUpdate")

csv.close()
logger.info("Completed the Parsing of the events and wrote the information to the CSV file")

if not var["push_changes_to_fmc"]:
	logger.info("Not supposed to push any changes to FMC as per the parameters in 'parameters.json'...  So exiting!")
	print ("Not supposed to push any changes to FMC as per the parameters in 'parameters.json'...  So exiting!")
	sys.exit()
else:
	# Call the Perl Host Input SDK client for the Host Input
	logger.info("Calling the PERL client of FMC Host Input SDK to push the CSV details into FMC")
	
	perl_log_filename = ".HostInput.log"
	if os.path.exists(perl_log_filename):
		try:
			os.remove(perl_log_filename)
		except:
			pass
	
	logger.info("COMMAND:-" + " perl" + " sf_host_input_agent.pl" + " -server={}".format(var["FMC_ipaddress"]) + " -level=3" + " -logfile={}".format(perl_log_filename) + " -plugininfo=hostinputcsv.txt" + " csv" + " -runondc=n")
	
	pipe = subprocess.call(["perl", "sf_host_input_agent.pl", "-server={}".format(var["FMC_ipaddress"]),"-level=3","-logfile={}".format(perl_log_filename),"-plugininfo=hostinputcsv.txt","csv","-runondc=n" ])
	
	logger.info("The output of the script is saved in a seperate file. Copying the content of that file here as-it-is")
	
	try:
		with open(perl_log_filename) as f:
			output = f.read()
			logger.info("\n"+output)
			f.close()
		os.remove(perl_log_filename)
	except:
		logger.error("Could not open the " + perl_log_filename + " file, so probably the PERL script execution might have failed")
		print ("Could not open the " + perl_log_filename + " file, so probably the PERL script execution might have failed")
		sys.exit()

print ("The output of the script is appended to '" + auditlogfile + "' file" )