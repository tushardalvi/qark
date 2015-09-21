'''Copyright 2015 LinkedIn Corp. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software 
distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.'''

import os, sys
import fnmatch
from collections import defaultdict
from xml.dom import minidom
import traceback
import logging
import shutil
from threading import Thread
from Queue import Queue
import subprocess
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)) + '/../lib')
import axmlparserpy.axmlprinter as axmlprinter

from pyfiglet import Figlet

from pubsub import pub

from modules import findExtras,webviews, report, unpackAPK
from modules.DetermineMinSDK import determine_min_sdk, process_manifest, find_manifest_in_source
from modules import sdkManager
from modules import createSploit
from modules import createExploit
from modules import writeExploit
from modules import findMethods
from modules import findPending
from modules import findBroadcasts
from modules import findTapJacking
from modules import filePermissions
from modules import cryptoFlaws
from modules import certValidation
from modules import GeneralIssues
from modules import contentProvider
from modules.adb import show_exports, list_all_apk, uninstall, pull_apk
from modules.cli import exploit_choice
from modules.contentProvider import *
from modules import filters
from modules.common import terminalPrint, exit, clear_lines
from modules.report import Severity, report_badger
from modules.ui import progress_bar_update

ignore = os.system('clear')
f = Figlet(font='colossal')
print f.renderText('Q A R K')


common.logger = logging.getLogger()
common.rootDir = os.path.dirname(os.path.realpath(__file__))

#Initialize system
#Verify that settings.properties always exists
if not os.path.exists(os.path.dirname(os.path.realpath(__file__)) + "/settings.properties"):
	f = open(os.path.dirname(os.path.realpath(__file__)) + "/settings.properties",'w')
	f.close()

#
common.writeKey("rootDir", common.rootDir)
common.initialize_logger()

#Reset any old report
report.reset()
common.set_environment_variables()
#Copy the exploit code into a separate temp directory
if not os.path.exists(common.getConfig("rootDir") + "/build"):
	shutil.copytree(common.getConfig("rootDir") + "/exploitAPKs", common.getConfig("rootDir") + "/build")

common.logger.info(common.config.get('qarkhelper', 'STARTUP'))

if not sdkManager.is_android_sdk_installed():
	sdkManager.get_android_sdk_manager()
else:
	common.logger.info( common.config.get('qarkhelper', 'SDK_INSTALLATION_IDENTIFIED'))

common.minSdkVersion=1

#Begin
common.logger.info('Initializing QARK\n')
common.checkJavaVersion()

if common.interactive_mode:
	while True:
		try:
			print common.term.cyan + common.term.bold + str(common.config.get('qarkhelper','APK_OR_SOURCE_PROMPT')).decode('string-escape').format(t=common.term)
			common.source_or_apk=int(raw_input(common.config.get('qarkhelper','ENTER_YOUR_CHOICE')))
			if common.source_or_apk in (1,2):
				break
			else:
				if not common.interactive_mode:
					common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION'))
					exit()
				common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION_INTERACTIVE'))
		except Exception as e:
			if not common.interactive_mode:
				common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION'))
				exit()
			common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION_INTERACTIVE'))

else:
	common.source_or_apk = common.args.source
if common.source_or_apk==1:
	while True:
		try:
			if common.interactive_mode:
				while True:
					print common.term.cyan + common.term.bold + str(common.config.get('qarkhelper','APK_PATH_OR_FROM_PHONE')).decode('string-escape').format(t=common.term)
					common.apkPathChoice=int(raw_input(common.config.get('qarkhelper','ENTER_YOUR_CHOICE')))
					if common.apkPathChoice in (1,2):
						break
					else:
						if not common.interactive_mode:
							common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION'))
							common.exitClean()
						else:
							common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION_INTERACTIVE'))
				if (common.apkPathChoice==2):
					print common.term.cyan + common.term.bold + str(common.config.get('qarkhelper','TRUST_ME')).decode('string-escape').format(t=common.term)
					apkList = list_all_apk()
					for apk in apkList:
						print str(apkList.index(apk)) + ") " +  apk
					print common.term.cyan + common.term.bold + str(common.config.get('qarkhelper','APK_PATH_OR_FROM_PHONE')).decode('string-escape').format(t=common.term)
					apkIndex = int(raw_input(common.config.get('qarkhelper', 'SELECT_AN_APK') + "[" + "0-" + str(len(apkList)-1) + "]: " ))
					while apkIndex not in range(0,len(apkList)):
						common.logger.error('Please select a valid APK number')
						apkIndex = int(raw_input(common.config.get('qarkhelper', 'SELECT_AN_APK') + "(" + "0-" + str(len(apkList)-1) + "): " ))
					common.logger.info("Selected:"+ str(apkIndex) + " " + str(apkList[apkIndex]))
					common.apkPath = pull_apk(str(apkList[apkIndex]))
					apkName=str(os.path.abspath(common.apkPath)).split("/")[-1]
					common.sourceDirectory=re.sub(r''+apkName,'',os.path.abspath(common.apkPath))
				else:
					print common.term.cyan + common.term.bold + str(common.config.get('qarkhelper','PATH_PROMPT_APK')).decode('string-escape').format(t=common.term)
					common.apkPath = str(raw_input(common.config.get('qarkhelper', 'PATH_APK'))).strip()
			else:
				if common.args.apkpath is not None:
					common.apkPath = common.args.apkpath
					common.logger.debug('User selected APK %s' + common.apkPath)

			common.apkPath = os.path.abspath(common.apkPath)
			common.apkPath = re.sub("\\\\\s",' ',common.apkPath)
			report.write("apkpath", common.apkPath)
			unpackAPK.unpack()
			break
		except Exception as e:
			continue

	try:
		package = defaultdict(list)
		mf = unpackAPK.find_manifest_in_unpacked_apk(common.apkPath, common.manifestName)
		ap = axmlprinter.AXMLPrinter(open(mf, 'rb').read())
		manifestInXML = minidom.parseString(ap.getBuff()).toxml()
		if common.interactive_mode:
			show=raw_input("Inspect Manifest?[y/n]")
			if show in ['y','Y']:
				common.logger.info(manifestInXML)
				raw_input("Press ENTER key to continue")
		else:
			common.logger.info(manifestInXML)
		report.write_manifest(manifestInXML.encode( "utf-8" ))
		common.manifest = mf

	except IOError:
		common.logger.error(IOError.message)

	#parse xml
	common.xmldoc = minidom.parseString(manifestInXML.encode('utf-8'))
elif common.source_or_apk==2:
		# Check if all required arguments are present before proceeding
		while True:
			if common.interactive_mode:
				common.sourceDirectory=os.path.abspath(raw_input(common.config.get('qarkhelper','SOURCE_PROMPT')).rstrip())
			else:
				common.sourceDirectory=common.args.codepath
			re.sub(r'AndroidManifest.xml','',common.sourceDirectory)
			common.sourceDirectory = os.path.abspath(str(common.sourceDirectory).strip())
			common.sourceDirectory = re.sub("\\\\\s",' ',common.sourceDirectory)
			if os.path.isdir(common.sourceDirectory):
				if not common.sourceDirectory.endswith('/'):
					common.sourceDirectory+='/'
				process_manifest(find_manifest_in_source())
				break
			else:
				common.logger.error("Not a directory. Please try again")
		report.write("apkpath", common.sourceDirectory)
		totalfiles = 0
		for root, dirnames, filenames in os.walk(common.sourceDirectory):
			for filename in fnmatch.filter(filenames, '*'):
				totalfiles = totalfiles + 1
		report.write("totalfiles",totalfiles)

else:
		common.logger.info("You only had 2 options and you still messed up. Let me choose option 2 for you")
#Only application and manifest elements are required: http://developer.android.com/guide/topics/manifest/manifest-intro.html
try:
	determine_min_sdk()

	common.print_terminal_header("APP COMPONENT ATTACK SURFACE")

	app = common.xmldoc.getElementsByTagName("application")
	common.compare(app.length,1,common.config.get('qarkhelper', 'APP_ELEM_ISSUE'), 'true')

	GeneralIssues.verify_allow_backup(app)
	GeneralIssues.verify_custom_permissions()
	GeneralIssues.verify_debuggable(app)

	common.logger.info("Checking provider")
	prov_priv_list, prov_exp_list, prov_exp_perm_list, prov_prot_broad_list, report_data, results =common.check_export('provider',True)
	report_badger("appcomponents", results)
	common.print_terminal(report_data)

	common.logger.info("Checking activity")
	act_priv_list, act_exp_list, act_exp_perm_list, act_prot_broad_list=[],[],[],[]
	act_priv_list, act_exp_list, act_exp_perm_list, act_prot_broad_list, report_data, results=common.check_export('activity',True)

	#Normalizing activity names for use in exploit APK, so all will be absolute
	act_priv_list=common.normalizeActivityNames(act_priv_list,common.package_name)
	act_exp_list=common.normalizeActivityNames(act_exp_list,common.package_name)
	act_exp_perm_list=common.normalizeActivityNames(act_exp_perm_list,common.package_name)
	act_prot_broad_list=common.normalizeActivityNames(act_prot_broad_list,common.package_name)

	report_badger("appcomponents", results)
	common.print_terminal(report_data)

	common.logger.info("Checking activity-alias")
	#TODO - Normalize activity alias names?
	actalias_priv_list, actalias_exp_list, actalias_exp_perm_list,actalias_prot_broad_list=[],[],[],[]
	actalias_priv_list, actalias_exp_list, actalias_exp_perm_list,actalias_prot_broad_list, report_data, results=common.check_export('activity-alias',True)
	report_badger("appcomponents", results)
	common.print_terminal(report_data)

	common.logger.info("Checking services")
	serv_priv_list, serv_exp_list, serv_exp_perm_list,serv_prot_broad_list=[],[],[],[]
	serv_priv_list, serv_exp_list, serv_exp_perm_list,serv_prot_broad_list, report_data, results=common.check_export('service',True)
	report_badger("appcomponents", results)
	common.print_terminal(report_data)

	common.logger.info("Checking receivers")
	rec_priv_list, rec_exp_list, rec_exp_perm_list,rec_prot_broad_list=[],[],[],[]
	rec_priv_list, rec_exp_list, rec_exp_perm_list,rec_prot_broad_list, report_data, results=common.check_export('receiver',True)
	report_badger("appcomponents", results)
	common.print_terminal(report_data)

except Exception as e:
	common.logger.error(traceback.format_exc())

#Begin static code Analysis
#Easy Wins first
if common.source_or_apk ==1:
	if common.interactive_mode:
		stop_point = raw_input("Press ENTER key to begin decompilation")

#Converting dex files to jar
if common.source_or_apk!=1:
	try:
		if os.path.exists(common.manifest.rsplit("/",1)[0] + "/java"):
			common.pathToUnpackedAPK = common.manifest.rsplit("/",1)[0] + "/java"
			common.logger.info("Found Java Source at %s", common.pathToUnpackedAPK)
			confirm = raw_input(common.config.get('qarkhelper', 'SOURCE_CONFIRM'))
			if str(confirm).lower()=='n':
				common.sourceDirectory = os.path.abspath(raw_input(common.config.get('qarkhelper', 'SOURCE_PROMPT'))).rstrip()
			else:
				common.sourceDirectory = common.pathToUnpackedAPK
		elif os.path.exists(common.sourceDirectory):
			common.logger.info("Using "+common.sourceDirectory+" as the project source directory")
		else:
			common.sourceDirectory = os.path.abspath(raw_input(common.config.get('qarkhelper', 'SOURCE_PROMPT'))).rstrip()
			common.sourceDirectory = re.sub("\\\\\s",' ',common.sourceDirectory)
	except IOError:
		common.logger.error("Oops! all hope is lost \n %s", IOError.message)
else:
	unpackAPK.decompile(common.pathToDEX)
	if common.pathToUnpackedAPK != "":
		common.logger.info('Decompiled code found at:%s', common.pathToUnpackedAPK)
		common.sourceDirectory = common.pathToUnpackedAPK

#find all java files
common.java_files=common.find_java(common.sourceDirectory)

#find all R.java files
common.xml_files=common.find_xml(common.sourceDirectory)

if common.interactive_mode:
	stop_point = raw_input("Press ENTER key to begin Static Code Analysis")
#Regex to look for collection of deviceID
#Regex to determine if WebViews are imported
wv_imp_rex=r'android.webkit.WebView'
cp_imp_rex=r'android.content.ContentProvider'
#Run through all files, look for regex, print warning/info text and lines of code, with file names/paths

cert_queue = Queue()
pending_intents_queue = Queue()
file_permission_queue = Queue()
web_view_queue = Queue()
find_broadcast_queue = Queue()
crypto_flaw_queue = Queue()

if common.source_or_apk==1:
	report.write("javafiles", common.count)
else:
	javafiles = 0
	for root, dirnames, filenames in os.walk(common.sourceDirectory):
	  for filename in fnmatch.filter(filenames, '*.java'):
		javafiles = javafiles + 1
	report.write("javafiles", javafiles)

common.logger.info("Running Static Code Analysis...")
common.keyFiles=common.findKeys(common.sourceDirectory)

'''
#Look for improper use of checkCallingPermission, rather than enforceCallingPermission
try:
	use_check_permission()
except Exception as e:
	common.logger.error("Unable to run checks for improper use of checkCallingPermission: " + str(e))
'''

clear_lines(14)
height = common.term.height

try:

	pub.subscribe(progress_bar_update, 'progress')

	thread0 = Thread(name='Certificate Validation', target=certValidation.validate, args=(cert_queue,height-8))
	thread1 = Thread(name='Pending Intent validation', target=findPending.start, args = (pending_intents_queue,height-6))
	thread2 = Thread(name='File Permission checks', target=filePermissions.start, args = (file_permission_queue,height-4))
	thread3 = Thread(name='Webviews', target=webviews.validate, args = (web_view_queue,))
	thread4 = Thread(name='Find Broadcasts', target=findBroadcasts.main, args = (find_broadcast_queue,))
	thread5 = Thread(name='Crypto Issues', target=cryptoFlaws.main, args = (crypto_flaw_queue,))
	thread0.start()
	thread1.start()
	thread2.start()
	thread3.start()
	thread4.start()
	thread5.start()
	thread0.join()
	thread1.join()
	thread2.join()
	thread3.join()
	thread4.join()
	thread5.join()

	clear_lines(5)
	try:
	#Start looking for stuff potentially vulnerable to malicious apps
		if len(prov_exp_list)>0:
			findMethods.map_from_manifest(prov_exp_list,'provider')
		if len(prov_exp_list)>0:
			findMethods.map_from_manifest(prov_exp_perm_list,'provider')
		if len(act_exp_list)>0:
			findMethods.map_from_manifest(act_exp_list,'activity')
		if len(act_exp_perm_list)>0:
			findMethods.map_from_manifest(act_exp_perm_list,'activity')
		#BUG Need to customize this
		if len(actalias_exp_list)>0:
			findMethods.map_from_manifest(actalias_exp_list,'activity-alias')
		if len(act_exp_perm_list)>0:
			findMethods.map_from_manifest(actalias_exp_perm_list,'activity-alias')
		if len(serv_exp_list)>0:
			findMethods.map_from_manifest(serv_exp_list,'service')
		if len(serv_exp_perm_list)>0:
			findMethods.map_from_manifest(serv_exp_perm_list,'service')
		if len(rec_exp_list)>0:
			findMethods.map_from_manifest(rec_exp_list,'receiver')
		if len(rec_exp_perm_list)>0:
			findMethods.map_from_manifest(rec_exp_perm_list,'receiver')
	except Exception as e:
		common.logger.error("Unable to use findMethods to map from manifest: " + str(e))


	crypto_flaw_results = crypto_flaw_queue.get()
	try:
		report.writeSection(report.Section.CRYPTO_BUGS, crypto_flaw_results)
	except Exception as e:
		print e.message
	with common.term.location(0,common.term.height):
		common.logger.log(common.HEADER_ISSUES_LEVEL, "CRYPTO ISSUES")
	if not any(isinstance(x, terminalPrint) for x in crypto_flaw_results):
		common.logger.info(" No issues to report")
	for item in crypto_flaw_results:
		if isinstance(item, terminalPrint):
			if item.getLevel() == Severity.INFO:
				common.logger.info(item.getData())
			if item.getLevel() == Severity.WARNING:
				common.logger.warning(item.getData())
			if item.getLevel() == Severity.ERROR:
				common.logger.error(item.getData())
			if item.getLevel() == Severity.VULNERABILITY:
				common.logger.log(common.VULNERABILITY_LEVEL,item.getData())

	find_broadcast_results = find_broadcast_queue.get()
	report.writeSection(report.Section.BROADCASTS, find_broadcast_results)
	with common.term.location(0,common.term.height):
		common.logger.log(common.HEADER_ISSUES_LEVEL, "BROADCAST ISSUES")
	if not any(isinstance(x, terminalPrint) for x in find_broadcast_results):
		common.logger.info(" No issues to report")
	for item in find_broadcast_results:
		if isinstance(item, terminalPrint):
			if item.getLevel() == Severity.INFO:
				common.logger.info(item.getData())
			if item.getLevel() == Severity.WARNING:
				common.logger.warning(item.getData())
			if item.getLevel() == Severity.ERROR:
				common.logger.error(item.getData())
			if item.getLevel() == Severity.VULNERABILITY:
				common.logger.log(common.VULNERABILITY_LEVEL,item.getData())


	cert_validation_results = cert_queue.get()
	report.writeSection(report.Section.X509, cert_validation_results)
	with common.term.location(0,common.term.height):
		common.logger.log(common.HEADER_ISSUES_LEVEL, "CERTIFICATE VALIDATION ISSUES")
	if not any(isinstance(x, terminalPrint) for x in cert_validation_results):
		common.logger.info(" No issues to report")
	for item in cert_validation_results:
		if isinstance(item, terminalPrint):
			if item.getLevel() == Severity.INFO:
				common.logger.info(item.getData())
			if item.getLevel() == Severity.WARNING:
				common.logger.warning(item.getData())
			if item.getLevel() == Severity.ERROR:
				common.logger.error(item.getData())
			if item.getLevel() == Severity.VULNERABILITY:
				common.logger.log(common.VULNERABILITY_LEVEL,item.getData())

	pending_intent_results = pending_intents_queue.get()
	report.writeSection(report.Section.PENDING_INTENTS, pending_intent_results)
	with common.term.location(0,common.term.height):
		common.logger.log(common.HEADER_ISSUES_LEVEL, "PENDING INTENT ISSUES")
	if not any(isinstance(x, terminalPrint) for x in pending_intent_results):
		common.logger.info(" No issues to report")
	for item in pending_intent_results:
		if isinstance(item, terminalPrint):
			if item.getLevel() == Severity.INFO:
				common.logger.info(item.getData())
			if item.getLevel() == Severity.WARNING:
				common.logger.warning(item.getData())
			if item.getLevel() == Severity.ERROR:
				common.logger.error(item.getData())
			if item.getLevel() == Severity.VULNERABILITY:
				common.logger.log(common.VULNERABILITY_LEVEL,item.getData())


	file_permission_results = file_permission_queue.get()
	report.writeSection(report.Section.FILE_PERMISSIONS, file_permission_results)
	with common.term.location(0,common.term.height):
		common.logger.log(common.HEADER_ISSUES_LEVEL, "FILE PERMISSION ISSUES")
	if not any(isinstance(x, terminalPrint) for x in file_permission_results):
		common.logger.info(" No issues to report")
	for item in file_permission_results:
		if isinstance(item, terminalPrint):
			if item.getLevel() == Severity.INFO:
				common.logger.info(item.getData())
			if item.getLevel() == Severity.WARNING:
				common.logger.warning(item.getData())
			if item.getLevel() == Severity.ERROR:
				common.logger.error(item.getData())
			if item.getLevel() == Severity.VULNERABILITY:
				common.logger.log(common.VULNERABILITY_LEVEL,item.getData())


	webview_results = web_view_queue.get()
	report.writeSection(report.Section.WEBVIEW, webview_results)
	with common.term.location(0,common.term.height):
		common.logger.log(common.HEADER_ISSUES_LEVEL, "WEB-VIEW ISSUES")
	if not any(isinstance(x, terminalPrint) for x in webview_results):
		common.logger.info(" No issues to report")
	#webview_results_dedup = list(set(webview_results))
	for item in webview_results:
		if isinstance(item, terminalPrint):
			if item.getLevel() == Severity.INFO:
				common.logger.info(item.getData())
			if item.getLevel() == Severity.WARNING:
				common.logger.warning(item.getData())
			if item.getLevel() == Severity.ERROR:
				common.logger.error(item.getData())
			if item.getLevel() == Severity.VULNERABILITY:
				common.logger.log(common.VULNERABILITY_LEVEL,item.getData())


except Exception as e:
	common.logger.error("Unexpected error: " + str(e))

#Look for TapJacking vulnerabilities
#Native protection was added in API v. 9, so previous likely vulnerable
if common.minSdkVersion >8:
	common.logger.debug("Beginning TapJacking testing")
	findTapJacking.start(common.sourceDirectory)
else:
	common.logger.log(common.VULNERABILITY_LEVEL,"Since the minSdkVersion is less that 9, it is likely this application is vulnerable to TapJacking. QARK made no attempt to confirm, as the protection would have to be custom code, which is difficult for QARK to examine and understand properly. This vulnerability allows a malicious application to lay on top of this app, while letting the key strokes pass through to the application below. This can cause users to take unwanted actions, within the victim application, similar to Clickjacking on websites. Please select the appropriate options in the exploitation menus to verify manually using QARK's exploit APK. Note: The QARK proof-of-concept is transparent, but in real-world attacks, it would likely not be. This is done solely to aid in testing. For more information: https://media.blackhat.com/ad-12/Niemietz/bh-ad-12-androidmarcus_niemietz-WP.pdf")


###########
#Look for Content Provider issues
if len(common.text_scan(common.java_files,cp_imp_rex)) > 1:
	common.logger.info("Content Providers appear to be in use, locating...")
	cp_dec_list=contentProvider.find_content_providers()
	cp_dec_list=filter(None,cp_dec_list)
	cp_dec_list=common.dedup(cp_dec_list)

	common.logger.info("FOUND " + str(len(cp_dec_list)) + " CONTENTPROVIDERS:")
	for p in cp_dec_list:
		common.logger.info(str(p))

	query_rex=r'\.query\(.*\)'
	update_rex=r'\.update\(.*\)'
	delete_rex=r'\.delete\(.*\)'
	insert_rex=r'\.insert\(.*\)'
	#TODO - Add SQLi checks
	#VERY LAME SQL INJECTION DETECTION (GUESSING)
	statement_list=[]
	statement_list.append([])
	for p in cp_dec_list:
		if len(p)>1:
			statement_list+=common.text_scan([p[1]],query_rex)
			statement_list+=common.text_scan([p[1]],update_rex)
			statement_list+=common.text_scan([p[1]],delete_rex)
			statement_list+=common.text_scan([p[1]],insert_rex)
	if len(cp_dec_list)>0:
		common.logger.info("The Content Providers above should be manually inspected for injection vulnerabilities.")
try:
	#TODO - This is a pain in the ass and incomplete
	content_provider_uri_permissions()
except Exception as e:
	common.logger.error("Unable to parse Content Provider permissions. Error: " + str(e))


for item in list(common.parsingerrors):
	report.write("parsingerror-issues-list",item,"strong")

#reporting number of vulns before ading ADB commands
report.write_counters()

common.print_terminal_header("ADB EXPLOIT COMMANDS")

for a in common.xmldoc.getElementsByTagName('manifest'):
	if 'package' in a.attributes.keys():
		common.package_name=a.attributes['package'].value


try:

	if ((prov_exp_list is not None) or (act_exp_list is not None) or (actalias_exp_list is not None) or (serv_exp_list is not None) or (rec_exp_list is not None)):
		common.logger.info("Until we perfect this, for manually testing, run the following command to see all the options and their meanings: adb shell am. Make sure to update qark frequently to get all the enhancements! You'll also find some good examples here: http://xgouchet.fr/android/index.php?article42/launch-intents-using-adb")
		try:

			show_exports(prov_exp_list,'provider')
			show_exports(act_exp_list,'activity')
			show_exports(actalias_exp_list,'alias')
			show_exports(serv_exp_list,'service')
			show_exports(rec_exp_list,'receiver')

			print "\nTo view any sticky broadcasts on the device:"
			print "adb shell dumpsys activity| grep sticky\n"

			common.logger.info("Support for other component types and dynamically adding extras is in the works, please check for updates")

		except Exception as e:
			common.logger.error("Problem running show_exports in qark.py: " + str(e))
	else:
		print "Sorry, nothing exploitable via ADB"
except Exception as e:
	common.logger.error("Unfortunately, we were unable to print out the ADB commands for exploitation: " + str(e))

#TODO - return line of code for bugs
while True:
	try:
		if common.interactive_mode:
			print common.term.cyan + common.term.bold + str(common.config.get('qarkhelper','EXPLOIT_CHOICE')).decode('string-escape').format(t=common.term)
			exploit_choice =int(raw_input(common.config.get('qarkhelper','ENTER_YOUR_CHOICE')))
			if exploit_choice in (1,2):
				break
			else:
				common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION_INTERACTIVE'))
		else:
			if int(common.args.exploit) in (0,1):
				exploit_choice = int(common.args.exploit)
				break
			else:
				common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION'))
				common.exitClean()
	except Exception as e:
			if not common.interactive_mode:
				common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION'))
				exit()
			common.logger.error(common.config.get('qarkhelper','NOT_A_VALID_OPTION_INTERACTIVE'))

if exploit_choice ==1:
	# Exploit all vulnerabilities
	print "Generating exploit payloads for all vulnerabilities"
	type_list=['String','StringArray','StringArrayList','Boolean','BooleanArray','Int','Float','Long','LongArray','[]','','IntArray','IntegerArrayList','FloatArray','Double','Char','CharArray','CharSequence','CharSequenceArray','CharSequenceArrayList','Byte','ByteArray', 'Bundle','Short','ShortArray','Serializable','Parcelable','ParcelableArrayList','ParcelableArray','unknownType']
	shutil.rmtree(common.getConfig("rootDir") +'/build')
	if str(createSploit.copy_template(common.getConfig("rootDir") + '/exploitAPKs/qark/',common.getConfig("rootDir") + '/build/qark')) is not 'ERROR':
		common.exploitLocation = common.getConfig("rootDir") + '/build/qark'
		if len(prov_exp_list)>0:
			common.logger.info("Sorry, we're still working on the providers")
		if len(act_exp_list)>0:
			common.normalizeActivityNames(act_exp_list,filters.find_package())
			for i in act_exp_list:
				common.logger.debug(str(i))
				exploit = createExploit.exploitActivity()
				print str(i)
				extras_list=[]
				entries=common.get_entry_for_component('activity')
				for n in entries:
					tmp_extra=findExtras.find_extras(str(i),n)
					if tmp_extra not in type_list:
						if tmp_extra not in extras_list:
							extras_list+=tmp_extra
				common.dedup(extras_list)
				if re.match(r'^\..*',str(i)):
					i=str(common.package_name)+str(i)
				exploit.setExportedActivity(str(i))
				for j in range(0,len(extras_list)):
					extras_list[j] = str(extras_list[j]).replace('\"','')
					bad_extras=["\"\"","\" \"","[]"]
					#if (extras_list[j]==" " or extras_list[j]==""):
					if extras_list[j] in bad_extras:
						pass
					elif extras_list[j] in type_list:
						pass
					else:
						exploit.setExtra(extras_list[j])
				try:
					writeExploit.write(exploit)
				except Exception as e:
					common.logger.error("Problems creating exploit (activity): " + str(e))
		if len(actalias_exp_list)>0:
			common.logger.info("Sorry, we're still working on Activity Aliases")
		if len(serv_exp_list)>0:
			for i in range(0, len(serv_exp_list)):
				exploit = createExploit.exploitService()
				exploit.setIntent(filters.find_package() + serv_exp_list[i])
				writeExploit.write(exploit)
		if len(rec_exp_list)>0:
			for i in range(0, len(rec_exp_list)):
				exploit = createExploit.exploitReceiver()
				action=filters.find_intent_filters(rec_exp_list[i],"receiver")
				exploit.setIntent(action)
				print rec_exp_list[i]
				extras_list=[]
				entries=common.get_entry_for_component('receiver')
				for n in entries:
					tmp_extra=findExtras.find_extras(rec_exp_list[i],n)
					if tmp_extra not in type_list:
						if tmp_extra not in extras_list:
							extras_list+=tmp_extra
				common.dedup(extras_list)
				if len(common.sploitparams)==0:
					for j in range(0,len(extras_list)):
						extras_list[j] = extras_list[j].replace('\"','')
						if (extras_list[j]==" " or extras_list[j]==""):
							pass
						else:
							exploit.setExtra(extras_list[j])
				else:
					for j in range(0,len(common.sploitparams)):
						#exploit.setExtra((common.sploitparams[j])[0])
						if type(common.sploitparams[j]) is str:
							pass
							#exploit.setExtra(common.sploitparams[j])
						else:
							common.sploitparams[j][0] = common.sploitparams[j][0].replace('\"','')
							if (common.sploitparams[j][0]==" " or common.sploitparams[j][0]==""):
								pass
							else:
								exploit.setExtra(common.sploitparams[j][0])
				try:
					writeExploit.write(exploit)
				except Exception as e:
					common.logger.error("Problems creating exploit (receiver): " + str(e))
		sdkManager.build_apk('qark')
		if common.interactive_mode:
			install=raw_input("Do you want to install this to your device? (y/n)").lower()
		else:
			install_option = common.args.install
			if install_option:
				install = "y"
			else:
				install_option = "n"
		if install=='y':
			apkList = list_all_apk()
			for apk in apkList:
				if "com.secbro.qark" in apk:
					uninstall(str(apk).split("/")[-1].rstrip(".apk"))
			common.logger.info("Installing...")
			try:
				common.logger.info("The apk can be found in the "+common.getConfig("rootDir")+"/build/qark directory")
				subprocess.call("adb install " + common.getConfig("rootDir") + "/build/qark/app/build/outputs/apk/app-debug.apk",shell=True)
			except Exception as e:
				common.logger.error("Problems installing exploit APK: " + str(e))
		else:
			common.logger.info("The apk can be found in the "+common.getConfig("rootDir")+"/build/qark directory")
elif exploit_choice ==2:
	if common.reportInitSuccess:
		print "An html report of the findings is located in : " + common.getConfig("rootDir") + "/report/report.html"
	else:
		common.logger.error("Problem with reporting; No html report generated. Please see the readme file for possible solutions.")
	common.exitClean()
if common.reportInitSuccess:
	print "An html report of the findings is located in : " + common.getConfig("rootDir") + "/report/report.html"
else:
	common.logger.error("Problem with reporting; No html report generated. Please see the readme file for possible solutions.")

print "Goodbye!"
raise SystemExit

