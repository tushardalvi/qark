import argparse, sys
from modules import common

__author__ = 'tdalvi'
parser = argparse.ArgumentParser(description='QARK - Andr{o}id Source Code Analyzer and Exploitation Tool')
required = parser.add_argument_group('Required')
mode = parser.add_argument_group('Mode')
advanced = parser.add_argument_group('When --source=2')
auto = parser.add_argument_group('When --source=1')
optional = parser.add_argument_group('Optional')
exploitmenu = parser.add_argument_group('Exploit Generation')
advanced_mutual = advanced.add_mutually_exclusive_group()
required_group = required.add_mutually_exclusive_group()
exploit_choice = 1

mode.add_argument("-s", "--source", dest="source", metavar='int', type=int, help="1 if you have an APK, 2 if you want to specify the source selectively")
advanced.add_argument("-m", "--manifest", dest="manifest", help="Enter the full path to the manifest file. Required only when --source==2")
auto.add_argument("-p", "--pathtoapk", dest="apkpath", help="Enter the full path to the APK file. Required only when --source==1")

advanced_mutual.add_argument("-a", "--autodetectcodepath", dest="autodetect", help="AutoDetect java source code path based of the path provided for manifest. 1=autodetect, 0=specify manually")
advanced_mutual.add_argument("-c", "--codepath", dest="codepath", help="Enter the full path to the root folder containing java source. Required only when --source==2")

optional.add_argument("-e", "--exploit", dest="exploit", help="1 to generate a targeted exploit APK, 0 to skip")
optional.add_argument("-i", "--install", dest="install", help="1 to install exploit APK on the device, 0 to skip")
optional.add_argument("-d", "--debug", dest="debuglevel", help="Debug Level. 10=Debug, 20=INFO, 30=Warning, 40=Error")
optional.add_argument("-v", "--version", dest="version", help="Print version info", action='store_true')
optional.add_argument("-r", "--reportdir", dest="reportdir", help="Specify full path for output report directory. Defaults to /report")
required_group.add_argument("-t", "--acceptterms", dest="acceptterms", help="Automatically accept terms and conditions when downloading Android SDK")
required_group.add_argument("-b", "--basesdk", dest="basesdk", help="Specify the full path to the root directory of the Android SDK")


common.args = parser.parse_args()

if len(sys.argv) > 1:
	common.interactive_mode = False

#######################################
#Command line argument sanity checks
if not common.interactive_mode:
	if not common.args.source:
		common.logger.error("Please specify source (--source=1 or --source==2)")
		exit()
	if common.args.source==1:
		if common.args.apkpath is None:
			common.logger.error("When selecting --source=1, Please provide the path to the APK via --pathtoapk flag")
			exit()
		if common.args.exploit is None:
			common.logger.error("--exploit flag missing. Possible values 0/1")
			exit()
		if int(common.args.exploit) == 1:
			if common.args.install is None:
				common.logger.error("--install flag missing. Possible values 0/1")
				exit()
	if common.args.source==2:
		if common.args.autodetect is None:
			if common.args.manifest is None or common.args.codepath is None:
				common.logger.error("When selecting --source=2, Please either pass --autodetectcodepath=1 or both --manifest and --codepath")
		if common.args.exploit is None:
			common.logger.error("--exploit flag missing. Possible values 0/1")
			exit()
		if int(common.args.exploit) == 1:
			if common.args.install is None:
				common.logger.error("--install flag missing. Possible values 0/1")
				exit()

if common.args.debuglevel is not None:
	if int(common.args.debuglevel) in range(10,60):
		common.logger.setLevel(int(common.args.debuglevel))
	else:
		parser.error("Please provide a valid Debug level (10,20,30,40,50,60)")

if common.args.version:
	common.version()

if common.args.basesdk is not None:
	common.writeKey('AndroidSDKPath', str(common.args.basesdk).strip())
