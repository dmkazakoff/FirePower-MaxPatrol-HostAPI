Detailed video step-by-step manual: https://youtu.be/6M5lg82aECc

FMC PART (STEP #0 - Preparation - !!! First time step only !!!):

	1) Copy installer folder content (installer.sh, installer.zip) to FMC via SCP (for example to: "/Volume/home/admin/").
	2) Make installer.sh executable:
		$ chmod +x installer.sh
	3) Run installer with sudo:
		$ sudo installer.sh
	4) Go to FMC WEBGUI "Policies->Application Detectors->User Third-Party Mappings-> Create Product Map Set". Name it "MaxPatrolMap" and click Save, this is for future use.	

SCRIPT PART (STEP #1 - Operation):

	# Should be run on a separate system, not FMC, you may use any Linux server for example for ease of automation tasks.
	1) Install requirements, code uses python 2.7 version
		pip install -r requirements.txt
	2) Put your MaxPatrol Reports into "reports" folder (you can mount it to a remote share where MaxPatrol exports its XML reports for automation)
	3) Run the script main.py. After script finishes, it creates a series of files (output_XX.txt) one per scanned IP in "export" folder.

FMC PART (STEP #2 - Operation):

	1) Transfer "export" folder content (from STEP#2 point 3) to FMC "export" folder located on path "/Volume/home/admin/export" (should've been created after STEP #1)
	2) Manually run with sudo importer.sh located in "/Volume/home/admin/" directory (it will just import one by one export files from exports folder to FMC)
		$ sudo ./importer.sh

RELEASE NOTES v0.1:

	1) Correctly imports Vulnerability Scan results for hosts;
	2) UTF8 Scan results import and display on FMC;
	3) CVSS Score added to Title;
	4) Not currently maps OS;
	5) Not currently maps Client/Server services;

This integration is not covered by Cisco TAC or BU Support and is absolutely enthusiastic.