

INSTALLATION (v0.2): 
	- Run script with install option "install" like: "python main.py install"
USAGE (v0.2):
    - Edit FMC related information at the beginning of the script using variables:
    	FMC_host  = <place fmc fqdn or IP address here for ssh>
		FMC_login = <place username with cli/ssh access to FMC here>
		FMC_passw = <you can permanently save password in this variable, or modify this script to use key file authentication, by default you need to interactively put password for FMC login at runtime>
	- Place XML reports from MaxPatrol into "reports folder" and run the script like: "python main.py"
	- Wait for script to finish, read output log if needed 

RELEASE NOTES:

v0.2:
	
	1) Totally rebuilt and automated installation process and file transfer to FMC and remote command execution. No need to connect to FMC anymore, just run the script and you're done. 
	2) Limited line count for single output file to 100 to not overwhelm the API. Fixes problem of not all the scan results been imported in big output files.
	3) Fixed Import API to correctly import OS from scan results. Installer need to be run on FMC with new "installer.zip" file to take effect.


	Roadmap:
	1) Decide what to do with Apps Import as they are not tied to protocols and may be used only for audit purpose
	2) Import Server Services mappings
	3) Built-in choise for key authentication on FMC.
	4) Miscellaneous imrovements

v0.1:

	Installation:
	Detailed video step-by-step manual (for v0.1, see release notes v0.2 for changes): https://youtu.be/6M5lg82aECc

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

	Features:

	1) Correctly imports Vulnerability Scan results for hosts;
	2) UTF8 Scan results import and display on FMC;
	3) CVSS Score added to Title;
	4) Not currently maps OS;
	5) Not currently maps Client/Server services;

*IMPORTANT NOTICE* This integration is not covered by Cisco TAC or BU Support and is absolutely enthusiastic.