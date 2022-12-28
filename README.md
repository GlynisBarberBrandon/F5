# F5
Sharing some tools designed for F5 appliances.<br>

<b>bigipParser</b>: This tool, is a bash script and can be used for to extract each virtual server configurations into the individual separate files. The files contain whole virtual server configurations with all dependent configurations like pools monitors, iRules, policies and etc. However, there are some limitations. This script can only detects LTM objects, so will be disappointed if you need to export ASM (AWAF), APM, DNS (GTM) related virtual server configuraitons. This script supports versions up to BIG-IP version 16. I did not use it with newer versions like ver. 17 or 18 yet but i believe there will be no major issues.<br>
<br>
<b>F5_APM_RDP_SessionPersistence.iRule</b>: This is an iRule which can be used to load balance MS-RDP connections created on APM policy. Because, when APM policy used SSO within a MS-RDP session, there is no way to see username information so you can not create a persistanceo on LTM side especially when APM and LTM runs on different appliances. You can find actual story behind this iRule with searching the key words (APM SSO breaks RDP persistence) on "community.f5.com". (https://community.f5.com/t5/technical-forum/apm-sso-breaks-rdp-persistence/td-p/224456)
<br><br>
<b>APM_Policy_extractor.sh</b>: This shell script can be used for extracting APM policies from ucs or qkview files. There is a better way as you probably know which can be used as exporting / importing purposes. But this method ("https://techdocs.f5.com/kb/en-us/products/big-ip_apm/manuals/product/apm-implementations-12-1-0/21.html") requires to have either the ucs file which contains APM policy or access the actual f5 that have intended APM policy. Sometimes you only have a qkview file and you desperately need to look an APM policy. This tool can be your solution to your needs. But i have to warn you that this script can only be useful if you handle all those dependencies in custiomizations. 
Script provides two files which contains actual APM policy tree and relevant customizations. You can start with the placing the  customizations and then try to import APM policy with tmsh ("load sys config from-terminal merge") way. Couple of times i used this script and got success but i admit that was take too much time because there was many errors coming from dependants.
<br><br>
<b>nstoF5</b>: This script aims to transform a Netscaler virtual server configuration and its corresponding contents to F5 configuration. Before going any further, you must be aware of some crucial points. First of all, it was designed to transform Netscaler virtual server configuration files to F5 virtual server configurations. This script uses seperate files that contains Netcaler virtual server configurations as an input. It is not designed to read whole "ns.conf" file. The seperated virtual server configuration files provided by another project which is created by "Carl Stalhood". ("https://github.com/cstalhood/Get-ADCVServerConfig/blob/master/Get-ADCVServerConfig.ps1" and "https://www.carlstalhood.com/netscaler-scripting/") Thanks to him for all his efforts. Because his efforts made this conversion job a lot easier. 

On the other hand, I've added some lines to support special needs to fits only my case so please be prepared to modify some lines to get better conversions.

The script doesn't aim to support every single feature exist on Netscaler. It only supports to conversion for well known generic features like Vs (name, destination, tcp/udp) definition, pool, persistence, monitor(s), cache, compression, certificate profiles.
<br><br>
<b>DNS_queryLogger.tcl:</b> is an iRule that aims to send DNS requests as logs to remote server. Basically, there is a better way to achieve this if you have DNS license on your F5 devices. But if you don't have a DNS license you have to use another solution which is why i created this iRule.<br><br>
<b>findPool.sh:</b> This scripts designed to find pools used in iRules. Basically you need two parameters. The first parameter is the path of "bigip.conf" and the second is the pool name you're looking for.<br><br>
<b>findSslVs.sh:</b> This script searches for virtual servers in "bigip.conf" file that doesn't have any client-ssl profile attached. First parameter is the path of "bigip.conf" file as always.
