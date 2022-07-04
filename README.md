# F5
Sharing some tools for designed for F5 appliances.<br>

<b>bigipParser</b>: This tool, is a bash script and can be used for to extract each virtual server configurations into the individual separate files. The files contain whole virtual server configurations with all dependent configurations like pools monitors, iRules, policies and etc. However, there are some limitations. This script can only detects LTM objects, so will be disappointed if you need to export ASM (AWAF), APM, DNS (GTM) related virtual server configuraitons. This script supports versions up to BIG-IP version 16. I did not use it with newer versions like ver. 17 or 18 yet but i believe there will be no major issues.<br>
<br>
<b>F5_APM_RDP_SessionPersistence.iRule</b>: This is an iRule which can be used to load balance MS-RDP connections created on APM policy. Because, when APM policy used SSO within a MS-RDP session, there is no way to see username information so you can not create a persistanceo on LTM side especially when APM and LTM runs on different appliances. You can find actual story behind this iRule with searching the key words (APM SSO breaks RDP persistence) on "community.f5.com". (https://community.f5.com/t5/technical-forum/apm-sso-breaks-rdp-persistence/td-p/224456)
<br>
