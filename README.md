BGPmon-Parser
=============

Description: simple script written in perl for BGPmon. Parser uses LibXML library and parses XML streams (both update and RIB-IN), which are generated by BGPmon.

File:		BGPmon-Parser-0.1.pl

Version:	0.1

Authors:	Mikhail Strizhov, He Yan

Contacts:	strizhov@cs.colostate.edu

Date:		December 16th, 2010


Requirements:          
		libXML 
		XML::LibXML

Usage:		./BGPmon-Parser-0.1.pl IPADDRESS PORT
Example:	./BGPmon-Parser-0.1.pl livebgp.netsec.colostate.edu 50001

Description:    
		BGPMon XML client (DOM based)

Output Format:

Timestamp|Source IPaddress|Source AS|Destination IPaddress|Destination AS|AS Path|List of Prefixes|Message Flag

Available Message Flags:

WITH - update message containing a list of prefixes withdrew from a peer.
SPATH, DPATH, NANN, DANN - should be considered as announce message with AS path and list of prefixes.

Example output:

1292545766|128.223.51.15|6447|82.143.24.1|29449|125.167.122/23 63.211.68/22|WITH
1292545766|128.223.51.15|6447|82.143.24.1|29449|29449 8928 3356 701 32528|130.36.35/24 130.36.34/24|DPATH
1292545767|2001:468:d01:33::80df:3370|6447|2001:240:100:ff::2497:2|2497|2497 6453|32.2/16|DPATH

