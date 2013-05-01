#!/usr/bin/perl

# =====================================================================
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
# 
# Copyright (c) 2009-2012 Colorado State University
# All rights reserved.
# 
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom
# the Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# 
# File:    BGPmon-Parser-0.1.pl
# Version: 0.1
# Authors: Mikhail Strizhov, He Yan
# Contacts: strizhov@netsec.colostate.edu
# Date:    December 16th, 2010
#
# Requirement:          
#          libXML 
#          XML::LibXML
#
# Usage:   ./BGPmon-Parser-0.1.pl IPADDRESS PORT
# Example: ./BGPmon-Parser-0.1.pl livebgp.netsec.colostate.edu 50001
#
# Description:    
#          BGPMon XML client (DOM based)
#
# =====================================================================

$| = 1;

use IO::Select;
use IO::Socket;
use XML::LibXML;

###
### Initialize global system variables
###
chdir $Bin;
my $_PROG_NAME = "$0";
my %_SOCKET_BUFFER    = ();

###
### Initialize global system constants
###
my $_VERSION = "0.2";
my $_SOCKET_TIMEOUT  = 10 * 60;  # 10 minutes timeout
my $_SOCKET_READLEN  = 512;      # 512 characters per read
my $_MAX_BUFFER_SIZE = 4  * 1024 * 1024; # 2M

###
### Initialize global user variables
###
my $_SERVER_ADDR  =  $ARGV[0];
my $_SERVER_PORT  = $ARGV[1];

if ($_SERVER_ADDR eq undef)
{
    print "Need to enter IP address\n";
    exit;
}
if ($_SERVER_PORT eq undef)
{
    print "Need to enter port number\n";
    exit;
}
main();

exit;

### =====================================================================
### Function
### =====================================================================
sub main {
    
    #---------------------------------------------------------------
    # Infinite loop
    #---------------------------------------------------------------
    use bigint;

    for (my $i=1; ;$i++)
    {
        my $sock, $sel, @ready;
        eval
        {
            #-------------------------------------------------------
            # Connect to server
            #-------------------------------------------------------
            $sock = new IO::Socket::INET ( PeerAddr  => $_SERVER_ADDR,
                                           PeerPort  => $_SERVER_PORT,
                                           Proto => 'tcp',
                                         ) or die "Could not create socket to $_SERVER_ADDR:$_SERVER_PORT: $!\n";
            $sel  = new IO::Select($sock);

            #-------------------------------------------------------
            # Receive xml stream
            #-------------------------------------------------------
            # Loop with timeout 
            while(@ready = $sel->can_read($_SOCKET_TIMEOUT)) 
            {
                #-----------------------------
                # Read from socket
                #-----------------------------
                foreach my $fh (@ready) 
                {
                    my $text      = "";
                    my $xml_line  = "";
            
                    # There are three possible return values for sysread
                    # http://perldoc.perl.org/functions/sysread.html
                    my $readlen = sysread($fh, $text, $_SOCKET_READLEN);

                    if    ($readlen >  0) { $_SOCKET_BUFFER{$fh} .= $text; }                 # (1) success 
                    elsif ($readlen == 0) { die "Socket closed by server $_SERVER_ADDR\n"; } # (2) end of socket # Raise exception
                    else                  { die "Socket error $!\n";                       } # (3) error         # Raise exception

                    # Safety check
                    if (length($_SOCKET_BUFFER{$fh}) > $_MAX_BUFFER_SIZE)
                    {
                        die "Message size too large\n";
                    }

                    # Process the open tab <xml> or <BGP_MESSAGES>
                    if ( $_SOCKET_BUFFER{$fh} =~ /^\s*(<xml[^>]*>|<BGP_MESSAGES[^>]*>)\s*(.*)/s )
                    {
                        $_SOCKET_BUFFER{$fh} = $2;
                        $xml_line = $1;
                    }

                    # Extract each following BGP_MESSAGE
                    if ( $_SOCKET_BUFFER{$fh} =~ /^\s*(<BGP_MESSAGE.*?<\/BGP_MESSAGE>)\s*(.*)/s )
                    {
                        $xml_line            = $1;
                        $_SOCKET_BUFFER{$fh} = $2;

                        ### Example processing code
                        &parsing_example($xml_line);
                    }
                }
            }
            # Reach here if timeout
            die "Timeout";
        };
        if ( $@ )
        { # There is an error
            chomp($@);

            print $@;

            # clear socket
            close($sock) if ($sock);
            undef $sock;
            undef $sel;

            # clear buffer
            foreach my $fh (keys %_SOCKET_BUFFER)
            {
                delete $_SOCKET_BUFFER{$fh};
            };
            %_SOCKET_BUFFER = ();
        }
        sleep(5);
    }
}

sub parsing_example
{
    &parsing_example_0_1(@_);
}

sub parsing_example_0_1
{
    my ($xml_string) = @_;

    ###
    ### Parse XML message
    ###
    my $parser = XML::LibXML->new();
    my $tree = $parser->parse_string($xml_string);

    ###
    ### Setup pointers to elements
    ###
    my $bgp_message      = $tree->getDocumentElement;

    ### Check message version
    my $version = $bgp_message->getAttribute("version");
    die "ERROR: Expecting version '0.1', but receiving '$version'\n" if ($version ne $_VERSION);

    ### Check type, 3 is update message, 4 is table message
    ### Ignore other types
    my $type = $bgp_message->getAttribute("type_value");
    if (($type != 3) && ($type !=4))
    {
    	undef $parser;
	return undef;
    }
    ###
    ### TIME
    ###
    my ($time_node)      = $bgp_message->getElementsByTagName('TIME');
    my ($timestamp_node) = $time_node->getElementsByTagName("TIMESTAMP");
    
    ###
    ### PEERING
    ###
    my ($peering_node)   = $bgp_message->getElementsByTagName('PEERING');
    # Next if peering node doesn't exists
    return undef if (not $peering_node);
    
    print $timestamp_node->textContent, "|";
    my ($src_as_node)    = $peering_node->getElementsByTagName('SRC_AS');
    my ($dst_as_node)    = $peering_node->getElementsByTagName('DST_AS');
    my ($src_addr_node)  = $peering_node->getElementsByTagName('SRC_ADDR');
    my ($dst_addr_node)  = $peering_node->getElementsByTagName('DST_ADDR');


    # print Source Address
    if ($src_addr_node)
    {
        print $src_addr_node->textContent, "|";
    }
    # print Source AS number
    if ($src_as_node)
    {
        print $src_as_node->textContent, "|";
    }
    # print Destination Address
    if ($dst_addr_node)
    {
        print $dst_addr_node->textContent, "|";
    }
    # print Destionation AS number
    if ($dst_as_node)
    {
        print $dst_as_node->textContent, "|";
    }

    # test
    #return  if ($dst_as_node->textContent != 852);	

    ###
    ### ASCII message
    ###
    my ($ascii_msg_node) = $bgp_message->getElementsByTagName('ASCII_MSG');

    ###
    ### Parse WITHDRAWN
    ###
    my $with_flag = 0;

    my ($wh_node) = $ascii_msg_node->getElementsByTagName('WITHDRAWN') if ($ascii_msg_node);
    if ($wh_node)
    {
#        print "WITHDRAWN:\n";
	my $label="";
        my @prefixes  = $wh_node->getElementsByTagName('PREFIX');
	my $count = 0;
	my $arrsize = scalar (@prefixes);
        foreach my $prefix (@prefixes)
        {
		$label = $prefix->getAttribute("label");
		$count = $count + 1;
		if ($count != $arrsize)
		{
			printf("%s ", $prefix->textContent);
		}
		else
		{
			printf("%s", $prefix->textContent);
		}
        }
	if ($label)
	{
		printf("|%s", $label);
	}
	$with_flag = 1;
    }

    ###
    ### Parse ATTRIBUTES
    ###
    if ($with_flag != 0)
    {
	my @ases="";

	my ($pa_node) = $ascii_msg_node->getElementsByTagName('PATH_ATTRIBUTES') if ($ascii_msg_node);
	if ($pa_node)
	{
#        print "ATTRIBUTES:\n";
        	my @attr  = $pa_node->getElementsByTagName('ATTRIBUTE');
	        foreach my $attr (@attr)
	        {
		        my ($type_node)  = $attr->getElementsByTagName('TYPE');
			my $type = $type_node->textContent;

			my $value   = "";
			if ($type eq "ORIGIN") 
			{
				my ($value_node) = $attr->getElementsByTagName('ORIGIN');
				$value = $value_node->textContent;
            		}
			elsif ($type eq "NEXT_HOP")
			{
            			my ($value_node) = $attr->getElementsByTagName('NEXT_HOP');
				$value = $value_node->textContent;
				#print $value, "|";
			}
			elsif ($type eq "MULTI_EXIT_DISC")
			{
				my ($value_node) = $attr->getElementsByTagName('MULTI_EXIT_DISC');
				$value = $value_node->textContent;
			}
			elsif ($type eq "AS_PATH")
			{
				#look for tag "AS_SEG"
				#then look for tag "AS"
				my @as_seg = $attr->getElementsByTagName('AS_SEG');
#				print $as_seg . "\n";
#                		my @as = $as_seg->getElementsByTagName('AS')->textContent;
#				print join (" ", @as)."\n";
#                		$value = join(" ", map {$_->textContent} @as);
		                @ases = $as_seg[0]->getElementsByTagName('AS');
        			my $value="";
				my $count = 0;
				my $arrsize = scalar (@ases);
				foreach my $as (@ases)
				{
					$count = $count + 1;
					if ($count != $arrsize)
					{
						$value .= $as->textContent." ";
					}
					else
					{
						$value .= $as->textContent;
					}
				}
				print $value . "|";
			}
			elsif ($type eq "COMMUNITIES")
			{
				my @cu = $attr->getElementsByTagName('COMMUNITY');
				$value = join(" ", map {
                                         join(":",
                                              ($_->getElementsByTagName("AS"))[0]->textContent,
                                              ($_->getElementsByTagName("VALUE"))[0]->textContent
                                             )
                                       } @cu);
            		}
            		else
            		{
		                # Parse attributes
                		$value = "NOT PARSED IN DEMO CODE";
            		}

 #           print " "x4 , sprintf("%-20.20s: %s\n", $type, $value);
        	}
    	}
    

    	###
	### Parse NLRI
	###

	my ($nlri_node) = $ascii_msg_node->getElementsByTagName('NLRI') if ($ascii_msg_node);
	if ($nlri_node)
	{
#        print "NLRI:\n";
		my @prefixes  = $nlri_node->getElementsByTagName('PREFIX');
		my $label="";
		my $count = 0;
		my $arrsize = scalar (@prefixes);
		foreach my $prefix (@prefixes)
		{
			$count = $count + 1;
			$label = $prefix->getAttribute("label");
			if ($count != $arrsize)
			{

				printf("%s ", $prefix->textContent);
			}
			else
			{
				printf("%s", $prefix->textContent);
			}

		}
		if ($label)
		{
			printf("|%s", $label);
		}
	}
    ### Release parser
    }

###
### Uncomment to print OCTETS in HEX
###
#    my ($octets_msg_node) = $bgp_message->getElementsByTagName('OCTET_MSG');
#    my ($octets)    = $octets_msg_node->getElementsByTagName('OCTETS');
#    if ($octets)
#    {
#        printf("|%s", $octets->textContent );
#    }


    print "\n";
    undef $parser;
}

