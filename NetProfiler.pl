#!/usr/bin/perl -w

##      Net Profile
##      Copyrighted:  Justin M. Wray (wray.justin@gmail.com)
##
##    This program is free software: you can redistribute it and/or modify
##    it under the terms of the GNU General Public License as published by
##    the Free Software Foundation, either version 3 of the License, or
##    (at your option) any later version.
##
##    This program is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##    GNU General Public License for more details.
##
##    You should have received a copy of the GNU General Public License
##    along with this program.  If not, see <http://www.gnu.org/licenses/>.

##  On Ubuntu?  Use This To Install Dependencies:
##      sudo apt-get install liblist-allutils-perl libdatetime-perl libnet-pcap-perl libnetpacket-perl perl-doc libnet-dns-perl libnet-dns-async-perl libnet-dns-sec-perl libnet-whois-parser-perl

##  Standard Libraries
use strict;
use warnings;
use diagnostics;
use Getopt::Long;
use List::MoreUtils;
use DateTime;
use File::Basename;
use Pod::Usage;
use Data::Dumper;

##  Libraries (Dependencies)
use Net::Pcap qw( :functions );
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;

##  Version
our $program = basename($0);
our $version = "0.04";

##  Global Variables
our $debug = 0;
our $interface = "eth0";
our $filterFile;
our $pcapFile;
our $outputFile;
our $pcapSnapLen = "512";
our $pcapPromisc = "1";
our $pcapTimeout = "1";
our $switchDirection = 0;
our $packetCount = 0;
our $packetLimit = 100;
our $connectionLimit = 100;
our $clientLimit = 100;
our $pcapObj;
our %connections;
our @finalFilter;
our $filter;
our $exit = 0;
$| = 1;

##  Capture Exit
$SIG{'INT'} = sub {
        $| = 1;
        if ($exit == 0) {
                $exit = 1;
                print "Quiting at Users Request...\n";
                quit();
        };
};

##  Options
GetOptions (
        "interface|i=s" => \$interface,
        "filter|f=s" => \$filterFile,
        "file|r=s" => \$pcapFile,
        "packets|p=i" => \$packetLimit,
        "connection-limit|x=i" => \$connectionLimit,
        "client-limit|c=i" => \$clientLimit,
        "switch|s" => \$switchDirection,
        "write|w=s" => \$outputFile,
        "debug|d" => \$debug,
        "version" => sub { displayVersion(); },
        "h" => sub{ displayUsage(); },
        "help" => sub{ displayHelp(); }
) or displayUsage();

##  Usage Subroutine
sub displayUsage {
        pod2usage();
        quit();
};

##  Help Subroutine
sub displayHelp {
        pod2usage({ -verbose => 2, -exitval => 0 });
        quit();
};

##  Help Subroutine
sub displayVersion {
        print "$program - $version\n";
        quit();
};

##  Error Subroutine
sub throwError {
        my $message = $_[0];
        my $forceExit = 0;
        $forceExit = $_[1];
        print "[ERROR] $message\n";
        if ($forceExit) {
                exit;
        } else {
                quit();
        };
};

##  Cleanup & Exit Subroutine
sub quit {
        if (defined($pcapObj)) {
                print "Ending PCAP Processing Loop:  ";
                pcap_breakloop($pcapObj);
                print "Done\n";
                print "Closing PCAP Handler:  ";
                Net::Pcap::close($pcapObj);
                print "Done\n";
                undef($pcapObj);
        };
        if (@finalFilter) {
                print "Building Final Filter, Please Wait...\n";
                outputFilter();
        };
        exit;
};

##  Main Subroutine
sub main {
        $| = 1;
        $pcapObj = openPCAP();
        setupFilter();
        Net::Pcap::loop($pcapObj, -1, \&processPackets, '') || throwError("Unable to Start Capture");
};

##  Open PCAP Subroutine
sub openPCAP {
        my $error;

        if (defined($pcapFile)) {
                $pcapObj = Net::Pcap::open_offline($pcapFile, \$error);
        } else {
                $pcapObj = Net::Pcap::open_live($interface, $pcapSnapLen, $pcapPromisc, $pcapTimeout, \$error);
        };

        if (!defined($pcapObj)) {
                throwError($error);
        } else {
                return $pcapObj;
        }
};

##  Setup Filter Subroutine
sub setupFilter {
        if (defined($filterFile)) {
                open(FILTER, $filterFile) or newFilter();
                my @loadedFilter = <FILTER>;
                close(FILTER);
                foreach my $fileLine (@loadedFilter) {
                        $fileLine =~ s/ and not //g;
                        if ($fileLine =~ /\w/) { push (@finalFilter, $fileLine); };
                };
                applyFilter();
        } else {
               newFilter(); 
        };
};

##  New Filter Subroutine
sub newFilter {
        print "NEW FILTER\n";
        #push(@finalFilter,"tcp and tcp[13] == 18");
        #push(@finalFilter,"tcp and tcp[13] == 2");
        push(@finalFilter,"tcp");
        applyFilter();
};

##  Packing Processing Subroutine
sub processPackets {
        my ($userData, $packetHeader, $packetData) = @_;
        my ($protocol, $payload, $srcIP, $srcPort, $dstIP, $dstPort, $flags);

        my $etherData = NetPacket::Ethernet::strip($packetData);
        my $ipData = NetPacket::IP->decode($etherData);

        if ($ipData->{proto} == 6) {
                my $tcpData = NetPacket::TCP->decode($ipData->{'data'});

                $srcIP  = $ipData->{src_ip};
                $dstIP = $ipData->{dest_ip};      
                $protocol = "TCP";
                $srcPort = $tcpData->{src_port};
                $dstPort = $tcpData->{dest_port};
                $payload = $tcpData->{data};

                my $timestamp = DateTime->from_epoch( epoch => $packetHeader->{tv_sec} );
                if ($debug) { printf "[Packet:  %5d] ", $packetCount; };
                print "[", $timestamp->date, " - ", $timestamp->time, "] $srcIP:$srcPort -> $dstIP:$dstPort\n";

                if ($switchDirection) {
                        $connections{$dstIP}{$dstPort}{$srcIP}++;
                } else {
                        $connections{$srcIP}{$srcPort}{$dstIP}++;
                };
                $packetCount++;

                if ($packetCount == $packetLimit) {
                        $packetCount = 0;
                        buildFilter();
                        applyFilter();
                };
        };
};

##  Build Filter Subroutine
sub buildFilter {
        foreach my $serverIP ( keys %connections ) {
                if ($debug) { print "Server: $serverIP, Port-Count: ", scalar keys $connections{$serverIP}, "\n"; };
                foreach my $serverPort ( keys $connections{$serverIP} ) {
                        if ($debug) { print "\tPort: $serverPort, Client-Count: ", scalar keys $connections{$serverIP}{$serverPort}, "\n"; };
                        if (scalar keys $connections{$serverIP}{$serverPort} >= $clientLimit) { push(@finalFilter,"(host $serverIP and port $serverPort)"); };
                        foreach my $clientIP ( keys $connections{$serverIP}{$serverPort} ) {
                                if ($debug) { print "\t\tClient: $clientIP, Connections: ", $connections{$serverIP}{$serverPort}{$clientIP}, "\n"; };
                                if ($connections{$serverIP}{$serverPort}{$clientIP} >= $connectionLimit) { push(@finalFilter,"(host $serverIP and host $clientIP and port $serverPort)"); };
                        };
                };
        };
        @finalFilter = List::MoreUtils::uniq(@finalFilter);
};

##  Apply Filter Subroutine
sub applyFilter {
        if (@finalFilter) {
                my $filterString = join(" and not ", @finalFilter);
                if ($debug) { print "Current Filter:  $filterString\n"; };
                pcap_compile($pcapObj, \$filter, $filterString, 1, 0) == 0 or throwError("Filter Compile Failed");
                pcap_setfilter($pcapObj, $filter) == 0 or throwError("Setting Filter Failed");
                pcap_freecode($filter);
                print "FILTER UPDATED:  ", ($#finalFilter + 1), " filter(s) loaded\n";
        };
};

##  Output Filter Subroutine
sub outputFilter{
        if (@finalFilter) {
                @finalFilter = List::MoreUtils::uniq(@finalFilter);
                my $filterString = join("\n and not ", @finalFilter);
                if (defined($outputFile)) {
                        open(OUTPUT, ">$outputFile") or throwError("File Output Failed",1);
                        print OUTPUT "$filterString\n";
                        close(OUTPUT)
                };
                print "$filterString\n";
        };
};

##  Run
main();
quit();

__END__

=head1 NAME

NetProfiler - Build Network Profile Filter

=head1 SYNOPSIS

    NetProfile
        -i, --interface,          Network Capture Interface (ethX)
	-f, --filter,             Network Capture Filter (BPF)
	-r, --file,               Network Capture File (PCAP)
        -p, --packets             Number of Packets before Filter Processing (Interval)
        -x, --connection-limit    Number of Connections before Server-Client-Port is Filtered
        -c, --client-limit        Number of Clients before Server-Port is Filtered
        -s, --switch              Switch Traffice Direction
        -w, --write               Output Filter File (BPF)
        -d, --debug               Verbose/Debug Output
	-h, --help,               Help Output (This Message)
        --version,                Output Version Information

=head1 OPTIONS

=over

=item B<-i>, B<--interface>  I<device>

Network interface I<device> in which NetProfiler will start capturing and profiling.
If no interface is provided, NetProfiler will use "eth0" as the default.

=item B<-f>, B<--filter>  I<file>

PCAP filter I<file> (BPF) in which NetProfiler will use, to filter, the traffic it is analyzing.
By default NetProfiler is only going to filter for SYN-ACK packets, no other filtering will take place.

=item B<-r>, B<--file>  I<file>

PCAP I<file> in which NetProfiler will use, to profile, in place of a live capture.
By default this is unused, as NetProfiler will listen live.

=item B<-p>, B<--packets>  I<number>

The I<number> of packets required to be seen before the filter will be processed (built and applied).
This is an interval.  The lower the value the more often the filter is processed, but the more processing required.
The higher the value the longer the wait between the filter being processed, resulting in far more traffic, but less processing.
The default value is 100.

=item B<-x>, B<--connection-limit>  I<number>

The I<number> of connections required to be seen before server-client-port tuplet is added to the filter.
Once this value is meet the combination of the server's IP, client's IP, and service port will be added to the filter.
The default value is 100.

=item B<-c>, B<--client-limit>  I<number>

The I<number> of clients required to be seen before a server-port pair is added to the filter.
Once this value is meet the combination of the server's IP and service port will be added to the filter.
The default value is 100.

=item B<-s>, B<--switch>

Switch the direction the traffic is stored, effectivly switching who the profiler thinks is the client and who it thinks is the server.
Useful if you're seeing the Clients and Servers reversed (or doing some alternate filtering).

=item B<-w>, B<--write>  I<file>

The BPF I<file> in which NetProfiler will write out the final filter.
This file will be overwritten, choice carefully.

=item B<-d>, B<--debug>

Enabled debugging mode, which will provide verbose output.  Useful to ensure filtering the hash matches your expectations.

=back

=head1 DESCRIPTION

B<NetProfiler> builds a custom filter for your network based off of common communications.

=head1 EXAMPLES

B<NetProfiler>
        Standard execution, using all defaults.

B<NetProfiler -i eth1>
        Standard execution, using an alternate network interface device.

B<NetProfiler -w test.bpf>
        Standard execution, writing final filter out to a file named I<test.bpf>.

B<NetProfiler -f test.bpf>
        Standard execution, reading initial filter (BPF) from a file named I<test.bpf>.

B<NetProfiler -f test.bpf -w test.bpf>
        Standard execution, reading initial filter (BPF) from a file named I<test.bpf> and then writing updates to the same file.

B<NetProfiler -p 50 -c 10 -x 5 -f test.bpf -w test.bpf>
        Custom execution, reading initial filter (BPF) from a file named I<test.bpf> and then writing updates to the same file.
        Processing filter every I<50> packets.
        Filtering any Server-Port pair that has I<10> or more clients.
        Filtering any Server-Port-Client tuplet that has I<5> or more connections.

=head1 ADDITIONAL INFORMATION

If you start with no filter, B<NetProfiler> will capture and profile all I<TCP> traffic.

It is suggested that you instead start with a base filter for either I<SYN> packets or I<SYN>/I<ACK> packets.

To monitor I<SYN> packets use:
        I<tcp and tcp[13] == 2>

To monitor I<SYN>/I<ACK> packets use:
        I<tcp and tcp[13] == 18>

=head1 AUTHOR

B<Justin M. Wray>, E<lt>wray.justin@gmail.comE<gt>

=head1 COPYRIGHT
