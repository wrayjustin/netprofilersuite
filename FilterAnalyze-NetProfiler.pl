#!/usr/bin/perl -w

##      Filter Analyze - Net Profile
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
use Net::DNS;
use Net::Whois::Parser;

##  Version
our $program = basename($0);
our $version = "0.02";

##  Global Variables
our $debug = 0;
our $dnsServer1 = "192.168.1.1";
our $dnsServer2 = "8.8.8.8";
our $filterFile;
our %domains;
our %orgs;
our $dnsObj;
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
        "filter|f=s" => \$filterFile,
        "dns1|1=s" => \$dnsServer1,
        "dns2|2=s" => \$dnsServer2,
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
        if ($debug) { print Dumper(%domains); };
        if ($debug) { print Dumper(%orgs); };
        exit;
};

##  Main Subroutine
sub main {
        $| = 1;

	if (!$filterFile) { throwError("Filter File Required, See Help."); };

        setupDNS();

        my @filterLines = openFilter();
        my @hosts = parseFilter(\@filterLines);
        my @output = lookupHosts(\@hosts);
        displayOutput(\@output);
};

##  Setup DNS Subroutine
sub setupDNS {
        $dnsObj = Net::DNS::Resolver->new(
                nameservers => [$dnsServer1,$dnsServer2],
                recurse     => 0,
                debug       => $debug,
        );
};

##  Open PCAP Subroutine
sub openFilter {
        open(FILTER, $filterFile) or throwError("Cannot Open Filter, Does File Exist?");
        my @filterLines = <FILTER>;

        return @filterLines;
};

##  Parse Filter Subroutine
sub parseFilter {
        my @hosts;

	my @filterLines = @{$_[0]};
        my @hostLines = grep(/host/, @filterLines);

        foreach my $hostLine (@hostLines) {
                $hostLine =~ s/.*\(//g;
                $hostLine =~ s/\).*//g;
                $hostLine =~ s/host //g;
                my @hostLineParts = split(/ and /, $hostLine);
                push(@hosts, [@hostLineParts]);
        };

        return @hosts;
};

##  Lookup Hosts Subroutine
sub lookupHosts {
        my @hosts = @{$_[0]};
        my $count = 1;
        my @output;

        print "[NOTICE]  Looking Up Hosts, This May Take A Few Minutes.\n";
        print "[NOTICE]  Total Hosts:  $#hosts\n";

        foreach my $host (@hosts) {
                my @outputLine;
                my @host = @{$host};
                foreach my $hostPart (@host) {
                        if ($hostPart !~ /port/) {
                                my $domain = lookupHost($hostPart);
                                my $org = whoisHost($hostPart);
                                my $outputPart = "$hostPart";
                                if (($domain) || ($org)) { $outputPart .= " - "; };
                                if ($domain) { $outputPart .= "$domain "; };
                                if ($org) { $outputPart .= "[$org]"; };
                                push (@outputLine, $outputPart);
                        } else {
                                push(@outputLine, $hostPart);
                        };
                };
                my $outputLine = join(' and ', @outputLine);
                push(@output, $outputLine);
                $count++;
                my $status = ($count / $#hosts) * 100;
                printf "[STATUS]  Complete:  %.2f%%\r", $status;
	};

        return @output;
};

##  DNS Query Subroutine
sub lookupHost {
        my $host = $_[0];

        if (defined($domains{$host})) { return $domains{$host}; };

        my $dnsAnswer = $dnsObj->query($host);
        if (defined($dnsAnswer)) {
                foreach my $answer ($dnsAnswer->answer) {
                        $domains{$host} = $answer->ptrdname;
                        last;
                };
        } else {
                $domains{$host} = "";
        };

        return $domains{$host};
};

##  Whois Query Subroutine
sub whoisHost {
        my $host = $_[0];

        if (defined($orgs{$host})) { return $orgs{$host}; };

	my $whoisAnswer = parse_whois( domain => $host );
        if (defined($whoisAnswer)) {
                $orgs{$host} = $whoisAnswer->{'orgname'};
        } else {
                $orgs{$host} = "";
        };

        return $orgs{$host};
};

##  Output Filter Subroutine
sub displayOutput {
        my @output = @{$_[0]};

        foreach my $line (@output) {
                chomp($line);
                print "$line\n";
        };
};

##  Run
main();
quit();

__END__

=head1 NAME

FilterAnalyze-NetProfiler - Analyze Network Profile Filter

=head1 SYNOPSIS

    NetProfile
	-f, --filter,             Network Capture Filter (BPF)
        -1, --dnsserver1,         Primary DNS Server
        -2, --dnsserver2,         Secondary DNS Server
        -d, --debug               Verbose/Debug Output
	-h, --help,               Help Output (This Message)
        --version,                Output Version Information

=head1 OPTIONS

=over

=item B<-f>, B<--filter>  I<file>

PCAP filter I<file> (BPF) which will be analyzed.
This should be the filter created by NetProfiler, but any BPF may work.

=item B<-d>, B<--debug>

Enabled debugging mode, which will provide verbose output.  Useful to troubleshoot DNS and Whois issues.

=back

=head1 DESCRIPTION

B<FilterAnalyze-NetProfiler> analyzes the custom filter built by NetProfiler (it may work with other filters as well).

=head1 EXAMPLES

B<NetProfiler -f test.bpf>
        Standard execution, analyzing I<test.bpf>, using all defaults.

B<NetProfiler -f test.bpf -1 8.8.8.8>
        Standard execution, using an alternate DNS server of I<8.8.8.8>, analyzing I<test.bpf>.

=head1 AUTHOR

B<Justin M. Wray>, E<lt>wray.justin@gmail.comE<gt>

=head1 COPYRIGHT
