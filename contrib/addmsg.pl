#!/usr/bin/perl -w

# $Id$ #

use strict;


my (%sidmsgmap);

my $usage = "Usage: $0 <oinkmaster config file> <rules directory>\n\n".
            "New config file will be printed to standard output so you\n".
            "probably want to redirect the output to a file, for example:\n".
            "$0 oinkmaster.conf rules/ > oinkmaster.conf.new\n".
            "If oinkmaster.conf.new looks ok, simply rename it to oinkmaster.conf.\n\n";

my $snort_rule_regexp = '^\s*#*\s*(?:alert|log|pass) .+msg\s*:\s*"(.+?)"\s*;.+sid\s*:\s*(\d+)\s*;';

my $config   = shift || die($usage);
my $rulesdir = shift || die($usage);


# Read in oinkmaster.conf.
open(CONFIG, "<$config") or die("could not open $config for reading: $!\n");
my @config = <CONFIG>;
close(CONFIG);


# Read in *.rules and create %sidmsgmap ($sidmsgmap{sid} = msg).
$rulesdir =~ s/\/+$//;
my @rulesfiles = glob("$rulesdir/*.rules");
die("No .rules files in $rulesdir\n") if ($#rulesfiles < 0);

foreach my $file (@rulesfiles) {
    open(RULESFILE, "<$file") or die("could not open $file: $!");
    while (<RULESFILE>) {
	$sidmsgmap{$2} = $1 if (/$snort_rule_regexp/);
    }
}


# Print new oinkmaster.conf.
while ($_ = shift(@config)) {
    if (/^\s*disablesids*\s+(\d+)\s*$/) {
	my $sid = $1;
	chomp;
	s/ +/ /g;	
	tr/\t/ /;
	$_ = sprintf("%-25s", $_);
	if (exists($sidmsgmap{$sid})) {
            print "$_  # $sidmsgmap{$sid}\n";
	} else {
            print "$_  # (SID not found)\n";
	    print STDERR "Warning: SID $sid not found in $rulesdir/*.rules\n";
        }
    } else {
	print;
    }
} 
