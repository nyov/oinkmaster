#!/usr/bin/perl -w
#
# $Id$ #
#
# makesidex.pl - (make sid exclusions)-  Make snort SID exclusion list for 'oinkmaster.pl'
# redirect (append!) output to your oinkmaster.conf

# change this to where your snort rules are...
my $confdir = "/temp/oinkmaster/out/";

my @files = glob "$confdir/*.rules";
my %sid;

foreach my $file (@files) {
	chomp $file;
	open RULE, "< $file"
		or die "Can't open '$file' for reading: $!";
	while (my $line = <RULE>) {
		chomp $line;
		# look for anything that's commented out....grab sid
		if ($line =~ /^#.*?sid\:(\d+)/) {
			# this is just for sorting....
			my $key = sprintf("%06g", $1);
			$sid{$key} = $1;
		}
	}
	close RULE;
}

foreach my $key (sort keys %sid) {
	print "disablesid " . $sid{$key} . "\n";
}
