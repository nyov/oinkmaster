#!/usr/bin/perl -w

# $Id$ #

# XXX sid-map with refs

opendir(RULESDIR, ".");

my $sid = 1000000;

while ($file = readdir(RULESDIR)) {
    next unless ($file =~ /\.rules$/);

    open(FILE, $file);
    print STDERR "$file\n";

    my ($multi, $single);

    LINE: while ($_ = <FILE>) {
       undef($multi);
       undef($single);

        if (/^\s*(?:alert|log|pass) .*\\\n$/) {
            $multi  = $_;
            $single = $_;

            while (/\\\n$/) {
                $single =~ s/\\\n//;
                $_ = <FILE>;
		$single .= $_;
                $multi  .= $_;
            }

	} elsif (/^\s*(?:alert|log|pass)/) {
	    $single = $_;
        } else {
	   print $_;
           next LINE;
	}

        $multi = $single unless (defined($multi));

      # Missing SID?
	if ($single =~ /^\s*#*\s*(?:alert|log|pass) .+msg.*;\)\s*\n$/ && $single !~ /sid:\s*\d+\s*;/) {
	    $multi =~ s/;\)\s*\n/; sid:$sid; rev:1;)\n/;
            $sid++;
            print $multi;
        }
    }
    close(FILE);

}
closedir(RULESDIR);
