#!/usr/bin/perl -w

# $Id$ #

my $usage = "usage: $0 <rulesdir>\n";

my $rulesdir = shift || die("$usage");

my %sidmap;

opendir(RULESDIR, "$rulesdir") or die("could not open $rulesdir: $!\n");

while ($file = readdir(RULESDIR)) {
    next unless ($file =~ /\.rules$/);

    open(FILE, "$rulesdir/$file") or die("could not open $rulesdir/$file: $!\n");
    print STDERR "Processing $file\n";

    my ($multi, $single, $nonrule, $newfile);

    while ($_ = <FILE>) {
        undef($multi);
        undef($single);
 	undef($nonrule);

      # Start of multi-line rule?
        if (/^\s*(?:alert|log|pass) .*\\\s*\n$/) {
            $multi  = $_;
            $single = $_;

          # Keep on reading as long as line ends with "\".
            while (/\\\n$/) {
                $single =~ s/\\\n//;
                $_ = <FILE>;
		$single .= $_;
                $multi  .= $_;
	    }

      # Single-line rule?
	} elsif (/^\s*(?:alert|log|pass)/) {
	    $single = $_;
        }

      # Even if it was a single-line, put it in $multi now anyway.
        $multi = $single unless (defined($multi));

      # If we've got a valid rule...
	if (defined($single) && $single =~ /msg\s*:\s*"(.+?)"\s*;.*sid\s*:\s*(\d+)\s*;/) {
            my $msg = $1;
            my $sid = $2;
            $sidmap{$sid} = "$sid || $msg";

          # Print all references. Borrowed from Brian Caswell's regen-sidmap script.
            my $ref = $single;
            while ($ref =~ s/(.*)reference\s*:\s*([^\;]+)(.*)$/$1 $3/) {
                $sidmap{$sid} .= " || $2"
            }

            $sidmap{$sid} .= "\n";

        } elsif (defined($single)) {
            print STDERR "Warning: unable to parse rule: $single";
        }
    }
    close(FILE);

}
closedir(RULESDIR);

# Print results.
foreach my $sid (sort { $a <=> $b } keys(%sidmap)) {
    print "$sidmap{$sid}";
}
