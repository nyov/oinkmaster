#!/usr/bin/perl -w

# $Id$ #

# XXX should create a sid map

my $usage   = "usage: $0 <rulesdir> <start sid>\n";

# Set this to the default classtype you want to add, if missing.
# Comment out if you don't want to add a classtype.
my $classtype = "misc-attack";

# Only >= 1000000 is reserved for personal use.
my $min_sid = 1000000;

my $rulesdir = shift || die("$usage");
my $sid      = shift || die("$usage");

die("sid to start with must be at least $min_sid!\n")
  unless ($sid >= $min_sid);


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
        if (/^\s*(?:alert|log|pass) .*\\\n$/) {
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

      # Non-rule line.
        } else {
	   $nonrule = $_;
	}

      # Even if it was a single-line, put it in $multi now anyway.
        $multi = $single unless (defined($multi));


      # If we've got a valid rule...
	if (defined($single) && $single =~ /msg\s*:\s*"(.+?)".*;\s*\)\s*\n$/) {
            my $msg = $1;

            if ($single !~ /sid\s*:\s*\d+\s*;/) {
                print STDERR "Adding sid to \"$msg\"\n";
		$sid++;
                $multi =~ s/;\s*\)\s*\n/; sid:$sid;)\n/;
	    }

            if ($single !~ /rev\s*:\s*\d+\s*;/) {
                print STDERR "Adding rev to \"$msg\"\n";
                $multi =~ s/;\s*\)\s*\n/; rev:1;)\n/;
	    }

            if (defined($classtype)) {
                if ($single !~ /classtype\s*:\s*".*"\s*;/) {
                    print STDERR "Adding classtype to \"$msg\"\n";
                    $multi =~ s/;\s*\)\s*\n/; classtype:"$classtype";)\n/;
	        }
            }

            $newfile .= $multi;

      # Non-valid rule.
        } elsif (defined($single)) {
	      print STDERR "Warning: don't understand this rule: $single";
              $newfile .= $single;
        } else {
	      $newfile .= $nonrule;
        }

    }
    close(FILE);

    open(NEWFILE, ">$rulesdir/$file") or die("could not open $rulesdir/$file for writing: $!\n");
    print NEWFILE $newfile;
    close(NEWFILE);

}
closedir(RULESDIR);
