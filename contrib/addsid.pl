#!/usr/bin/perl -w

# $Id$ #

use strict;

sub get_next_entry($ $ $ $);


my $USAGE = "usage: $0 <rulesdir> <start sid>\n";

# SID must not be required in this regexp.
my $SNORT_RULE_REGEXP = '^\s*#*\s*(?:alert|log|pass) .+msg\s*:\s*"(.+?)"\s*;.*\)\s*$';

# Set this to the default classtype you want to add, if missing.
# Comment out if you don't want to add a classtype.
my $classtype = "misc-attack";

# Only >= 1000000 is reserved for personal use.
my $min_sid = 1000000;

my $rulesdir = shift || die("$USAGE");
my $sid      = shift || die("$USAGE");   # XXX should start with the next available SID by default? but option should remain

die("sid to start with must be at least $min_sid!\n")
  unless ($sid >= $min_sid);


opendir(RULESDIR, "$rulesdir") or die("could not open $rulesdir: $!\n");

while (my $file = readdir(RULESDIR)) {
    next unless ($file =~ /\.rules$/);

    open(OLDFILE, "$rulesdir/$file") or die("could not open $rulesdir/$file: $!\n");
    print STDERR "Processing $file\n";
    my @file = <OLDFILE>;
    close(OLDFILE);

    open(NEWFILE, ">$rulesdir/$file") or die("could not open $rulesdir/$file for writing: $!\n");

    my ($single, $multi, $nonrule);
    while (get_next_entry(\@file, \$single, \$multi, \$nonrule)) {

        if (defined($nonrule)) {
	    print NEWFILE "$nonrule";
	    next;
        }

        $multi = $single unless (defined($multi));

        if ($single !~ /sid\s*:\s*\d+\s*;/) {
            $sid++;
            $multi =~ s/\)\s*\n/sid:$sid;)\n/;
        }

        if ($single !~ /rev\s*:\s*\d+\s*;/) {
            $multi =~ s/\)\s*\n/rev:1;)\n/;
        }

        if (defined($classtype)) {
            if ($single !~ /classtype\s*:\s*".*"\s*;/) {
                $multi =~ s/\)\s*\n/classtype:"$classtype";)\n/;
            }
        }


        print NEWFILE "$multi";

    }


    close(NEWFILE);

}
closedir(RULESDIR);



sub
get_next_entry($ $ $ $)
{
    my $arr_ref     = shift;
    my $single_ref  = shift;
    my $multi_ref   = shift;
    my $nonrule_ref = shift;

    undef($$single_ref);
    undef($$multi_ref);
    undef($$nonrule_ref);

    my $line = shift(@$arr_ref) || return(0);

    if ($line =~ /^\s*#*\s*(?:alert|log|pass) .*\\\s*\n$/) {    # start multi-line rule?
        $$single_ref = $line;
        $$multi_ref  = $line;

      # Keep on reading as long as line ends with "\".
        while ($line =~ /\\\s*\n$/) {
            $$single_ref =~ s/\s*\\\s*\n//;    # remove "\" for single-line version

          # If there are no more lines, this can not be a valid multi-line rule.
            if (!($line = shift(@$arr_ref)) || $line =~ /^\s*#/) {

		$$multi_ref .= $line if (defined($line));

                @_ = split(/\n/, $$multi_ref);

                undef($$multi_ref);
                undef($$single_ref);

              # First line of broken multi-line rule will be returned as a non-rule line.
                $$nonrule_ref = shift(@_) . "\n";

              # The rest is put back to the array again.
                foreach $_ (reverse((@_))) {
                    unshift(@$arr_ref, "$_\n");
	        }

		return (1);
	    }

            $$single_ref .= $line;
            $$multi_ref  .= $line;
        }

      # Single-line version should now be a valid rule.
      # If not, it wasn't a valid multi-line rule after all.
        if ($$single_ref =~ /$SNORT_RULE_REGEXP/) {
	    return (1);
        } else {
            print "invalid multi:\n$$single_ref";             # XXX debug

            @_ = split(/\n/, $$multi_ref);

            undef($$multi_ref);
            undef($$single_ref);

          # First line of broken multi-line rule will be returned as a non-rule line.
            $$nonrule_ref = shift(@_) . "\n";

          # The rest is put back to the array again.
            foreach $_ (reverse((@_))) {
                unshift(@$arr_ref, "$_\n");
	    }

	    return (1);
        }

    } elsif ($line =~ /$SNORT_RULE_REGEXP/) {                   # single-line rule?
        $$single_ref = $line;
	return (1);
    } else {                                                    # non-rule line?
        $$nonrule_ref = $line;
	return (1);
    }
}

