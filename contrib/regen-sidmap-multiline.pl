#!/usr/bin/perl -w

# $Id$ #

use strict;

sub get_next_entry($ $ $ $);

my $SNORT_RULE_REGEXP = '^\s*#*\s*(?:alert|log|pass) .+msg\s*:\s*"(.+?)"\s*;.+sid\s*:\s*(\d+)\s*;.*\)\s*$';
my $USAGE = "usage: $0 <rulesdir>\n";
my $rulesdir = shift || die("$USAGE");
my %sidmap;


opendir(RULESDIR, "$rulesdir") or die("could not open $rulesdir: $!\n");

while (my $file = readdir(RULESDIR)) {
    next unless ($file =~ /\.rules$/);

    open(OLDFILE, "$rulesdir/$file") or die("could not open $rulesdir/$file: $!\n");
    print STDERR "Processing $file\n";
    my @file = <OLDFILE>;
    close(OLDFILE);

    my ($single, $multi, $nonrule);

    while (get_next_entry(\@file, \$single, \$multi, \$nonrule)) {

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
	    print STDERR "Warning: unable to parse rule (missing SID?): $single";
	} elsif ($nonrule =~ /^\s*#*alert /) {
	    print STDERR "Warning: unable to parse rule: $nonrule";
        }
    }
}

# Print results.
foreach my $sid (sort { $a <=> $b } keys(%sidmap)) {
    print "$sidmap{$sid}";
}



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
