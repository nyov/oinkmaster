#!/usr/bin/perl -w

# $Id$ #

use strict;

sub get_next_entry($ $ $ $);


# Regexp to match a snort rule line.
# We only care about active rules.
my $SINGLELINE_RULE_REGEXP = '^\s*(?:alert|drop|log|pass|reject|sdrop)\s.+msg\s*:\s*"'.
                             '(.+?)"\s*;.*sid\s*:\s*(\d+)\s*;.*\)\s*$'; # ';

# Regexp to match the start (the first line) of a possible multi-line rule.
my $MULTILINE_RULE_REGEXP  = '^\s*(?:alert|drop|log|pass|reject|sdrop)\s.*\\\\\s*\n$'; # ';



my $USAGE    = "usage: $0 <rulesdir>\n";

my $rulesdir = shift || die("$USAGE");

my $verbose  = 1;

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
        if (defined($single)) {

          # Grab sid and msg.
            $single =~ /$SINGLELINE_RULE_REGEXP/oi;
            my ($msg, $sid) = ($1, $2);

            $sidmap{$sid} = "$sid || $msg";

          # Print all references. Borrowed from Brian Caswell's regen-sidmap script.
            my $ref = $single;
            while ($ref =~ s/(.*)reference\s*:\s*([^\;]+)(.*)$/$1 $3/) {
                $sidmap{$sid} .= " || $2"
            }

            $sidmap{$sid} .= "\n";
        }
    }
}

# Print results.
foreach my $sid (sort { $a <=> $b } keys(%sidmap)) {
    print "$sidmap{$sid}";
}



sub get_next_entry($ $ $ $)
{
    my $arr_ref        = shift;
    my $single_ref     = shift;
    my $multi_ref      = shift;
    my $nonrule_ref    = shift;

    undef($$single_ref);
    undef($$multi_ref);
    undef($$nonrule_ref);

    my $line = shift(@$arr_ref) || return(0);

    if ($line =~ /$MULTILINE_RULE_REGEXP/oi) {    # possible beginning of multi-line rule?
        $$single_ref = $line;
        $$multi_ref  = $line;

      # Keep on reading as long as line ends with "\".
        while ($line =~ /\\\s*\n$/) {
            $$single_ref =~ s/\\\s*\n//;    # remove trailing "\" for single-line version

          # If there are no more lines, this can not be a valid multi-line rule.
            if (!($line = shift(@$arr_ref))) {

                warn("WARNING: got EOF while parsing multi-line rule: $$multi_ref\n")
                  if ($verbose);

                @_ = split(/\n/, $$multi_ref);

                undef($$multi_ref);
                undef($$single_ref);

              # First line of broken multi-line rule will be returned as a non-rule line.
                $$nonrule_ref = shift(@_) . "\n";
                $$nonrule_ref =~ s/\s*\n$/\n/;            # remove trailing whitespaces

              # The rest is put back to the array again.
                foreach $_ (reverse((@_))) {
                    unshift(@$arr_ref, "$_\n");
                }

                return (1);   # return non-rule
            }

          # Multi-line continuation.
            $$multi_ref .= $line;
            $line =~ s/^\s*#*\s*//;     # In single-line version, remove leading #'s first
            $$single_ref .= $line;

        } # while line ends with "\"

      # Single-line version should now be a valid rule.
      # If not, it wasn't a valid multi-line rule after all.
        if ($$single_ref =~ /$SINGLELINE_RULE_REGEXP/oi) {

            $$single_ref =~ s/^\s*//;        # remove leading whitespaces
            $$single_ref =~ s/^#+\s*/#/;     # remove whitespaces next to the leading #
            $$single_ref =~ s/\s*\n$/\n/;    # remove trailing whitespaces

            $$multi_ref  =~ s/^\s*//;
            $$multi_ref  =~ s/\s*\n$/\n/;
            $$multi_ref  =~ s/^#+\s*/#/;

            return (1);   # return multi
        } else {
            warn("WARNING: invalid multi-line rule: $$single_ref\n")
              if ($verbose && $$multi_ref !~ /^\s*#/);

            @_ = split(/\n/, $$multi_ref);

            undef($$multi_ref);
            undef($$single_ref);

          # First line of broken multi-line rule will be returned as a non-rule line.
            $$nonrule_ref = shift(@_) . "\n";
            $$nonrule_ref =~ s/\s*\n$/\n/;   # remove trailing whitespaces

          # The rest is put back to the array again.
            foreach $_ (reverse((@_))) {
                unshift(@$arr_ref, "$_\n");
            }

            return (1);   # return non-rule
        }

    } elsif ($line =~ /$SINGLELINE_RULE_REGEXP/oi) {  # regular single-line rule?
        $$single_ref = $line;
        $$single_ref =~ s/^\s*//;            # remove leading whitespaces
        $$single_ref =~ s/^#+\s*/#/;         # remove whitespaces next to the leading #
        $$single_ref =~ s/\s*\n$/\n/;        # remove trailing whitespaces

        return (1);   # return single
    } else {                                 # non-rule line?

      # Do extra check and warn if it *might* be a rule anyway, but that we couldn't parse.
        warn("WARNING: line may be a rule but it could not be parsed: $line\n")
          if ($verbose && $line =~ /^\s*alert .+msg\s*:\s*".+"\s*;/);

        $$nonrule_ref = $line;
        $$nonrule_ref =~ s/\s*\n$/\n/;       # remove trailing whitespaces

        return (1);   # return non-rule
    }
}
