#!/usr/bin/perl -w

# $Id$ #

use strict;


sub get_next_entry($ $ $ $);
sub get_highest_sid($);


my $USAGE = "usage: $0 <rulesdir>\n";

# Regexp to match a snort rule line. SID must not be required in this one.
my $SINGLELINE_RULE_REGEXP = '^\s*#*\s*(?:alert|drop|log|pass|reject|sdrop) '.
                             '.+msg\s*:\s*"(.+?)"\s*;.*\)\s*$'; # ';

# Regexp to match the start (the first line) of a possible multi-line rule.
my $MULTILINE_RULE_REGEXP = '^\s*(?:alert|drop|log|pass|reject|sdrop)\s.*\\\\\s*\n$'; # ';


# Set this to the default classtype you want to add, if missing.
# Set to 0 if you don't want to add a classtype.
my $CLASSTYPE = "misc-attack";

# If ADD_REV is set to 1, "rev: 1;" will be added to rule if it has no rev.
# Set to 0 if you don't want to add it.
my $ADD_REV = 1;


# Minimum SID to add. Normally, the next available SID will be used,
# unless it's below this value. Only SIDs >= 1000000 are reserved for
# personal use.
my $MIN_SID = 1000000;

# Start in verbose mode.
my $verbose = 1;


my %allsids;

my $rulesdir = shift || die("$USAGE");


# Find out the next available SID.
my $sid = get_highest_sid($rulesdir);

# If it's below MIN_SID, use MIN_SID instead.
$sid = $MIN_SID if ($sid < $MIN_SID);

# Avoid seeing possible warnings about broken rules twice.
$verbose = 0;

opendir(RULESDIR, "$rulesdir") or die("could not open $rulesdir: $!\n");

while (my $file = readdir(RULESDIR)) {
    next unless ($file =~ /\.rules$/);

    open(OLDFILE, "$rulesdir/$file")
      or die("could not open $rulesdir/$file: $!\n");
    print STDERR "Processing $file\n";
    my @file = <OLDFILE>;
    close(OLDFILE);

    open(NEWFILE, ">$rulesdir/$file")
      or die("could not open $rulesdir/$file for writing: $!\n");

    my ($single, $multi, $nonrule);
    while (get_next_entry(\@file, \$single, \$multi, \$nonrule)) {

        if (defined($nonrule)) {
	    print NEWFILE "$nonrule";
	    next;
        }

      # Grab msg.
        $single =~ /$SINGLELINE_RULE_REGEXP/oi;
        my $msg = $1;

        $multi = $single unless (defined($multi));

      # Don't care about inactive rules.
        if ($single =~ /\s*#/) {
	    print NEWFILE "$multi";
	    next;
        }

      # Add SID.
        if ($single !~ /sid\s*:\s*\d+\s*;/) {
            print "Adding SID $sid to rule \"$msg\"\n";
            $multi =~ s/\)\s*\n/sid:$sid;)\n/;
            $sid++;
        }

      # Add revision.
        if ($ADD_REV && $single !~ /rev\s*:\s*\d+\s*;/) {
            $multi =~ s/\)\s*\n/rev:1;)\n/;
        }

      # Add classtype.
        if ($CLASSTYPE && $single !~ /classtype\s*:\s*.+\s*;/) {
            $multi =~ s/\)\s*\n/classtype:$CLASSTYPE;)\n/;
        }

        print NEWFILE "$multi";
    }

    close(NEWFILE);

}
closedir(RULESDIR);



# Read in *.rules in given directory and return highest SID.
sub
get_highest_sid($)
{
    my $dir = shift;

    opendir(RULESDIR, "$dir") or die("could not open $dir: $!\n");

  # Only care about *.rules.
    while (my $file = readdir(RULESDIR)) {
        next unless ($file =~ /\.rules$/);

        open(OLDFILE, "<$dir/$file") or die("could not open $dir/$file: $!\n");
        my @file = <OLDFILE>;
        close(OLDFILE);

        my ($single, $multi, $nonrule);

        while (get_next_entry(\@file, \$single, \$multi, \$nonrule)) {
            if (defined($single) && $single =~ /sid\s*:(\d+)\s*;/) {
	        my $tmpsid = $1;

                print STDERR "WARNING: duplicate sid: $tmpsid\n"
	          if (exists($allsids{$tmpsid}));

	        $allsids{$tmpsid}++;
            }
        }
    }

  # Sort sids and use highest one + 1, unless it's below MIN_SID.
    @_ = sort {$a <=> $b} keys(%allsids);
    my $sid = pop(@_);
    $sid = $MIN_SID unless(defined($sid));
    $sid++;

    return ($sid)
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
