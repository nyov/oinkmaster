#!/usr/bin/perl -w

# $Id$ #

# Copyright (c) 2004-2006 Andreas ?stling <andreas_ostling@bredband.net>
# All rights reserved.
#
#  Redistribution and use in source and binary forms, with or
#  without modification, are permitted provided that the following
#  conditions are met:
#
#  1. Redistributions of source code must retain the above
#     copyright notice, this list of conditions and the following
#     disclaimer.
#
#  2. Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials
#     provided with the distribution.
#
#  3. Neither the name of the author nor the names of its
#     contributors may be used to endorse or promote products
#     derived from this software without specific prior written
#     permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


use strict;

sub get_next_entry($ $ $ $ $ $);
sub parse_singleline_rule($ $ $);


my $USAGE = << "RTFM";

Parse Oinkmaster configuration file and add the rule's "msg" string as a 
#comment for each disablesid/enablesid line.

Usage: $0 <oinkmaster.conf> <rulesdir> [rulesdir2, ...]

The new config file will be printed to standard output, so you
probably want to redirect the output to a new file (*NOT* the same
file you used as input, because that will destroy the file!).
For example:

$0 /etc/oinkmaster.conf /etc/rules/ > oinkmaster.conf.new

If oinkmaster.conf.new looks ok, simply rename it to /etc/oinkmaster.conf.

RTFM


# Regexp to match the start of a multi-line rule.
# %ACTIONS% will be replaced with content of $config{actions} later.
my $MULTILINE_RULE_REGEXP  = '^\s*#*\s*(?:%ACTIONS%)'.
                             '\s.*\\\\\s*\n$'; # ';

# Regexp to match a single-line rule.
my $SINGLELINE_RULE_REGEXP = '^\s*#*\s*(?:%ACTIONS%)'.
                             '\s.+;\s*\)\s*$'; # ';


my $config   = shift || die($USAGE);

my @rulesdirs = @ARGV;
die($USAGE) unless ($#rulesdirs > -1);

my $verbose = 1;
my (%sidmsgmap, %config);

$config{rule_actions} = "alert|drop|log|pass|reject|sdrop|activate|dynamic";

$SINGLELINE_RULE_REGEXP =~ s/%ACTIONS%/$config{rule_actions}/;
$MULTILINE_RULE_REGEXP  =~ s/%ACTIONS%/$config{rule_actions}/;



# Read in oinkmaster.conf.
open(CONFIG, "<" , "$config") or die("could not open \"$config\" for reading: $!\n");
my @config = <CONFIG>;
close(CONFIG);


# Read in *.rules in all rulesdirs and create %sidmsgmap ($sidmsgmap{sid} = msg).
foreach my $rulesdir (@rulesdirs) {
    opendir(RULESDIR, "$rulesdir") or die("could not open \"$rulesdir\": $!\n");

    while (my $file = readdir(RULESDIR)) {
        next unless ($file =~ /\.rules$/);

        open(FILE, "<", "$rulesdir/$file") or die("could not open \"$rulesdir/$file\": $!\n");
        my @file = <FILE>;
        close(FILE);

        my ($single, $multi, $nonrule, $msg, $sid);

        while (get_next_entry(\@file, \$single, \$multi, \$nonrule, \$msg, \$sid)) {
            $sidmsgmap{$sid} = $msg
              if (defined($single));
        }
    }
}


# Print new oinkmaster.conf.
while ($_ = shift(@config)) {
    if (/^\s*(?:disable|enable|local)sid\s+(\d+)\s*$/ || /^\s*(\d+)\s*,\s*\\$/ || /^\s*(\d+)\s*$/) {
	my $sid = $1;
        my $is_multiline = 0;
	chomp;

        if (/\\$/) {
           $is_multiline = 1;
           s/\\$//;
        }

	$_ = sprintf("%-25s", $_);
	if (exists($sidmsgmap{$sid})) {
            print "$_  # $sidmsgmap{$sid}";
	} else {
            print "$_";
        }
        print " \\" if ($is_multiline);
        print "\n";
    } else {
	print;
    }
}



# From oinkmaster.pl.
sub get_next_entry($ $ $ $ $ $)
{
    my $arr_ref     = shift;
    my $single_ref  = shift;
    my $multi_ref   = shift;
    my $nonrule_ref = shift;
    my $msg_ref     = shift;
    my $sid_ref     = shift;

    undef($$single_ref);
    undef($$multi_ref);
    undef($$nonrule_ref);
    undef($$msg_ref);
    undef($$sid_ref);

    my $line = shift(@$arr_ref) || return(0);
    my $disabled = 0;
    my $broken   = 0;

  # Possible beginning of multi-line rule?
    if ($line =~ /$MULTILINE_RULE_REGEXP/oi) {
        $$single_ref = $line;
        $$multi_ref  = $line;

        $disabled = 1 if ($line =~ /^\s*#/);

      # Keep on reading as long as line ends with "\".
        while (!$broken && $line =~ /\\\s*\n$/) {

          # Remove trailing "\" and newline for single-line version.
            $$single_ref =~ s/\\\s*\n//;

          # If there are no more lines, this can not be a valid multi-line rule.
            if (!($line = shift(@$arr_ref))) {

                warn("\nWARNING: got EOF while parsing multi-line rule: $$multi_ref\n")
                  if ($config{verbose});

                @_ = split(/\n/, $$multi_ref);

                undef($$multi_ref);
                undef($$single_ref);

              # First line of broken multi-line rule will be returned as a non-rule line.
                $$nonrule_ref = shift(@_) . "\n";
                $$nonrule_ref =~ s/\s*\n$/\n/;    # remove trailing whitespaces

              # The rest is put back to the array again.
                foreach $_ (reverse((@_))) {
                    unshift(@$arr_ref, "$_\n");
                }

                return (1);   # return non-rule
            }

          # Multi-line continuation.
            $$multi_ref .= $line;

          # If there are non-comment lines in the middle of a disabled rule,
          # mark the rule as broken to return as non-rule lines.
            if ($line !~ /^\s*#/ && $disabled) {
                $broken = 1;
            } elsif ($line =~ /^\s*#/ && !$disabled) {
                # comment line (with trailing slash) in the middle of an active rule - ignore it
            } else {
                $line =~ s/^\s*#*\s*//;  # remove leading # in single-line version
                $$single_ref .= $line;
            }

        } # while line ends with "\"

      # Single-line version should now be a valid rule.
      # If not, it wasn't a valid multi-line rule after all.
        if (!$broken && parse_singleline_rule($$single_ref, $msg_ref, $sid_ref)) {

            $$single_ref =~ s/^\s*//;     # remove leading whitespaces
            $$single_ref =~ s/^#+\s*/#/;  # remove whitespaces next to leading #
            $$single_ref =~ s/\s*\n$/\n/; # remove trailing whitespaces

            $$multi_ref  =~ s/^\s*//;
            $$multi_ref  =~ s/\s*\n$/\n/;
            $$multi_ref  =~ s/^#+\s*/#/;

            return (1);   # return multi
        } else {
            warn("\nWARNING: invalid multi-line rule: $$single_ref\n")
              if ($config{verbose} && $$multi_ref !~ /^\s*#/);

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
     } elsif (parse_singleline_rule($line, $msg_ref, $sid_ref)) {
        $$single_ref = $line;
        $$single_ref =~ s/^\s*//;
        $$single_ref =~ s/^#+\s*/#/;
        $$single_ref =~ s/\s*\n$/\n/;

        return (1);   # return single
    } else {                          # non-rule line

      # Do extra check and warn if it *might* be a rule anyway,
      # but that we just couldn't parse for some reason.
        warn("\nWARNING: line may be a rule but it could not be parsed ".
             "(missing sid or msg?): $line\n")
          if ($config{verbose} && $line =~ /^\s*alert .+msg\s*:\s*".+"\s*;/);

        $$nonrule_ref = $line;
        $$nonrule_ref =~ s/\s*\n$/\n/;

        return (1);   # return non-rule
    }
}



# From oinkmaster.pl.
sub parse_singleline_rule($ $ $)
{
    my $line    = shift;
    my $msg_ref = shift;
    my $sid_ref = shift;

    if ($line =~ /$SINGLELINE_RULE_REGEXP/oi) {

        if ($line =~ /\bmsg\s*:\s*"(.+?)"\s*;/i) {
            $$msg_ref = $1;
        } else {
            return (0);
        }

        if ($line =~ /\bsid\s*:\s*(\d+)\s*;/i) {
            $$sid_ref = $1;
        } else {
            return (0);
        }

        return (1);
    }

    return (0);
}
