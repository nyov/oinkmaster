#!/usr/bin/perl -w

use strict;
use Getopt::Std;
use File::Copy;
use POSIX qw(strftime);

sub show_usage;
sub parse_cmdline;
sub read_config;
sub sanity_check;

my $version     = 'Oinkmaster v0.4 by Andreas Östling <andreaso@it.su.se>';
my $config_file = "./oinkmaster.conf";    # default config file
my $verbose     = 0;
my $quiet       = 0;
my $tmpdir      = "/tmp/oinkmaster.$$";

use vars
qw (
      $opt_h $opt_v $opt_o $opt_q
   );

my (
      $output_dir
   );

my (
      %sid_disable_list, %file_ignore_list, %config
   );



#### MAIN ####

select(STDERR); $| = 1;         # No buffering.
select(STDOUT); $| = 1;

parse_cmdline;
read_config;
sanity_check;

# Set new (temporary) PATH.
local $ENV{"PATH"} = $config{path};

# Create empty temporary directory.
mkdir("$tmpdir", 0700) or die("could not create temporary directory $tmpdir: $!\nExiting");




# END OF MAIN #



sub show_usage
{
    print STDERR "$version\n\n".
                 "Usage: $0 -o <dir> [options]\n\n".
		 "<dir> is where to put the new rules files. This should be the\n".
                 "directory where you store your snort.org rules\n".
                 "\nOptions:\n".
                 "-q        Quiet mode. No output unless changes were found\n".
		 "-v        Verbose mode\n".
                 "-h        Show usage help\n";
    exit;
}



sub parse_cmdline
{
    my $cmdline_ok = getopts('ho:q');

    show_usage if     (defined($opt_h));  # -h
    $quiet = 1 if     (defined($opt_q));  # -q
    show_usage unless ($cmdline_ok);

    if (defined($opt_o)) {                # -o <dir>, the only required option.
        $output_dir = $opt_o;
    } else {
        print STDERR "You must specify where to put the rules with -o <dir>.\n\n";
        show_usage;
    }

#    die("Don't run as root!\nExiting") if (!$>);
}



sub read_config
{
    my $line = 0;

    open(CONF, "$config_file") or die("could not open $config_file: $!\nExiting");

    while (<CONF>) {
        $line++;
        s/\s*\#.*//;                     # remove comments
	s/^\s*//;                        # remove leading whitespaces
	s/\s*$//;                        # remove trailing whitespaces
        next unless (/\S/);              # skip blank lines

        if (/^\s*sid\s*(\d+)/i) {                             # sid X
            $sid_disable_list{$1}++;
        } elsif (/^\s*file\s*(\S+)/i) {                       # file X
            $verbose && print STDERR "Adding file to ignore list: $1.\n";
            $file_ignore_list{$1}++;
	} elsif (/^URL\s*=\s*((?:http|ftp):\/\/\S+.*gz$)/i) {  # URL
	    $config{url} = $1;
	} elsif (/^PATH\s*=\s*(.*)/i) {
	    $config{path} = $1;
        } else {                                              # invalid line
            print STDERR "Warning: line $line in $config_file is invalid, skipping line.\n";
        }
    }

    close(CONF)
}



sub sanity_check
{
   my @req_config   = qw (url path);
   my @req_binaries = qw (which wget gzip tar);

  # Make sure all required variables was defined in the config file.
    foreach $_ (@req_config) {
        die("$_ not defined in $config_file\nExiting")
          unless (exists($config{$_}));
    }

  # Make sure all required binaries are found.
    foreach $_ (@req_binaries) {
        die("\"$_\" binary not found\nExiting")
          if (system("which \"$_\" >/dev/null 2>&1"));
    }

  # Make sure the output directory exists and is writable.
    die("The output directory \"$output_dir\" doesn't exist or isn't writable by you.\n\nExiting")
      if (! -d "$output_dir" || ! -w "$output_dir");

}

#### EOF ####
