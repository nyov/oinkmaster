#!/usr/bin/perl -w

use strict;
use Getopt::Std;
use File::Copy;
use POSIX qw(strftime);
use Cwd;

sub show_usage;
sub parse_cmdline;
sub read_config;
sub sanity_check;
sub unpack_rules_archive;
sub disable_rules;
sub setup_rule_hashes;

my $version     = 'Oinkmaster v0.4 by Andreas Östling <andreaso@it.su.se>';
my $config_file = "./oinkmaster.conf";
my $tmpdir      = "/tmp/oinkmaster.$$";
my $outfile     = "snortrules.tar.gz";
my $verbose     = 0;
my $quiet       = 0;

# Regexp to match a Snort rule line.
# The msg string will go into $1, and the sid will go into $2.
my $snort_rule_regexp = '^\s*#*\s*(?:alert|log|pass) .+msg\s*:\s*"(.+?)"\s*;.+sid\s*:\s*(\d+)\s*;';

use vars qw
   (
      $opt_h $opt_v $opt_o $opt_q
   );

my (
      $output_dir
   );

#my (
#
#   );

my (
      %sid_disable_list, %file_ignore_list, %config, %old_files, %new_files
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

# Pull down the rules archive.
# Die if wget doesn't exit with status level 0.
if ($quiet) {
    if (system("wget","-q","-nv","-O","$tmpdir/$outfile","$config{url}")) {
        die("Unable to download rules.\n".
            "Consider running in non-quiet mode if the problem persists.\nExiting");
    }
} else {
    print STDERR "Downloading rules archive from $config{url}...\n";
    if (system("wget","-nv","-O","$tmpdir/$outfile","$config{url}")) {
        die("Unable to download rules.\nExiting")
    }
}

# Verify and unpack archive. This will leave us with a directory
# called "rules/" in the temporary directory, containing the new rules.
unpack_rules_archive;

# Add filenames to update from the downloaded archive to the list of new
# files, unless filename exists in %file_ignore_list.
opendir(NEWRULES, "$tmpdir/rules") or die("could not open directory $tmpdir/rules: $!\nExiting");
while ($_ = readdir(NEWRULES)) {
    $new_files{$_}++
      if (/$config{update_files}/ && !exists($file_ignore_list{$_}));
}
closedir(NEWRULES);

# Create list of (old) files that are in our output directory.
opendir(OLDRULES, "$output_dir") or die("could not open directory $output_dir: $!\nExiting");
while ($_ = readdir(OLDRULES)) {
    $old_files{$_}++
      if (/$config{update_files}/ && !exists($file_ignore_list{$_}));
}
closedir(OLDRULES);

# Make sure there is at least one file to be updated.
$_ = keys(%new_files);
if ($_  < 1) {
    die("Found no files in archive to be updated\nExiting");
} else {
    print STDERR ("Found $_ files to be updated.\n")
      unless ($quiet);
}

# Disable (#comment out) all rules listed in %sid_disable_list.
# All files will still be left in the temporary directory.
disable_rules;

setup_rule_hashes;


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
    my $cmdline_ok = getopts('ho:qv');


    $quiet   = 1 if     (defined($opt_q));  # -q
    $verbose = 1 if     (defined($opt_v));  # -v
    show_usage   if     (defined($opt_h));  # -h
    show_usage   unless ($cmdline_ok);

    if (defined($opt_o)) {                # -o <dir>, the only required option.
        $output_dir = $opt_o;
    } else {
        print STDERR "You must specify where to put the rules with -o <dir>.\n\n";
        show_usage;
    }

  # Can't use both -q and -v.
    die("Both quiet mode and verbose mode at the same time doesn't make sense.\nExiting")
      if ($quiet && $verbose);

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
	} elsif (/^URL\s*=\s*((?:http|ftp):\/\/\S+.*\.tar\.gz$)/i) {  # URL
	    $config{url} = $1;
	} elsif (/^PATH\s*=\s*(.*)/i) {
	    $config{path} = $1;
	} elsif (/update_files\s*=\s*(.*)/i) {
	    $config{update_files} = $1;
        } else {                                              # invalid line
            print STDERR "Warning: line $line in $config_file is invalid, skipping line.\n";
        }
    }

    close(CONF)
}



sub sanity_check
{
   my @req_config   = qw (url path update_files);
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



sub unpack_rules_archive
{
    my ($old_dir, $ok_chars, $filename);

    $ok_chars = 'a-zA-Z0-9_\.\-/\n :';   # allowed characters in the tar archive
    $filename = $outfile;                # so we don't modify the global filename variable

    $old_dir = getcwd or die("could not get current directory: $!\nExiting");
    chdir("$tmpdir")  or die("could not change directory to $tmpdir: $!\nExiting");

    unless (-s "$filename") {
        die("failed to get rules archive: ".
            "$tmpdir/$filename doesn't exist or hasn't non-zero size\nExiting");
    }

  # Run integrity check (gzip -t) on the gzip file.
    die("integrity check on gzip file failed (file transfer failed or ".
        " file in URL not in gzip format?)\nExiting")
      if (system("gzip","-t","$filename"));

  # Decompress it.
    system("gzip","-d","$filename") and die("unable to uncompress $outfile.\nExiting");

  # Suffix has now changed from .tar.gz to .tar.
    $filename =~ s/\.gz$//;

  # Run integrity check on the tar file (by doing a "tar tf"
  # on it and checking the return value).
    die("integrity check on tar file failed (file transfer failed or ".
        "file in URL not a compressed tar file?)\nExiting")
      if (system("tar tf \"$filename\" >/dev/null"));

  # Look for uncool stuff in the archive.
    if (open(TAR,"-|")) {
        @_ = <TAR>;                           # Read output of the "tar vtf" command into @_.
    } else {
        exec("tar","vtf","$filename")
          or die("Unable to execute untar/unpack command: $!\nExiting");
    }

    foreach $_ (@_) {
      # We don't want to have any weird characters in the tar file.
        die("Forbidden characters in tar archive. Offending file/line:\n$_\nExiting")
          if (/[^$ok_chars]/);
      # We don't want to unpack any "../../" junk.
        die("file in tar archive contains \"..\" in filename.\nOffending file/line:\n$_\nExiting")
          if (/\.\./);
      # Links in the tar archive are not allowed (should be detected because of illegal chars above though).
        die("file in tar archive contains link: refuse to unpack file.\nOffending file/line:\n$_\nExiting")
          if (/->/ || /=>/ || /==/);
    }

  # Looks good. Now we can finally untar it.
    print STDERR "Archive successfully downloaded, unpacking...\n" unless ($quiet);

    die("Failed to untar $filename\nExiting")
      if system("tar","xf","$filename");

    die("No \"rules/\" directory found in tar file.\nExiting")
      unless (-d "rules");

  # Change back to old dir.
    chdir("$old_dir") or die("could not change directory back to $tmpdir: $!\nExiting");
}



# Disable (#comment out) all rules listed in %sid_disable_list.
# All files will still be left in the temporary directory.
sub disable_rules
{
    my ($num_disabled, $msg, $sid, $line, $file);

    $num_disabled = 0;
    print STDERR "Disabling rules...\n" unless ($quiet);

    foreach $file (keys(%new_files)) {
        open(INFILE, "<$tmpdir/rules/$file") or die("could not open $tmpdir/rules/$file: $!\nExiting");
	@_ = <INFILE>;
        close(INFILE);

      # Write back to the same file.
	open(OUTFILE, ">$tmpdir/rules/$_") or die("could not open $tmpdir/rules/$_: $!\nExiting");
	RULELOOP:foreach $line (@_) {
            unless ($line =~ /$snort_rule_regexp/) {    # Only care about snort rules.
	        print OUTFILE $line;
		next RULELOOP;
	    }

	    ($msg, $sid) = ($1, $2);
            if (exists($sid_disable_list{$sid})) {      # should this sid be disabled?
                if ($verbose) {
                    $_ = $file;
                    $_ =~ s/.+\///;                     # remove path, just keep the filename.
                    $_ = sprintf("Disabling sid %-5s in file %-20s (%s)\n", $sid, $_, $msg);
                    print STDERR "$_";
                }
                $line = "#$line" unless ($line =~ /^\s*#/);
                $num_disabled++;
            } else {                     # Sid was not listed in the config file. Uncomment it to be
                $line =~ s/^\s*#*\s*//;  # sure, since some rules may be commented by default.
            }

            print OUTFILE $line;       # Write line back to the rules file.
        }
        close(OUTFILE);
    }
    print STDERR "Disabled $num_disabled rules.\n" unless ($quiet)
}



sub setup_rule_hashes
{
    my ($file);

    foreach $file (keys(%new_files)) {
        open(NEWFILE, "$tmpdir/rules/$file") or die("could not open $tmpdir/rules/$file: $!\n");
	while (<NEWFILE>) {
	    if (/$snort_rule_regexp/) {
#print "sätter new_files($file)($2)\n";
#	        $new_files{"$file"}{"123"} = "foo";
$new_files{$file}{$2} = $_;
	    } else {
#	        $new_files{
	    }
	}
	close(NEWFILE);
    }

}

#### EOF ####
