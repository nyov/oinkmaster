#!/usr/bin/perl -w

# $Id$ #

use strict;
use Cwd;
use File::Copy;
use Getopt::Std;
use POSIX qw(strftime);

sub show_usage();
sub parse_cmdline();
sub read_config($ $);
sub sanity_check();
sub download_rules($ $);
sub unpack_rules_archive($);
sub disable_and_modify_rules($ $ @);
sub setup_rules_hash($ $ @);
sub find_line($ $);
sub print_changes($ $);
sub make_backup($ $);
sub get_modified_files($ $);
sub get_changes($ $);
sub get_new_filenames($ $);
sub update_rules($ @);
sub clean_exit($);


my $VERSION           = 'Oinkmaster v0.7 by Andreas Östling <andreaso@it.su.se>';
my $TMPDIR            = "/tmp/oinkmaster.$$";

my $config_file       = "/usr/local/etc/oinkmaster.conf";
my $outfile           = "snortrules.tar.gz";
my $verbose           = 0;
my $careful           = 0;
my $quiet             = 0;
my $check_removed     = 0;
my $preserve_comments = 1;

# Regexp to match a snort rule line.
# Multiline rules are currently not handled, but at this time,
# all of the official rules are one rule per line. The msg string
# will go into $1 and the sid will go into $2 if the regexp matches.
my $SNORT_RULE_REGEXP = '^\s*#*\s*(?:alert|log|pass) .+msg\s*:\s*"(.+?)"\s*;.+sid\s*:\s*(\d+)\s*;';

use vars qw
   (
      $opt_b $opt_c $opt_C $opt_e $opt_h $opt_o
      $opt_q $opt_r $opt_u $opt_v $opt_V
   );

my (
      $output_dir, $backup_dir
   );

my (
      %config, %new_files, %rh
   );



#### MAIN ####

# No buffering.
select(STDERR);
$| = 1;
select(STDOUT);
$| = 1;

my $start_date = scalar(localtime);

# Parse command line arguments. Will exit if something is wrong.
parse_cmdline();

# Why would anyone want to run as root?
die("Don't run as root!") if (!$>);

# Create empty temporary directory. Die if we can't create unique filename.
mkdir("$TMPDIR", 0700)
  or die("Could not create temporary directory $TMPDIR: $!\nExiting");

# Read in $config_file. Will exit if something is wrong.
read_config($config_file, \%config);

# Do some basic sanity checking and exit if something fails.
# A new PATH will be set.
sanity_check();

# Download the rules archive.
# This will leave us with the file $TMPDIR/$outfile
# (/tmp/oinkmaster.$$/snortrules.tar.gz). Will exit if download fails.
download_rules("$config{'url'}", "$TMPDIR/$outfile");

# Verify and unpack archive. This will leave us with a directory
# called "rules/" in the same directory as the archive, containing the
# new rules. Will exit if something fails.
unpack_rules_archive("$TMPDIR/$outfile");

# Create list of new files that we care about from the downloaded archive.
# Filenames (with full path) will be stored as %new_files{filenme}.
# Make sure there is at least one file to be updated.
if (get_new_filenames(\%new_files, "$TMPDIR/rules/") < 1) {
    clean_exit("no rules files found in downloaded archive.")
}

# Disable (#comment out) all sids listed in conf{sid_disable_list}
# and modify sids listed in conf{sid_modify_list}.
# Will open each file listed in %new_files, make modifications, and
# write back to the same file.
disable_and_modify_rules(\%{$config{sid_disable_list}},
                         \%{$config{sid_modify_list}}, keys(%new_files));

# Setup rules hash.
setup_rules_hash(\%rh, $output_dir, keys(%new_files));

# Compare the new rules to the old ones.
my %changes = get_changes(\%rh, keys(%new_files));

# Get list of modified files (with full path to the new file).
my @modified_files = get_modified_files(\%changes, \%new_files);

# Update files listed in @modified_files (move the new files from the temporary
# directory into our output directory), unless we're running in careful mode.
# Create backup first if running with -b.
if ($#modified_files > -1) {
    if ($careful) {
        print STDERR "No need to backup old files (running in careful mode), skipping.\n"
          if (defined($backup_dir) && (!$quiet));
    }  else {
        make_backup($output_dir, $backup_dir)
          if (defined($backup_dir));
        update_rules($output_dir, @modified_files);
    }
} else {
    print STDERR "No files modified - no need to backup old files, skipping.\n"
      if (defined($backup_dir) && !$quiet);
}

# Print changes.
my $something_changed = 0;

$something_changed = 1
  if ($#modified_files > -1 ||
      keys(%{$changes{added_files}}) > 0 || keys(%{$changes{removed_files}}) > 0);

if ($something_changed || !$quiet) {
    print "\nNote: Oinkmaster is running in careful mode - not updating/adding anything.\n"
      if ($careful && $something_changed);
    print_changes(\%changes, \%rh);
}

# Everything worked. Do a clean exit without any error message.
clean_exit("");

# END OF MAIN #



# Show usage information and exit.
sub show_usage()
{
    print STDERR << "RTFM";

$VERSION

Usage: $0 -o <dir> [options]

<dir> is where to put the new files.
This should be the directory where you store your snort.org rules.
Note that your current files will be overwritten by the new ones
if they had been modified.

Options:
-b <dir>   Backup old rules into <dir> before overwriting them
-c         Careful mode - only check for changes, but do not update anything
-C <cfg>   Use this config file instead of $config_file
-e         Re-enable all rules that are disabled by default in the rules
           distribution (they are disabled for a reason so use with care)
-h         Show this usage information

-q         Quiet mode - no output unless changes were found
-r         Check for rules files that exist in the output directory
           but not in the downloaded rules archive (i.e. files that may
           have been removed from the distribution archive)
-u <url>   Download from this URL (http://, ftp:// or file:// ...tar.gz)
           instead of the URL specified in the configuration file
-v         Verbose mode
-V         Show version and exit

RTFM
    exit;
}



# Parse the command line arguments and exit if we don't like them.
sub parse_cmdline()
{
    my $cmdline_ok = getopts('b:cC:eho:pqru:vV');

    $backup_dir    = $opt_b if (defined($opt_b));
    $config_file   = $opt_C if (defined($opt_C));
    $config{url}   = $opt_u if (defined($opt_u));
    $careful           = 1  if (defined($opt_c));
    $preserve_comments = 0  if (defined($opt_e));
    $quiet             = 1  if (defined($opt_q));
    $check_removed     = 1  if (defined($opt_r));
    $verbose           = 1  if (defined($opt_v));
    show_usage()            if (defined($opt_h));
    die("$VERSION\n")       if (defined($opt_V));

    show_usage unless ($cmdline_ok);

  # -o <dir> is the only required option in normal usage.
    if (defined($opt_o)) {
        $output_dir = $opt_o;
    } else {
        show_usage();
    }

  # Don't accept additional arguments, since they're invalid.
    $_ = shift(@ARGV) && show_usage();

  # Remove possible trailing slashes (just for cosmetic reasons).
    $output_dir =~ s/\/+$//;
    $backup_dir =~ s/\/+$// if (defined($backup_dir));
}



# Read in stuff from the configuration file.
sub read_config($ $)
{
    my $config_file = shift;
    my $cfgref      = shift;
    my $linenum     = 0;

    unless (-e "$config_file") {
        clean_exit("configuration file \"$config_file\" does not exist.\n".
                   "Put it there or use the -C argument.");
    }

    open(CONF, "<$config_file")
      or clean_exit("could not open config file \"$config_file\": $!");

    while (<CONF>) {
        $linenum++;

      # Remove comments unless it's a modifysid line.
        s/\s*\#.*// unless (/^\s*modifysid/i);

      # Remove leading/traling whitespaces.
	s/^\s*//;
	s/\s*$//;

      # Skip blank lines.
        next unless (/\S/);

        if (/^disablesids*\s+(\d.*)/i) {                   # disablesid <SID[,SID, ...]>
	    my $args = $1;
	    foreach $_ (split(/\s*,\s*/, $args)) {
  	        if (/^\d+$/) {
                    $$cfgref{sid_disable_list}{$_}++;
	        } else {
                    warn("WARNING: line $linenum in $config_file is invalid, ignoring\n")
	        }
	    }
        } elsif (/^modifysid\s+(\d+)\s+(.*)/i) {         # modifysid <SID> <regexp>
            push(@{$$cfgref{sid_modify_list}{$1}}, $2);
        } elsif (/^skipfiles*\s+(.*)/i) {                # skipfile <file[,file, ...]>
	    my $args = $1;
	    foreach $_ (split(/\s*,\s*/, $args)) {
	        if (/^\S.*\S$/) {
                    $verbose && print STDERR "Adding file to ignore list: $_.\n";
                    $$cfgref{file_ignore_list}{$_}++;
		} else {
                    warn("WARNING: line $linenum in $config_file is invalid, ignoring\n")
		}
	    }
	} elsif (/^url\s*=\s*(.*)/i) {                   # URL to use
	    $$cfgref{url} = $1
              unless (exists($$cfgref{url}));            # may already be defined by -u <url>
	} elsif (/^path\s*=\s*(.*)/i) {                  # $PATH to be used
	    $$cfgref{path} = $1;
	} elsif (/^update_files\s*=\s*(.*)/i) {          # regexp of files to be updated
	    $$cfgref{update_files} = $1;
        } else {                                         # invalid line
            warn("WARNING: line $linenum in $config_file is invalid, ignoring\n")
        }
    }
    close(CONF)
}



# Make a few basic tests to make sure things look ok.
# Will also set a new PATH as defined in the config file.
sub sanity_check()
{
   my @req_config   = qw (path update_files);  # Required parameters in oinkmaster.conf.
   my @req_binaries = qw (which gzip rm tar);  # These binaries are always required.

  # Can't use both -q and -v.
    clean_exit("both quiet mode and verbose mode at the same time doesn't make sense.")
      if ($quiet && $verbose);

  # Make sure all required variables are defined in the config file.
    foreach $_ (@req_config) {
        clean_exit("the required parameter \"$_\" is not defined in $config_file.")
          unless (exists($config{$_}));
    }

  # We now know a path was defined in the config, so set it. Also reset IFS.
    $ENV{"PATH"} = $config{path};
    $ENV{'IFS'}  = '';

  # Make sure all required binaries can be found.
  # (Wget is not required if user specifies file:// as url. That check is done below.)
    foreach $_ (@req_binaries) {
        clean_exit("\"$_\" binary not found ".
                   "(perhaps you must edit $config_file and change 'path').")
          if (system("which \"$_\" >/dev/null 2>&1"));
    }

  # Make sure $url is defined (either by -u <url> or url=... in the conf).
    clean_exit("incorrect URL or URL not specified in neither $config_file nor command line.")
      unless (exists($config{'url'}) &&
        $config{'url'}  =~ /^(?:http|ftp|file):\/\/\S+.*\.tar\.gz$/);

  # Wget must be found if url is http:// or ftp://.
    clean_exit("\"wget\" binary not found ".
               "(perhaps you must edit $config_file and change 'path').")
      if ($config{'url'} =~ /^(http|ftp):/ && system("which \"wget\" >/dev/null 2>&1"));

  # Make sure the output directory exists and is readable.
    clean_exit("the output directory \"$output_dir\" doesn't exist or isn't readable by you.")
      if (!-d "$output_dir" || !-x "$output_dir");

  # Make sure the output directory is writable unless running in careful mode.
    clean_exit("the output directory \"$output_dir\" isn't writable by you.")
      if (!$careful && !-w "$output_dir");

  # Make sure the backup directory exists and is writable if running with -b.
    clean_exit("the backup directory \"$backup_dir\" doesn't exist or isn't writable by you.")
      if (defined($backup_dir) && (!-d "$backup_dir" || !-w "$backup_dir"));
}



# Download the rules archive.
sub download_rules($ $)
{
    my $url       = shift;
    my $localfile = shift;

    if ($url =~ /^(?:http|ftp)/) {     # use wget if URL starts with "http" or "ftp"
        print STDERR "Downloading rules archive from $url...\n"
          unless ($quiet);
        if ($quiet) {
            clean_exit("unable to download rules (got error code from wget).\n".
                       "Consider running in non-quiet mode if the problem persists.")
              if (system("wget","-q","-O","$localfile","$url"));         # quiet mode
        } elsif ($verbose) {
            clean_exit("unable to download rules (got error code from wget).")
              if (system("wget","-v","-O","$localfile","$url"));         # verbose mode
        } else {
            clean_exit("unable to download rules (got error code from wget).")
              if (system("wget","-nv","-O","$localfile","$url"));        # normal mode
        }
    } elsif ($url =~ /^file/) {        # grab file from local filesystem
        $url =~ s/^file:\/\///;        # remove "file://", the rest is the actual filename
	clean_exit("the file $url does not exist.")
          unless (-e "$url");
        print STDERR "Copying rules archive from $url... "
          unless ($quiet);
        copy("$url", "$localfile")
          or clean_exit("unable to copy $url to $localfile: $!");
        print STDERR "done.\n" unless ($quiet);
    }

  # Make sure the downloaded file is at least non-empty.
    unless (-s "$localfile") {
        clean_exit("failed to get rules archive: file $localfile ".
                   "doesn't exist or hasn't non-zero size after download.");
    }
}



# Make a few basic sanity checks on the rules archive and then 
# uncompress/untar it if everything looked ok.
sub unpack_rules_archive($)
{
    my $archive  = shift;
    my $ok_lead  = 'a-zA-Z0-9_\.';       # allowed leading char in filenames in the tar archive
    my $ok_chars = 'a-zA-Z0-9_\.\-/';    # allowed chars in filenames in the tar archive

    my ($dir) = ($archive =~ /(.*)\//);  # extract directory part of the filename

    my $old_dir = getcwd or clean_exit("could not get current directory: $!");
    chdir("$dir") or clean_exit("could not change directory to \"$dir\": $!");

  # Run integrity check (gzip -t) on the gzip file.
    clean_exit("integrity check on gzip file failed (file transfer failed or ".
               "file in URL not in gzip format?).")
      if (system("gzip","-t","$archive"));

  # Decompress it.
    system("gzip","-d","$archive") and clean_exit("unable to uncompress $archive.");

  # Suffix has now changed from .tar.gz to .tar.
    $archive =~ s/\.gz$//;

  # Read output from "tar tf $archive" into @_.
    if (open(TAR,"-|")) {
        @_ = <TAR>;
    } else {
        exec("tar","tf","$archive")
          or die("Unable to execute untar/unpack command: $!\nExiting");
    }

  # For each filename in the archive...
    foreach $_ (@_) {
       chomp;

      # Make sure the leading char is valid (not an absolute path, for example).
        clean_exit("forbidden leading character in filename in tar archive. ".
                   "Offending file/line:\n$_")
          unless (/^[$ok_lead]/);

      # We don't want to have any weird characters anywhere in the filename.
        clean_exit("forbidden characters in filename in tar archive. ".
                   "Offending file/line:\n$_")
          if (/[^$ok_chars]/);

      # We don't want to unpack any "../../" junk.
        clean_exit("filename in tar archive contains \"..\".\nOffending file/line:\n$_")
          if (/\.\./);
    }

  # Looks good. Now we can untar it.
    print STDERR "Archive successfully downloaded, unpacking... "
      unless ($quiet);
    clean_exit("failed to untar $archive.")
      if system("tar","xf","$archive");
    clean_exit("no \"rules/\" directory found in tar file.")
      unless (-d "$dir/rules");

    chdir("$old_dir") or clean_exit("could not change directory back to $old_dir: $!");

    print STDERR "done.\n" unless ($quiet);
}



# Open all rules files in the temporary directory and disable (#comment out)
# all rules in listed in the disable list and then write back to the same files.
sub disable_and_modify_rules($ $ @)
{
    my $disable_sid_ref = shift;
    my $modify_sid_ref  = shift;
    my @newfiles        = @_;

    my $num_disabled    = 0;

    if (!$preserve_comments && !$quiet) {
        warn("Warning: all rules that are disabled by default will be re-enabled\n");
    }

    print STDERR "Disabling rules according to $config_file... "
      unless ($quiet);
    print STDERR "\n"
      if ($verbose);

    foreach my $file (@newfiles) {
        open(INFILE, "<$file")
          or clean_exit("could not open $file for reading: $!");
	@_ = <INFILE>;
        close(INFILE);

      # Write back to the same file.
	open(OUTFILE, ">$file")
          or clean_exit("could not open $file for writing: $!");

	RULELOOP:foreach my $line (@_) {

          # Only care about snort rules we understand.
          # (The other lines are printed right back to the file.)
            unless ($line =~ /$SNORT_RULE_REGEXP/) {

	      # Our regexp didn't match, but make a less strict check to see if
              # it's likely to be a Snort rule anyway. If it is, then print a warning.
              # Only care about active rules to avoid false alarms.
   	        if ($line =~ /^\s*(?:alert|log|pass) .*msg.*;\)\n$/) {
		    $_ = $file;
                    $_ =~ s/.*\///;    # remove path
		    warn("\nWARNING: I don't understand this rule in downloaded file $_ ".
                         "(perhaps bad syntax or missing SID etc?):\n$line");
                }

              # Write this non-rule line right back to the same file.
	        print OUTFILE $line;
		next RULELOOP;
	    }

          # We've got a valid snort rule. Grab msg and sid.
   	    my ($msg, $sid) = ($1, $2);

          # Some rules may be commented out by default. Enable them if -e is specified.
	    if ($line =~ /^\s*#/) {
		if ($preserve_comments) {
		    print STDERR "Preserving disabled rule (sid $sid): $msg\n"
		      if ($verbose);
		} else {
		    print STDERR "Enabling disabled rule (sid $sid): $msg\n"
		      if ($verbose);
		    $line =~ s/^\s*#*//;
		}
	    }

          # Modify rule if requested.
            foreach my $regexp (@{$$modify_sid_ref{$sid}}) {
	        print STDERR "Modifying sid $sid with expression: $regexp\n  Before: $line"
		  if ($verbose);
		eval "\$line =~ $regexp";
		warn("WARNING: error in expression \"$regexp\": $@\n")
		  if ($@);
		print STDERR "  After: $line\n"
                  if ($verbose);
	    }

          # Disable rule if requested.
            if (exists($$disable_sid_ref{"$sid"})) {
                print STDERR "Disabling sid $sid: $msg\n"
                  if ($verbose);
                $line = "#$line" unless ($line =~ /^\s*#/);
                $num_disabled++;
	    }

	  # Make sure the rule ends with a \n.
          # (User may have screwed up with a modifysid.)
	    chomp($line);
	    $line .= "\n";

          # Write rule back to the same rules file.
            print OUTFILE $line;
        }

        close(OUTFILE);
    }
    print STDERR "$num_disabled rules disabled.\n"
      unless ($quiet)
}



# Setup rules hash.
# Format for rules will be:     rh{old|new}{rules{filename}{sid} = rule
# Format for non-rules will be: rh{old|new}{other}{filename}     = array of lines
# List of added files will be stored as rh{added_files}{filename}
sub setup_rules_hash($ $ @)
{
    my $rh_ref    = shift;
    my $old_dir   = shift;
    my @new_files = shift;

    foreach my $file (keys(%new_files)) {
        warn("WARNING: downloaded rules file $file is empty (maybe correct, maybe not)\n")
          if (!-s "$file" && $verbose);

        open(NEWFILE, "<$file")
          or clean_exit("could not open $file for reading: $!");

      # From now on we don't care about the path, so remove it.
	$file =~ s/.*\///;

	while (<NEWFILE>) {
            s/\s*\n$/\n/;                    # remove trailing whitespaces (for rules and non-rules)

	    if (/$SNORT_RULE_REGEXP/) {      # add rule line to hash
	        my $sid = $2;
  	        s/^\s*//;                    # remove leading whitespaces
		s/^#+\s*/#/;                 # remove whitespaces next to the leading #

		warn("WARNING: duplicate SID in downloaded rules archive in file ".
                     "$file: SID $sid\n")
		  if (exists($$rh_ref{new}{rules}{"$file"}{"$sid"}));
		$$rh_ref{new}{rules}{"$file"}{"$sid"} = $_;
	    } else {                         # add non-rule line to hash
	        push(@{$$rh_ref{new}{other}{"$file"}}, $_);
	    }
	}

	close(NEWFILE);

	# Also read in old file if it exists.
        if (-f "$output_dir/$file") {
            open(OLDFILE, "<$output_dir/$file")
              or clean_exit("could not open $output_dir/$file for reading: $!");

	    while (<OLDFILE>) {

	        s/\s*\n$/\n/;                # remove trailing whitespaces (for rules and non-rules)

                if (/$SNORT_RULE_REGEXP/) {  # add rule line to hash
		    my $sid = $2;
		    s/^\s*//;                # remove leading whitespaces
		    s/^#+\s*/#/;             # remove whitespaces next to the leading #

		    warn("WARNING: duplicate SID in your local rules in file ".
                         "$file: SID $sid\n")
	  	      if (exists($$rh_ref{old}{rules}{"$file"}{"$sid"}));
	  	    $$rh_ref{old}{rules}{"$file"}{"$sid"} = $_;
                } else {                     # add non-rule line to hash
	            push(@{$$rh_ref{old}{other}{"$file"}}, $_);
                }
            }

            close(OLDFILE);
        } else {                             # downloaded file did not exist in old rules dir
	    $$rh_ref{added_files}{"$file"}++;
        }
    }
}



# Try to find a given string in a given array. Return 1 if found, or 0 if not.
# Some things will always be considered as found (lines that we don't care if
# they were added/removed). It's extremely slow and braindead, but who cares.
sub find_line($ $)
{
    my $line    = shift;   # line to look for
    my $arr_ref = shift;   # reference to array to look in

    return 1 unless ($line =~ /\S/);                         # skip blank lines
    return 1 if     ($line =~ /^\s*#+\s*\$I\S:.+Exp\s*\$/);  # also skip CVS Id tag

    foreach $_ (@$arr_ref) {
        return 1 if ($_ eq $line);                           # string found
    }

    return 0;                                                # string not found
}



# Backup files in $output_dir matching $config{update_files} into $backup_dir.
sub make_backup($ $)
{
    my $src_dir  = shift;    # dir with the rules to be backed up
    my $dest_dir = shift;    # where to put the tarball containing the backed up rules

    my $date       = strftime("%Y%m%d-%H%M", localtime);
    my $bu_tmp_dir = "$TMPDIR/rules-backup-$date";

    print STDERR "Creating backup of old rules..."
      unless ($quiet);

    mkdir("$bu_tmp_dir", 0700)
      or clean_exit("could not create temporary backup directory $bu_tmp_dir: $!");

  # Copy all rules files from the rules dir to the temporary backup dir.
    opendir(OLDRULES, "$src_dir")
      or clean_exit("could not open directory $src_dir: $!");

    while ($_ = readdir(OLDRULES)) {
        copy("$src_dir/$_", "$bu_tmp_dir/")
          or warn("WARNING: error copying $src_dir/$_ to $bu_tmp_dir: $!")
            if (/$config{update_files}/ && !exists($config{file_ignore_list}{$_}));
    }

    closedir(OLDRULES);

  # Change directory to $TMPDIR (so we'll be right below the directory where
  # we have our rules to be backed up).
    my $old_dir = getcwd or clean_exit("could not get current directory: $!");
    chdir("$TMPDIR")     or clean_exit("could not change directory to $TMPDIR: $!");

  # Execute tar command. This will archive "rules-backup-$date/"
  # into the file rules-backup-$date.tar, placed in $TMPDIR.
    warn("WARNING: tar command did not exit with status 0 when archiving backup files.\n")
      if (system("tar","cf","rules-backup-$date.tar","rules-backup-$date"));

  # Compress it.
    warn("WARNING: gzip command did not exit with status 0 when compressing backup file.\n")
      if (system("gzip","rules-backup-$date.tar"));

  # Change back to old directory (so it will work with -b <directory> as either
  # an absolute or a relative path.
    chdir("$old_dir") or clean_exit("could not change directory back to $old_dir: $!");

  # Move the archive to the backup directory.
    move("$TMPDIR/rules-backup-$date.tar.gz", "$backup_dir/")
      or warn("WARNING: unable to move $TMPDIR/rules-backup-$date.tar.gz to $backup_dir/: $!\n");

    print STDERR " saved as $backup_dir/rules-backup-$date.tar.gz.\n"
      unless ($quiet);
}



# Print all changes.
sub print_changes($ $)
{
    my $ch_ref = shift;
    my $rh_ref = shift;

    print "\n[***] Results from Oinkmaster started " . scalar(localtime) . " [***]\n";


  # Print rules changes.
    print "\n[*] Rules modifications: [*]\n";

    foreach my $type (sort(keys(%{$$ch_ref{rules}}))) {
        print "\n  $type\n";

        foreach my $file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{rules}{"$type"}}))) {

            print "\n     -> File $file:\n";
            foreach my $sid (keys(%{$$ch_ref{rules}{"$type"}{"$file"}})) {
	      # Print old and new if the rule was modified.
	        if ($type =~ /modified/i) {
	            print "        old: $rh{old}{rules}{$file}{$sid}";
	            print "        new: $rh{new}{rules}{$file}{$sid}";
	      # Print only the new one if the rule was added, enabled or disabled.
	        } elsif ($type =~ /added/i || $type =~ /enabled/i || $type =~ /disabled/i) {
	            print "        $rh{new}{rules}{$file}{$sid}";
	      # Print only the old one if the rule was removed.
		} elsif ($type =~ /removed/i) {
	            print "        $rh{old}{rules}{$file}{$sid}";
		}
  	    }
        }
    }
    print "    None.\n" if (keys(%{$$ch_ref{rules}}) < 1);


  # Print non-rule changes.
    print "\n[*] Non-rule changes: [*]\n";

  # Print added non-rule lines.
    if (keys(%{$$ch_ref{other}{added}}) > 0) {
        print "\n  [+++]       Added lines:       [+++]\n";
        foreach my $file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{other}{added}}))) {
            print "\n     -> File $file:\n";
            foreach my $other (@{$$ch_ref{other}{added}{$file}}) {
	        print "        $other";
            }
        }
    }


  # Print removed non-rule lines.
    if (keys(%{$$ch_ref{other}{removed}}) > 0) {
        print "\n  [---]      Removed lines:      [---]\n";
        foreach my $file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{other}{removed}}))) {
            print "\n     -> File $file:\n";
            foreach my $other (@{$$ch_ref{other}{removed}{$file}}) {
	        print "        $other";
            }
        }
    }

    print "    None.\n"
      if (keys(%{$$ch_ref{other}{removed}}) < 1) && (keys(%{$$ch_ref{other}{added}}) < 1);


  # Print list of added files.
    if (keys(%{$$ch_ref{added_files}}) > 0) {
        print "\n[*] Files added (consider updating your snort.conf to include them): [*]\n";
        foreach my $added_file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{added_files}}))) {
            print "    -> $added_file\n";
        }
    } else {
         print "\n[*] Added files: [*]\n" .
               "    None.\n";
    }


  # Print list of possibly removed files, if requested.
    if ($check_removed) {
        if (keys(%{$$ch_ref{removed_files}}) > 0) {
            print "\n[*] Files possibly removed from the archive ".
                  "(consider removing them from your snort.conf): [*]\n";
            foreach my $removed_file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{removed_files}}))) {
                print "    -> $removed_file\n";
	    }
        } else {
             print "\n[*] Files possibly removed from the archive: [*]\n" .
                   "    None.\n";
        }
    }

    print "\n";
}



# Return list of modified files (with full path).
sub get_modified_files($ $)
{
    my $changes_ref   = shift;    # ref to hash with all changes
    my $new_files_ref = shift;    # ref to hash with all new files (with full path)

    my %modified_files;

  # For each new rules file...
    foreach my $file_w_path (keys(%$new_files_ref)) {
        my $file = $file_w_path;
            $file =~ s/.*\///;    # remove path

      # Check if there were any rules changes in this file.
        foreach my $type (keys(%{$changes{rules}})) {
	     $modified_files{"$file_w_path"}++
               if (exists($changes{rules}{"$type"}{"$file"}));
        }

      # Check if there were any non-rule changes in this file.
        foreach my $type (keys(%{$changes{other}})) {
            $modified_files{"$file_w_path"}++
              if (exists($changes{other}{"$type"}{"$file"}));
        }

      # Added files are also regarded as modified
      # since we want to update (add) those as well.
      # We only have a list of added files without the full path,
      # so that's why we have to do the special check below.
        foreach my $added_file (keys(%{$rh{added_files}})) {
            $modified_files{"$file_w_path"}++
              if ($added_file eq $file);
        }
    }

    return(keys(%modified_files));
}



# Compare the new rules to the old ones.
# For each rule in the new file, check if the rule also exists
# in the old file. If it does then check if it has been modified,
# but if it doesn't, it must have been added.
sub get_changes($ $)
{
    my %changes;

    print STDERR "Comparing new files to the old ones... "
      unless ($quiet);

  # We have the list of added files in $rh{added_files}, but we'd rather
  # want to have it in $changes{added_files} now.
    $changes{added_files} = $rh{added_files};

  # Add list of possibly removed files into $removed_files, if requested.
    if ($check_removed) {
        opendir(OLDRULES, "$output_dir")
          or clean_exit("could not open directory $output_dir: $!");

        while ($_ = readdir(OLDRULES)) {
            $changes{removed_files}{"$_"}++
              if (/$config{update_files}/ && !exists($config{file_ignore_list}{$_}) && 
                  !-e "$TMPDIR/rules/$_");
        }

        closedir(OLDRULES);
    }

  # Compare the rules.
    FILELOOP:foreach my $file_w_path (keys(%new_files)) {       # for each new file
        my $file = $file_w_path;
        $file =~ s/.*\///;                                      # remove path
        next FILELOOP if (exists($rh{added_files}{$file}));     # skip diff if it's an added file

        foreach my $sid (keys(%{$rh{new}{rules}{$file}})) {     # for each sid in the new file
            my $new_rule = $rh{new}{rules}{$file}{$sid};

                if (exists($rh{old}{rules}{$file}{$sid})) {     # also exists in the old file?
                    my $old_rule = $rh{old}{rules}{$file}{$sid};

		    unless ($new_rule eq $old_rule) {           # are they identical?
                        if ("#$old_rule" eq $new_rule) {                          # rule disabled?
 	                    $changes{rules}{"[---]          Disabled:         [---]"}{$file}{$sid}++;
                        } elsif ($old_rule eq "#$new_rule") {                     # rule enabled?
 	                    $changes{rules}{"[+++]          Enabled:          [+++]"}{$file}{$sid}++;
                        } elsif ($old_rule =~ /^\s*#/ && $new_rule !~ /^\s*#/) {  # rule enabled and modified?
 	                    $changes{rules}{"[+++]    Enabled and modified:   [+++]"}{$file}{$sid}++;
                        } elsif ($old_rule !~ /^\s*#/ && $new_rule =~ /^\s*#/) {  # rule disabled and modified?
 	                    $changes{rules}{"[---]    Disabled and modified:  [---]"}{$file}{$sid}++;
                        } elsif ($old_rule =~ /^\s*#/ && $new_rule =~ /^\s*#/) {  # inactive rule modified?
 	                    $changes{rules}{"[///]      Modified inactive:    [///]"}{$file}{$sid}++;
                        } else {                                                  # active rule modified?
 	                    $changes{rules}{"[///]       Modified active:     [///]"}{$file}{$sid}++;
	  	        }
		    }
	        } else {    # sid not found in old file so it must have been added
  	            $changes{rules}{"[+++]           Added:           [+++]"}{$file}{$sid}++;
	        }
        } # foreach sid

      # Check for removed rules, i.e. sids that exist in the old file but not in the new one.
        foreach my $sid (keys(%{$rh{old}{rules}{$file}})) {
            unless (exists($rh{new}{rules}{$file}{$sid})) {
	        $changes{rules}{"[---]          Removed:          [---]"}{$file}{$sid}++;
            }
        }

      # Check for added non-rule lines.
        foreach my $other_added (@{$rh{new}{other}{$file}}) {
            unless (find_line($other_added, \@{$rh{old}{other}{"$file"}})) {
	        push(@{$changes{other}{added}{$file}}, $other_added);
            }
        }

      # Check for removed non-rule lines.
        foreach my $other_removed (@{$rh{old}{other}{$file}}) {
            unless (find_line($other_removed, \@{$rh{new}{other}{"$file"}})) {
	        push(@{$changes{other}{removed}{$file}}, $other_removed);
            }
        }

    } # foreach new file

    print STDERR "done.\n" unless ($quiet);

    return(%changes);
}



# Create list of new files (with full path) that we care about.
# I.e. files that match the 'update_files' regexp and isn't listed
# in the ignore list.
sub get_new_filenames($ $)
{
    my $fn_ref    = shift;
    my $rules_dir = shift;

    opendir(NEWRULES, "$rules_dir")
      or clean_exit("could not open directory $rules_dir: $!");

    while ($_ = readdir(NEWRULES)) {
        $new_files{"$rules_dir/$_"}++
          if (/$config{update_files}/ && !exists($config{file_ignore_list}{$_}));
    }
    closedir(NEWRULES);

  # Return number of new interesting filenames.
    return(keys(%$fn_ref));
}



# Copy modified rules to the output directory.
sub update_rules($ @)
{
    my $dst_dir = shift;
    my @files   = @_;

    foreach my $file_w_path (@files) {
        my $file = $file_w_path;
        $file =~ s/.*\///;    # remove path
        move("$file_w_path", "$output_dir/$file")
          or clean_exit("could not move $file_w_path to $file: $!")
    }
}



# Remove temporary directory and exit. 
# If a non-empty string is given as argument, it will be regarded
# as an error message and we will use die() with the message instead
# of just exit(0).
sub clean_exit($)
{
    system("/bin/rm","-r","-f","$TMPDIR")
      and warn("WARNING: unable to remove temporary directory $TMPDIR.\n");

    if ($_[0] ne "") {
        $_ = $_[0];
	chomp;
        die("\n$0: Error: $_\nOink, oink. Exiting...\n");
    } else {
        exit(0);
    }
}



#### EOF ####
