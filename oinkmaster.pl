#!/usr/bin/perl -w

# $Id$ #

use strict;
use Cwd;
use File::Copy;
use Getopt::Std;

sub show_usage();
sub parse_cmdline($);
sub read_config($ $);
sub sanity_check();
sub download_rules($ $);
sub unpack_rules_archive($);
sub disable_and_modify_rules($ $ $);
sub setup_rules_hash($);
sub find_line($ $);
sub print_changes($ $);
sub print_changetype($ $ $);
sub make_backup($ $);
sub get_modified_files($ $);
sub get_changes($ $);
sub get_new_filenames($ $);
sub update_rules($ @);
sub is_in_path($);
sub get_next_entry($ $ $ $);
sub make_tempdir($);
sub clean_exit($);


my $VERSION           = 'Oinkmaster v0.8 by Andreas Östling <andreaso@it.su.se>';
my $TMP_BASEDIR       = "/tmp";

my $PRINT_NEW         = 1;
my $PRINT_OLD         = 2;
my $PRINT_BOTH        = 3;

my $config_file       = "/usr/local/etc/oinkmaster.conf";
my $outfile           = "snortrules.tar.gz";

my $verbose           = 0;
my $careful           = 0;
my $quiet             = 0;
my $super_quiet       = 0;
my $check_removed     = 0;
my $preserve_comments = 1;

# Regexp to match a snort rule line.
# Multiline rules are currently not handled, but at this time,
# all of the official rules are one rule per line. The msg string
# will go into $1 and the sid will go into $2 if the regexp matches.
my $SNORT_RULE_REGEXP = '^\s*#*\s*(?:alert|log|pass)\s.+msg\s*:\s*"(.+?)"\s*;.+sid\s*:\s*(\d+)\s*;.*\)\s*$';

# Regexp to match the start (the first line) of a possible multi-line rule.
my $SNORT_MULTILINE_REGEXP = '^\s*#*\s*(?:alert|log|pass)\s.*\\\s*\n$';


use vars qw
   (
      $opt_b $opt_c $opt_C $opt_e $opt_h $opt_o
      $opt_q $opt_Q $opt_r $opt_u $opt_v $opt_V
   );

my (
      %config, %new_files
   );



#### MAIN ####

# No buffering.
select(STDERR);
$| = 1;
select(STDOUT);
$| = 1;

my $start_date = scalar(localtime);

# Parse command line arguments and add at least %config{output_dir}.
# Will exit if something is wrong.
parse_cmdline(\%config);

# Read in $config_file. Will exit if something is wrong.
read_config($config_file, \%config);

# Create empty temporary directory.
my $tmpdir = make_tempdir(exists($config{tmpdir}) ? $config{tmpdir} : $TMP_BASEDIR);

# Do some basic sanity checking and exit if something fails.
# A new PATH will be set.
sanity_check();

# Set new umask if one was specified in the config file.
umask($config{umask}) if exists($config{umask});

# Download the rules archive.
# This will leave us with the file $tmpdir/$outfile
# (/tmp/oinkmaster.$$/snortrules.tar.gz). Will exit if download fails.
download_rules("$config{'url'}", "$tmpdir/$outfile");

# Verify and unpack archive. This will leave us with a directory
# called "rules/" in the same directory as the archive, containing the
# new rules. Will exit if something fails.
unpack_rules_archive("$tmpdir/$outfile");

# Create list of new files that we care about from the downloaded archive.
# Filenames (with full path) will be stored as %new_files{filenme}.
# Make sure there is at least one file to be updated.
if (get_new_filenames(\%new_files, "$tmpdir/rules/") < 1) {
    clean_exit("no rules files found in downloaded archive.");
}

# Disable (#comment out) all sids listed in conf{sid_disable_list}
# and modify sids listed in conf{sid_modify_list}.
# Will open each file listed in %new_files, make modifications, and
# write back to the same file.
disable_and_modify_rules(\%{$config{sid_disable_list}},
                         \%{$config{sid_modify_list}}, \%new_files);

# Setup rules hash.
my %rh = setup_rules_hash(\%new_files);

# Compare the new rules to the old ones.
my %changes = get_changes(\%rh, \%new_files);

# Get list of modified files (with full path to the new file).
my @modified_files = get_modified_files(\%changes, \%new_files);

# Update files listed in @modified_files (move the new files from the temporary
# directory into our output directory), unless we're running in careful mode.
# Create backup first if running with -b.
if ($#modified_files > -1) {
    if ($careful) {
        print STDERR "No need to backup old files (running in careful mode), skipping.\n"
          if (exists($config{backup_dir}) && (!$quiet));
    }  else {
        make_backup($config{output_dir}, $config{backup_dir})
          if (exists($config{backup_dir}));
        update_rules($config{output_dir}, @modified_files);
    }
} else {
    print STDERR "No files modified - no need to backup old files, skipping.\n"
      if (exists($config{backup_dir}) && !$quiet);
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

Usage: $0 -o <output dir> [options]

<output dir> is where to put the new files.
This should be the directory where you store your snort.org rules.
Note that your current files will be overwritten by the new ones
if they had been modified.

Options:
-b <dir>   Backup your old rules into <dir> before overwriting them
-c         Careful mode - only check for changes, but do not update anything
-C <cfg>   Use this config file instead of $config_file
-e         Re-enable all rules that are disabled by default in the rules
           distribution (they are disabled for a reason, so use with care)
-h         Show this usage information
-q         Quiet mode - no output unless changes were found
-Q         über-quiet mode (like -q but even more quiet when printing results)
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
sub parse_cmdline($)
{
    my $cfg_ref    = shift;
    my $cmdline_ok = getopts('b:cC:eho:qQru:vV');

    $$cfg_ref{backup_dir} = $opt_b if (defined($opt_b));
    $config_file          = $opt_C if (defined($opt_C));
    $$cfg_ref{url}        = $opt_u if (defined($opt_u));
    $careful              = 1      if (defined($opt_c));
    $preserve_comments    = 0      if (defined($opt_e));
    $quiet                = 1      if (defined($opt_q));
    $check_removed        = 1      if (defined($opt_r));
    $verbose              = 1      if (defined($opt_v));

    if (defined($opt_Q)) {
        $quiet       = 1;
        $super_quiet = 1;
    }

    show_usage()                   if (defined($opt_h));
    die("$VERSION\n")              if (defined($opt_V));

    show_usage unless ($cmdline_ok);

  # -o <dir> is the only required option in normal usage.
    if (defined($opt_o)) {
        $$cfg_ref{output_dir} = $opt_o;
    } else {
        show_usage();
    }

  # Don't accept additional arguments, since they're invalid.
    $_ = shift(@ARGV) && show_usage();

  # Remove possible trailing slashes (just for cosmetic reasons).
    $$cfg_ref{output_dir} =~ s/\/+$//;
    $$cfg_ref{backup_dir} =~ s/\/+$// if (exists($$cfg_ref{backup_dir}));
}



# Read in stuff from the configuration file.
sub read_config($ $)
{
    my $config_file = shift;
    my $cfg_ref     = shift;
    my $linenum     = 0;

    unless (-e "$config_file") {
        die("configuration file \"$config_file\" does not exist.\n".
            "Put it there or use the -C argument.\n");
    }

    open(CONF, "<$config_file")
      or die("could not open config file \"$config_file\": $!");

    while (<CONF>) {
        $linenum++;

      # Remove comments unless it's a modifysid line.
        s/\s*\#.*// unless (/^\s*modifysid/i);

      # Remove leading/traling whitespaces.
	s/^\s*//;
	s/\s*$//;

      # Skip blank lines.
        next unless (/\S/);

        if (/^disablesids*\s+(\d.*)/i) {                 # disablesid <SID[,SID, ...]>
	    my $args = $1;
	    foreach my $sid (split(/\s*,\s*/, $args)) {
  	        if ($sid =~ /^\d+$/) {
                    $$cfg_ref{sid_disable_list}{$sid}++;
	        } else {
                    warn("WARNING: line $linenum in $config_file is invalid, ignoring\n");
	        }
	    }
        } elsif (/^modifysid\s+(\d+)\s+(".+"\s*\|\s*".+")/i) {   # modifysid <SID> "substthis" | "withthis"
            push(@{$$cfg_ref{sid_modify_list}{$1}}, $2);
        } elsif (/^skipfiles*\s+(.*)/i) {                # skipfile <file[,file, ...]>
	    my $args = $1;
	    foreach my $file (split(/\s*,\s*/, $args)) {
	        if ($file =~ /^\S+$/) {
                    $verbose && print STDERR "Adding file to ignore list: $file.\n";
                    $$cfg_ref{file_ignore_list}{$file}++;
		} else {
                    warn("WARNING: line $linenum in $config_file is invalid, ignoring\n");
		}
	    }
	} elsif (/^url\s*=\s*(.*)/i) {                   # URL to use
	    $$cfg_ref{url} = $1
              unless (exists($$cfg_ref{url}));           # may already be defined by -u <url>
	} elsif (/^path\s*=\s*(.*)/i) {                  # $PATH to be used
	    $$cfg_ref{path} = $1;
	} elsif (/^update_files\s*=\s*(.*)/i) {          # regexp of files to be updated
	    $$cfg_ref{update_files} = $1;
        } elsif (/^umask\s*=\s*([0-7]{3,4})$/i) {        # umask
	  $$cfg_ref{umask} = oct($1);
        } elsif (/^tmpdir\s*=\s*(.+)/i) {
          $$cfg_ref{tmpdir} = $1;                        # tmpdir
        } elsif (/^check_non-rules\s*=\s*([01])/i) {
          $$cfg_ref{"check_non-rules"} = $1;             # check_non-rules
        } else {                                         # invalid line
            warn("WARNING: line $linenum in $config_file is invalid, ignoring\n");
        }
    }
    close(CONF);
}



# Make a few basic tests to make sure things look ok.
# Will also set a new PATH as defined in the config file.
sub sanity_check()
{
   my @req_params   = qw (path update_files);  # Required parameters in oinkmaster.conf.
   my @req_binaries = qw (gzip rm tar);        # These binaries are always required.

  # Can't use both -q and -v.
    clean_exit("both quiet mode and verbose mode at the same time doesn't make sense.")
      if ($quiet && $verbose);

  # Make sure all required variables are defined in the config file.
    foreach my $param (@req_params) {
        clean_exit("the required parameter \"$param\" is not defined in $config_file.")
          unless (exists($config{$param}));
    }

  # We now know a path was defined in the config, so set it.
    $ENV{'PATH'} = $config{path};

  # Reset environment variables that may cause trouble.
    delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};

  # Make sure all required binaries can be found.
  # (Wget is not required if user specifies file:// as url. That check is done below.)
    foreach my $binary (@req_binaries) {
        clean_exit("\"$binary\" could not be found in PATH")
          unless (is_in_path($binary));
    }

  # Make sure $url is defined (either by -u <url> or url=... in the conf).
    clean_exit("incorrect URL or URL not specified in neither $config_file nor command line.")
      unless (exists($config{'url'}) &&
        $config{'url'}  =~ /^(?:http|ftp|file):\/\/\S+.*\.tar\.gz$/);

  # Wget must be found if url is http:// or ftp://.
    clean_exit("\"wget\" not found in PATH")
      if ($config{'url'} =~ /^(http|ftp):/ && !is_in_path("wget"));

  # Make sure the output directory exists and is readable.
    clean_exit("the output directory \"$config{output_dir}\" doesn't exist ".
               "or isn't readable by you.")
      if (!-d "$config{output_dir}" || !-x "$config{output_dir}");

  # Make sure the output directory is writable unless running in careful mode.
    clean_exit("the output directory \"$config{output_dir}\" isn't writable by you.")
      if (!$careful && !-w "$config{output_dir}");

  # Make sure the backup directory exists and is writable if running with -b.
    clean_exit("the backup directory \"$config{backup_dir}\" doesn't exist or ".
               "isn't writable by you.")
      if (exists($config{backup_dir}) &&
        (!-d "$config{backup_dir}" || !-w "$config{backup_dir}"));
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
            clean_exit("unable to download rules from $url (got error code from wget).\n".
                       "Consider running in non-quiet mode if the problem persists.")
              if (system("wget","-q","-O","$localfile","$url"));         # quiet mode
        } elsif ($verbose) {
            clean_exit("unable to download rules from $url (got error code from wget).")
              if (system("wget","-v","-O","$localfile","$url"));         # verbose mode
        } else {
            clean_exit("unable to download rules from $url (got error code from wget).")
              if (system("wget","-nv","-O","$localfile","$url"));        # normal mode
        }
    } elsif ($url =~ /^file/) {        # grab file from local filesystem
        $url =~ s/^file:\/\///;        # remove "file://", the rest is the actual filename

	clean_exit("the file $url does not exist.")
          unless (-e "$url");

	clean_exit("the file $url is empty.")
          unless (-s "$url");

        print STDERR "Copying rules archive from $url... "
          unless ($quiet);

        copy("$url", "$localfile")
          or clean_exit("unable to copy $url to $localfile: $!");

        print STDERR "done.\n"
	  unless ($quiet);
    }

  # Make sure the downloaded file actually exists.
    clean_exit("failed to get rules archive: local target file $localfile doesn't exist after download.")
      unless (-e "$localfile");

  # Also make sure it's at least non-empty.
    clean_exit("failed to get rules archive: local target file $localfile is empty after download ".
               "(perhaps you're out of diskspace or file in url is empty?)")
      unless (-s "$localfile");
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

  # Read output from "tar tf $archive" into @tar_test.
    my @tar_test;
    if (open(TAR,"-|")) {
        @tar_test = <TAR>;
    } else {
        exec("tar","tf","$archive");
    }
    close(TAR);

  # For each filename in the archive, do some basic (pretty useless) sanity checks.
    foreach my $filename (@tar_test) {
       chomp($filename);

      # Make sure the leading char is valid (not an absolute path, for example).
        clean_exit("forbidden leading character in filename in tar archive. ".
                   "Offending file/line:\n$filename")
          unless ($filename =~ /^[$ok_lead]/);

      # We don't want to have any weird characters anywhere in the filename.
        clean_exit("forbidden characters in filename in tar archive. ".
                   "Offending file/line:\n$filename")
          if ($filename =~ /[^$ok_chars]/);

      # We don't want to unpack any "../../" junk.
        clean_exit("filename in tar archive contains \"..\".\n".
                   "Offending file/line:\n$filename")
          if ($filename =~ /\.\./);
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
# Also clean unwanted whitespaces from them.
sub disable_and_modify_rules($ $ $)
{
    my $disable_sid_ref = shift;
    my $modify_sid_ref  = shift;
    my $newfiles_ref    = shift;
    my $num_disabled    = 0;

    if (!$preserve_comments && !$quiet) {
        warn("WARNING: all rules that are disabled by default will be re-enabled\n");
    }

    print STDERR "Disabling rules according to $config_file... "
      unless ($quiet);
    print STDERR "\n"
      if ($verbose);

    foreach my $file (keys(%$newfiles_ref)) {

      # Make sure it's a regular file.
        clean_exit("$file is not a regular file.")
          unless (-f "$file" && ! -l "$file");

        open(INFILE, "<$file") or clean_exit("could not open $file for reading: $!");
	my @infile = <INFILE>;
        close(INFILE);

      # Write back to the same file.
	open(OUTFILE, ">$file") or clean_exit("could not open $file for writing: $!");

        my ($single, $multi, $nonrule);

	RULELOOP:while (get_next_entry(\@infile, \$single, \$multi, \$nonrule)) {
	    if (defined($nonrule)) {
	        print OUTFILE "$nonrule";
		next RULELOOP;
	    }

          # We've got a valid snort rule. Grab msg and sid.
	    $single =~ /$SNORT_RULE_REGEXP/oi;
   	    my ($msg, $sid) = ($1, $2);

          # Even if it was a single-line rule, we want to have a copy in $multi now.
	    $multi = $single unless (defined($multi));

          # Some rules may be commented out by default. Enable them if -e is specified.
	    if ($multi =~ /^#/) {
		if ($preserve_comments) {
		    print STDERR "Preserving disabled rule (SID $sid): $msg\n"
		      if ($verbose);
		} else {
		    print STDERR "Enabling disabled rule (SID $sid): $msg\n"
		      if ($verbose);
                    $multi =~ s/^#*//;
                    $multi =~ s/\n#*/\n/g;
		}
	    }

          # Modify rule if requested (mod = "substthis" | "withthis").
            foreach my $mod (@{$$modify_sid_ref{$sid}}) {

              # Remove leading/trailing ".
	        $mod =~ s/^"//;
                $mod =~ s/"$//;

                my ($sub, $repl) = split(/"\s*\|\s*"/, $mod);
		if ($multi =~ /\Q$sub\E/) {
  	            print STDERR "Modifying SID $sid with expression: $mod\n" .
                                 "Before: $multi\n"
		      if ($verbose);

                    $multi =~ s/\Q$sub\E/$repl/;

  	  	    print STDERR "After:  $multi\n"
                      if ($verbose);
		} else {
                   print STDERR "\nWARNING: SID $sid does not contain modifysid-string ".
                                "\"$sub\", skipping\n"
                     unless ($quiet);
                }
	    }

          # Disable rule if requested.
            if (exists($$disable_sid_ref{"$sid"})) {
                print STDERR "Disabling SID $sid: $msg\n"
                  if ($verbose);

               unless ($multi =~ /^\s*#/) {
                   $multi = "#$multi";
                   $multi =~ s/\n(.+)/\n#$1/g;
	       }

               $num_disabled++;
	    }

          # Write rule back to the same rules file.
            print OUTFILE $multi;
        }

        close(OUTFILE);
    }
    print STDERR "$num_disabled rules disabled.\n"
      unless ($quiet);
}



# Setup rules hash.
# Format for rules will be:     rh{old|new}{rules{filename}{sid} = rule
# Format for non-rules will be: rh{old|new}{other}{filename}     = array of lines
# List of added files will be stored as rh{added_files}{filename}
sub setup_rules_hash($)
{
    my $new_files_ref = shift;
    my %rh;

    foreach my $file (keys(%$new_files_ref)) {
        warn("WARNING: downloaded rules file $file is empty (maybe correct, maybe not)\n")
          if (!-s "$file" && $verbose);

        open(NEWFILE, "<$file") or clean_exit("could not open $file for reading: $!");
        my @newfile = <NEWFILE>;
        close(NEWFILE);

      # From now on we don't care about the path, so remove it.
	$file =~ s/.*\///;

        my ($single, $multi, $nonrule);

	while (get_next_entry(\@newfile, \$single, \$multi, \$nonrule)) {
	    if (defined($single)) {
	        $single =~ /$SNORT_RULE_REGEXP/oi;
	        my $sid = $2;
		warn("WARNING: duplicate SID in downloaded rules archive in file ".
                     "$file: SID $sid\n")
		  if (exists($rh{new}{rules}{"$file"}{"$sid"}));
		$rh{new}{rules}{"$file"}{"$sid"} = $single;
	    } else {                                 # add non-rule line to hash
	        push(@{$rh{new}{other}{"$file"}}, $nonrule);
	    }
	}

	# Also read in old file if it exists.
        if (-f "$config{output_dir}/$file") {

            open(OLDFILE, "<$config{output_dir}/$file")
              or clean_exit("could not open $config{output_dir}/$file for reading: $!");
	    my @oldfile = <OLDFILE>;
            close(OLDFILE);

	    while (get_next_entry(\@oldfile, \$single, \$multi, \$nonrule)) {
	        if (defined($single)) {
	            $single =~ /$SNORT_RULE_REGEXP/oi;
		    my $sid = $2;
		    warn("WARNING: duplicate SID in your local rules in file ".
                         "$file: SID $sid\n")
	  	      if (exists($rh{old}{rules}{"$file"}{"$sid"}));
	  	    $rh{old}{rules}{"$file"}{"$sid"} = $single;
                } else {                     # add non-rule line to hash
	            push(@{$rh{old}{other}{"$file"}}, $nonrule);
                }
            }
        } else {                             # downloaded file did not exist in old rules dir
	    $rh{added_files}{"$file"}++;
        }
    }

    return (%rh);
}



# Try to find a given string in a given array. Return 1 if found, or 0 if not.
# Some things will always be considered as found (lines that we don't care if
# they were added/removed). It's extremely slow and braindead, but who cares.
sub find_line($ $)
{
    my $line    = shift;   # line to look for
    my $arr_ref = shift;   # reference to array to look in

    return (1) unless ($line =~ /\S/);                         # skip blank lines
    return (1) if     ($line =~ /^\s*#+\s*\$I\S:.+Exp\s*\$/);  # also skip CVS Id tag

    foreach $_ (@$arr_ref) {
        return (1) if ($_ eq $line);                           # string found
    }

    return (0);                                                # string not found
}



# Backup files in output dir matching $config{update_files} into the backup dir.
sub make_backup($ $)
{
    my $src_dir  = shift;    # dir with the rules to be backed up
    my $dest_dir = shift;    # where to put the tarball containing the backed up rules

    (undef, my $min, my $hour, my $mday, my $mon, my $year, undef, undef, undef)
      = localtime(time);

    my $date = sprintf("%d%02d%02d-%02d%02d", $year + 1900, $mon + 1, $mday, $hour, $min);

    my $bu_tmp_dir = "$tmpdir/rules-backup-$date";

    print STDERR "Creating backup of old rules..."
      unless ($quiet);

    mkdir("$bu_tmp_dir", 0700)
      or clean_exit("could not create temporary backup directory $bu_tmp_dir: $!");

  # Copy all rules files from the rules dir to the temporary backup dir.
    opendir(OLDRULES, "$src_dir")
      or clean_exit("could not open directory $src_dir: $!");

    while ($_ = readdir(OLDRULES)) {
        if (/$config{update_files}/) {
          copy("$src_dir/$_", "$bu_tmp_dir/")
            or warn("WARNING: error copying $src_dir/$_ to $bu_tmp_dir: $!")
	}
    }

    closedir(OLDRULES);

  # Change directory to $tmpdir (so we'll be right below the directory where
  # we have our rules to be backed up).
    my $old_dir = getcwd or clean_exit("could not get current directory: $!");
    chdir("$tmpdir")     or clean_exit("could not change directory to $tmpdir: $!");

  # Execute tar command. This will archive "rules-backup-$date/"
  # into the file rules-backup-$date.tar, placed in $tmpdir.
    warn("WARNING: tar command did not exit with status 0 when archiving backup files.\n")
      if (system("tar","cf","rules-backup-$date.tar","rules-backup-$date"));

  # Compress it.
    warn("WARNING: gzip command did not exit with status 0 when compressing backup file.\n")
      if (system("gzip","rules-backup-$date.tar"));

  # Change back to old directory (so it will work with -b <directory> as either
  # an absolute or a relative path.
    chdir("$old_dir") or clean_exit("could not change directory back to $old_dir: $!");

  # Copy the archive to the backup directory.
    copy("$tmpdir/rules-backup-$date.tar.gz", "$dest_dir/")
      or warn("WARNING: unable to copy $tmpdir/rules-backup-$date.tar.gz ".
              "to $dest_dir/: $!\n");

    print STDERR " saved as $dest_dir/rules-backup-$date.tar.gz.\n"
      unless ($quiet);
}



# Print all changes.
sub print_changes($ $)
{
    my $ch_ref = shift;
    my $rh_ref = shift;

    print "\n[***] Results from Oinkmaster started " . scalar(localtime) . " [***]\n";

    print "\n[*] Rules modifications: [*]\n    None.\n"
      if (!keys(%{$$ch_ref{rules}}) && !$super_quiet);

  # Print added rules.
    if (exists($$ch_ref{rules}{added})) {
        print "\n[+++]          Added rules:          [+++]\n";
	print_changetype($PRINT_NEW, \%{$$ch_ref{rules}{added}}, $rh_ref);
    }

  # Print enabled rules.
    if (exists($$ch_ref{rules}{ena})) {
        print "\n[+++]         Enabled rules:         [+++]\n";
	print_changetype($PRINT_NEW, \%{$$ch_ref{rules}{ena}}, $rh_ref);
    }

  # Print enabled + modified rules.
    if (exists($$ch_ref{rules}{ena_mod})) {
        print "\n[+++]  Enabled and modified rules:   [+++]\n";
	print_changetype($PRINT_BOTH, \%{$$ch_ref{rules}{ena_mod}}, $rh_ref);
    }

  # Print modified active rules.
    if (exists($$ch_ref{rules}{mod_act})) {
        print "\n[///]     Modified active rules:     [///]\n";
	print_changetype($PRINT_BOTH, \%{$$ch_ref{rules}{mod_act}}, $rh_ref);
    }

  # Print modified inactive rules.
    if (exists($$ch_ref{rules}{mod_ina})) {
        print "\n[///]    Modified inactive rules:    [///]\n";
	print_changetype($PRINT_BOTH, \%{$$ch_ref{rules}{mod_ina}}, $rh_ref);
    }

  # Print disabled + modified rules.
    if (exists($$ch_ref{rules}{dis_mod})) {
        print "\n[---]  Disabled and modified rules:  [---]\n";
	print_changetype($PRINT_BOTH, \%{$$ch_ref{rules}{dis_mod}}, $rh_ref);
    }

  # Print disabled rules.
    if (exists($$ch_ref{rules}{dis})) {
        print "\n[---]         Disabled rules:        [---]\n";
	print_changetype($PRINT_NEW, \%{$$ch_ref{rules}{dis}}, $rh_ref);
    }

  # Print removed rules.
    if (exists($$ch_ref{rules}{removed})) {
        print "\n[---]         Removed rules:         [---]\n";
	print_changetype($PRINT_OLD, \%{$$ch_ref{rules}{removed}}, $rh_ref);
    }


    print "\n[*] Non-rule modifications: [*]\n    None.\n"
      if (!keys(%{$$ch_ref{other}}) && !$super_quiet);

  # Print added non-rule lines.
     if (exists($$ch_ref{other}{added})) {
        print "\n[+++]      Added non-rule lines:     [+++]\n";
        foreach my $file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{other}{added}}))) {
            print "\n     -> File $file:\n";
            foreach my $line (@{$$ch_ref{other}{added}{$file}}) {
                print "        $line";
            }
        }
    }

  # Print removed non-rule lines.
    if (keys(%{$$ch_ref{other}{removed}}) > 0) {
        print "\n[---]     Removed non-rule lines:    [---]\n";
        foreach my $file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{other}{removed}}))) {
            print "\n     -> File $file:\n";
            foreach my $other (@{$$ch_ref{other}{removed}{$file}}) {
	        print "        $other";
            }
        }
    }

  # Print list of added files.
    if (keys(%{$$ch_ref{added_files}})) {
        print "\n[+] Added files (consider updating your snort.conf to include them): [+]\n\n";
        foreach my $added_file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{added_files}}))) {
            print "    -> $added_file\n";
        }
    } else {
        print "\n[*] Added files: [*]\n    None.\n"
          unless ($super_quiet);
    }


  # Print list of possibly removed files, if requested.
    if ($check_removed) {
        if (keys(%{$$ch_ref{removed_files}})) {
            print "\n[-] Files possibly removed from the archive ".
                  "(consider removing them from your snort.conf): [-]\n\n";
            foreach my $removed_file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{removed_files}}))) {
                print "    -> $removed_file\n";
	    }
        } else {
             print "\n[*] Files possibly removed from the archive: [*]\n    None.\n"
               unless ($super_quiet);
        }
    }

    print "\n";
}



# Help-function for print_changes().
sub print_changetype($ $ $)
{
    my $type   = shift;
    my $ch_ref = shift;
    my $rh_ref = shift;

    foreach my $file (sort({uc($a) cmp uc($b)} keys(%$ch_ref))) {
        print "\n     -> File $file:\n";
        foreach my $sid (keys(%{$$ch_ref{$file}})) {
	    if ($type == $PRINT_OLD) {
                print "        $$rh_ref{old}{rules}{$file}{$sid}"
            } elsif ($type == $PRINT_NEW) {
                print "        $$rh_ref{new}{rules}{$file}{$sid}"
	    } elsif ($type == $PRINT_BOTH) {
                print "        old: $$rh_ref{old}{rules}{$file}{$sid}";
                print "        new: $$rh_ref{new}{rules}{$file}{$sid}";
	    }
        }
    }
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
        foreach my $type (keys(%{$$changes_ref{rules}})) {
	     $modified_files{"$file_w_path"}++
               if (exists($$changes_ref{rules}{"$type"}{"$file"}));
        }

      # Check if there were any non-rule changes in this file.
        foreach my $type (keys(%{$$changes_ref{other}})) {
            $modified_files{"$file_w_path"}++
              if (exists($$changes_ref{other}{"$type"}{"$file"}));
        }

      # Added files are also regarded as modified
      # since we want to update (add) those as well.
      # We only have a list of added files without the full path,
      # so that's why we have to do the special check below.
        foreach my $added_file (keys(%{$$changes_ref{added_files}})) {
            $modified_files{"$file_w_path"}++
              if ($added_file eq $file);
        }
    }

    return (keys(%modified_files));
}



# Compare the new rules to the old ones.
# For each rule in the new file, check if the rule also exists
# in the old file. If it does then check if it has been modified,
# but if it doesn't, it must have been added.
sub get_changes($ $)
{
    my $rh_ref        = shift;
    my $new_files_ref = shift;
    my %changes;

    print STDERR "Comparing new files to the old ones... "
      unless ($quiet);

  # We have the list of added files in $rh_ref{added_files}, but we'd rather
  # want to have it in $changes{added_files} now.
    $changes{added_files} = $$rh_ref{added_files};

  # Add list of possibly removed files into $removed_files, if requested.
    if ($check_removed) {
        opendir(OLDRULES, "$config{output_dir}")
          or clean_exit("could not open directory $config{output_dir}: $!");

        while ($_ = readdir(OLDRULES)) {
            $changes{removed_files}{"$_"}++
              if (/$config{update_files}/ && !exists($config{file_ignore_list}{$_}) &&
                !-e "$tmpdir/rules/$_");
        }

        closedir(OLDRULES);
    }

  # Compare the rules.
    FILELOOP:foreach my $file_w_path (keys(%$new_files_ref)) {    # for each new file
        my $file = $file_w_path;
        $file =~ s/.*\///;                                        # remove path
        next FILELOOP if (exists($$rh_ref{added_files}{$file}));  # skip diff if it's an added file

        foreach my $sid (keys(%{$$rh_ref{new}{rules}{$file}})) {  # for each sid in the new file
            my $new_rule = $$rh_ref{new}{rules}{$file}{$sid};

                if (exists($$rh_ref{old}{rules}{$file}{$sid})) {  # also exists in the old file?
                    my $old_rule = $$rh_ref{old}{rules}{$file}{$sid};

		    unless ($new_rule eq $old_rule) {                             # are they identical?
                        if ("#$old_rule" eq $new_rule) {                          # rule disabled?
 	                    $changes{rules}{dis}{$file}{$sid}++;
                        } elsif ($old_rule eq "#$new_rule") {                     # rule enabled?
 	                    $changes{rules}{ena}{$file}{$sid}++;
                        } elsif ($old_rule =~ /^\s*#/ && $new_rule !~ /^\s*#/) {  # rule enabled and modified?
 	                    $changes{rules}{ena_mod}{$file}{$sid}++;
                        } elsif ($old_rule !~ /^\s*#/ && $new_rule =~ /^\s*#/) {  # rule disabled and modified?
 	                    $changes{rules}{dis_mod}{$file}{$sid}++;
                        } elsif ($old_rule =~ /^\s*#/ && $new_rule =~ /^\s*#/) {  # inactive rule modified?
 	                    $changes{rules}{mod_ina}{$file}{$sid}++;
                        } else {                                                  # active rule modified?
 	                    $changes{rules}{mod_act}{$file}{$sid}++;
	  	        }

		    }
	        } else {    # sid not found in old file so it must have been added
  	            $changes{rules}{added}{$file}{$sid}++;
	        }
        } # foreach sid

      # Check for removed rules, i.e. sids that exist in the old file but not in the new one.
        foreach my $sid (keys(%{$$rh_ref{old}{rules}{$file}})) {
            unless (exists($$rh_ref{new}{rules}{$file}{$sid})) {
	        $changes{rules}{removed}{$file}{$sid}++;
            }
        }

      # Check for added/removed non-rule lines, unless check_non-rules is set to 0.
        unless (exists($config{"check_non-rules"}) && $config{"check_non-rules"} == 0) {
            foreach my $other_added (@{$$rh_ref{new}{other}{$file}}) {
                unless (find_line($other_added, \@{$$rh_ref{old}{other}{"$file"}})) {
	            push(@{$changes{other}{added}{$file}}, $other_added);
                }
            }

            foreach my $other_removed (@{$$rh_ref{old}{other}{$file}}) {
                unless (find_line($other_removed, \@{$$rh_ref{new}{other}{"$file"}})) {
	            push(@{$changes{other}{removed}{$file}}, $other_removed);
                }
            }
        }

    } # foreach new file

    print STDERR "done.\n" unless ($quiet);

    return (%changes);
}



# Create list of new files (with full path) that we care about.
# I.e. files that match the 'update_files' regexp and isn't listed
# in the ignore list.
sub get_new_filenames($ $)
{
    my $new_files_ref = shift;
    my $rules_dir     = shift;

    opendir(NEWRULES, "$rules_dir")
      or clean_exit("could not open directory $rules_dir: $!");

    while ($_ = readdir(NEWRULES)) {
        $new_files{"$rules_dir/$_"}++
          if (/$config{update_files}/ && !exists($config{file_ignore_list}{$_}));
    }
    closedir(NEWRULES);

  # Return number of new interesting filenames.
    return (keys(%$new_files_ref));
}



# Copy modified rules to the output directory.
sub update_rules($ @)
{
    my $dst_dir = shift;
    my @files   = @_;

    foreach my $file_w_path (@files) {
        my $file = $file_w_path;
        $file =~ s/.*\///;    # remove path
        copy("$file_w_path", "$dst_dir/$file")
          or clean_exit("could not copy $file_w_path to $file: $!");
    }
}



# Return true if file is in PATH and is executable.
sub is_in_path($)
{
    my $file = shift;

    foreach my $dir (split(/:/, $ENV{PATH})) {
        return (1) if (-x "$dir/$file");
    }

    return (0);
}



# get_next_entry() will parse the array referenced in the first arg
# and return the next entry. The array should contain a rules file,
# and the returned entry will be removed from it.
# An entry is one of:
# - single-line rule (put in 2nd ref)
# - multi-line rule (put in 3rd ref)
# - non-rule line (put in 4th ref)
# If the entry is a multi-line rule, its single-line version is also
# returned (put in the 2nd ref).
sub get_next_entry($ $ $ $)
{
    my $arr_ref     = shift;
    my $single_ref  = shift;
    my $multi_ref   = shift;
    my $nonrule_ref = shift;

    undef($$single_ref);
    undef($$multi_ref);
    undef($$nonrule_ref);

    my $line = shift(@$arr_ref) || return(0);

    if ($line =~ /$SNORT_MULTILINE_REGEXP/oi) {    # start multi-line rule?
        $$single_ref = $line;
        $$multi_ref  = $line;

      # Keep on reading as long as line ends with "\".
        while ($line =~ /\\\s*\n$/) {
            $$single_ref =~ s/\\\s*\n//;    # remove trailing "\" for single-line version

          # If there are no more lines, this can not be a valid multi-line rule.
            if (!($line = shift(@$arr_ref))) {

                $$multi_ref .= $line;

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

            $$multi_ref  .= $line;
            $line =~ s/^\s*#*\s*//;               # In single-line version, remove leading #'s first
            $$single_ref .= $line;
        }

      # Single-line version should now be a valid rule.
      # If not, it wasn't a valid multi-line rule after all.
        if ($$single_ref =~ /$SNORT_RULE_REGEXP/oi) {

            $$single_ref =~ s/^\s*//;             # remove leading whitespaces
	    $$single_ref =~ s/^#+\s*/#/;          # remove whitespaces next to the leading #
	    $$single_ref =~ s/\s*\n$/\n/;         # remove trailing whitespaces

            $$multi_ref  =~ s/^\s*//;
            $$multi_ref  =~ s/\s*\n$/\n/;
            $$multi_ref  =~ s/^#+\s*/#/;

            return (1);   # return multi

        } else {
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

    } elsif ($line =~ /$SNORT_RULE_REGEXP/oi) {  # single-line rule?
        $$single_ref = $line;
        $$single_ref =~ s/^\s*//;                # remove leading whitespaces
	$$single_ref =~ s/^#+\s*/#/;             # remove whitespaces next to the leading #
	$$single_ref =~ s/\s*\n$/\n/;            # remove trailing whitespaces
        return (1);   # return single
    } else {                                     # non-rule line?
        $$nonrule_ref = $line;
	$$nonrule_ref =~ s/\s*\n$/\n/;           # remove trailing whitespaces
        return (1);   # return non-rule
    }
}



# Create empty temporary directory inside the directory given as argument.
# Will die if we can't create it.
# If successful, the name of the created directory is returned.
sub make_tempdir($)
{
    my $base = shift;

    die("The temporary base directory $base does not exist.\nExiting...\n")
      unless (-d "$base");

    my $tmpdir = "$base/oinkmaster.$$";

    mkdir("$tmpdir", 0700)
      or die("Could not create temporary directory $tmpdir: $!\nExiting...\n");

    return ($tmpdir);
}



# Remove temporary directory and exit.
# If a non-empty string is given as argument, it will be regarded
# as an error message and we will use die() with the message instead
# of just exit(0).
sub clean_exit($)
{
    chdir('/');

    system("rm","-r","-f","$tmpdir")
      and warn("WARNING: unable to remove temporary directory $tmpdir.\n");

    if ($_[0] eq "") {
        exit(0);
    } else {
        $_ = $_[0];
	chomp;
        die("\n$0: Error: $_\n\nOink, oink. Exiting...\n");
    }
}



#### EOF ####
