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
sub print_changetype($ $ $ $);
sub make_backup($ $);
sub get_changes($ $);
sub get_new_filenames($ $);
sub update_rules($ @);
sub is_in_path($);
sub get_next_entry($ $ $ $);
sub make_tempdir($);
sub get_new_vars($ $ $);
sub add_new_vars($ $);
sub write_new_vars($ $);
sub clean_exit($);


my $VERSION           = 'Oinkmaster v0.8 by Andreas Östling <andreaso@it.su.se>';
my $OUTFILE           = "snortrules.tar.gz";
my $DIST_SNORT_CONF   = "rules/snort.conf";  # where (inside tmpdir) to look for new variables

my $PRINT_NEW         = 1;
my $PRINT_OLD         = 2;
my $PRINT_BOTH        = 3;

my $min_rules         = 1;                   # default minimum number of required rules
my $min_files         = 1;                   # default minimum number of required files

my $tmp_basedir       = "/tmp";                            # default base temporary directory
my $config_file       = "/usr/local/etc/oinkmaster.conf";  # default config file

my $verbose           = 0;
my $careful           = 0;
my $quiet             = 0;
my $super_quiet       = 0;
my $check_removed     = 0;
my $preserve_comments = 1;
my $update_vars       = 0;

# Regexp to match a snort rule line. The msg string will go into $1 and 
# the sid will go into $2.
my $SINGLELINE_RULE_REGEXP = '^\s*#*\s*(?:alert|log|pass)\s.+msg\s*:\s*"(.+?)'.
                             '"\s*;.*sid\s*:\s*(\d+)\s*;.*\)\s*$'; # ';

# Regexp to match the start (the first line) of a possible multi-line rule.
my $MULTILINE_RULE_REGEXP = '^\s*#*\s*(?:alert|log|pass)\s.*\\\\\s*\n$'; # ';


use vars qw
   (
      $opt_b $opt_c $opt_C $opt_e $opt_h $opt_o
      $opt_q $opt_Q $opt_r $opt_u $opt_U $opt_v $opt_V
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
my $tmpdir = make_tempdir($tmp_basedir);

# Do some basic sanity checking and exit if something fails.
# A new PATH will be set.
sanity_check();

# Set new umask if one was specified in the config file.
umask($config{umask}) if exists($config{umask});

# Download the rules archive.
# This will leave us with the file $tmpdir/$OUTFILE
# (/tmp/oinkmaster.$$/snortrules.tar.gz). Will exit if download fails.
download_rules("$config{url}", "$tmpdir/$OUTFILE");

# Verify and unpack archive. This will leave us with a directory
# called "rules/" in the same directory as the archive, containing the
# new rules. Will exit if something fails.
unpack_rules_archive("$tmpdir/$OUTFILE");

# Create list of new files (with full path) that we care about from the
# downloaded archive. Filenames (with full path) will be stored as %new_files{filenme}.
my $num_files = get_new_filenames(\%new_files, "$tmpdir/rules/");

# Make sure the number of files is at least $min_files.
clean_exit("not enough rules files in downloaded archive (is it broken?)\n".
           "Number of rules files is $num_files but minimum is set to $min_files.")
  if ($num_files < $min_files);

# In the downloaded rules, disable (#comment out) all sids listed in
# conf{sid_disable_list} and modify sids listed in conf{sid_modify_list}.
# Will open each file listed in %new_files, make modifications, and
# write back to the same file.
my $num_rules = disable_and_modify_rules(\%{$config{sid_disable_list}},
                                         \%{$config{sid_modify_list}}, \%new_files);

# Make sure the number of rules is at least $min_rules.
clean_exit("not enough rules in downloaded archive (is it broken?)\n".
           "Number of rules is $num_rules but minimum is set to $min_rules.")
  if ($num_rules < $min_rules);

# Setup rules hash.
my %rh = setup_rules_hash(\%new_files);

# Compare the new rules to the old ones.
my %changes = get_changes(\%rh, \%new_files);

# Check for variables that exist in dist snort.conf but not in local snort.conf.
get_new_vars(\%changes, $config{varfile}, "$tmpdir/$DIST_SNORT_CONF")
  if ($update_vars);


# Find out if something had changed.
my $something_changed = 0;
$something_changed = 1
    if (keys(%{$changes{modified_files}}) ||
        keys(%{$changes{added_files}})    ||
        keys(%{$changes{removed_files}})  ||
        keys(%{$changes{new_vars}}));


# Update files listed in %changes{modified_files} (move the new files from the temporary
# directory into our output directory) and add new variables to the local snort.conf
# if requested, unless we're running in careful mode.
# Create backup first if running with -b.
if ($something_changed) {
    if ($careful) {
        print STDERR "No need to backup old files (running in careful mode), skipping.\n"
          if (exists($config{backup_dir}) && (!$quiet));
    }  else {
        make_backup($config{output_dir}, $config{backup_dir})
          if (exists($config{backup_dir}));

        update_rules($config{output_dir}, keys(%{$changes{modified_files}}));

        add_new_vars(\%changes, $config{varfile})
          if ($update_vars);
    }
} else {
    print STDERR "No files modified - no need to backup old files, skipping.\n"
      if (exists($config{backup_dir}) && !$quiet);
}


# Print changes.
print "\nNote: Oinkmaster is running in careful mode - not updating/adding anything.\n"
  if ($something_changed && $careful);

print_changes(\%changes, \%rh)
  if ($something_changed || !$quiet);


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
This should be the directory where you store the official snort rules.

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
-U <file>  Variables that exist in the distribution snort.conf but not in <file>
           will be inserted at the top of it. This is probably your snort.conf.
-v         Verbose mode
-V         Show version and exit;

RTFM
    exit;
}



# Parse the command line arguments and exit if we don't like them.
sub parse_cmdline($)
{
    my $cfg_ref    = shift;
    my $cmdline_ok = getopts('b:cC:eho:qQru:U:vV');

    $$cfg_ref{backup_dir} = $opt_b if (defined($opt_b));
    $config_file          = $opt_C if (defined($opt_C));
    $$cfg_ref{url}        = $opt_u if (defined($opt_u));
    $$cfg_ref{varfile}    = $opt_U if (defined($opt_U));
    $careful              = 1      if (defined($opt_c));
    $preserve_comments    = 0      if (defined($opt_e));
    $quiet                = 1      if (defined($opt_q));
    $check_removed        = 1      if (defined($opt_r));
    $update_vars          = 1      if (defined($opt_U));
    $verbose              = 1      if (defined($opt_v));

    if (defined($opt_Q)) {
        $quiet       = 1;
        $super_quiet = 1;
    }

    show_usage() if (defined($opt_h));

    if (defined($opt_V)) {
        print "$VERSION\n";
        exit(0);
    }

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

      # disablesid <SID[,SID, ...]>
        if (/^disablesids*\s+(\d.*)/i) {
	    my $args = $1;
	    foreach my $sid (split(/\s*,\s*/, $args)) {
  	        if ($sid =~ /^\d+$/) {
                    $$cfg_ref{sid_disable_list}{$sid}++;
	        } else {
                    warn("WARNING: line $linenum in $config_file is invalid, ignoring\n");
	        }
	    }
      # modifysid <SID> "substthis" | "withthis"
        } elsif (/^modifysid\s+(\d+)\s+(".+"\s*\|\s*".+")/i) {
            push(@{$$cfg_ref{sid_modify_list}{$1}}, $2);
      # skipfile <file[,file, ...]>
        } elsif (/^skipfiles*\s+(.*)/i) {
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
        } elsif (/^min_files\s*=\s*(\d+)/i) {            # min_files
          $min_files = $1;
        } elsif (/^min_rules\s*=\s*(\d+)/i) {            # min_rules
          $min_rules= $1;
        } elsif (/^tmpdir\s*=\s*(.+)/i) {                # tmpdir
          $tmp_basedir = $1;
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

  # If a variable file (probably local snort.conf) has been specified,
  # it must exist. It must also be writable unless we're in careful mode.
    if (exists($config{varfile})) {
        clean_exit("file $config{varfile} does not exist.")
          unless (-e "$config{varfile}");

        clean_exit("file $config{varfile} is not writable by you.")
          if (!$careful && !-w "$config{varfile}");
    }

  # Make sure all required binaries can be found.
  # (Wget is not required if user specifies file:// as url. That check is done below.)
    foreach my $binary (@req_binaries) {
        clean_exit("\"$binary\" could not be found in PATH.")
          unless (is_in_path($binary));
    }

  # Make sure $url is defined (either by -u <url> or url=... in the conf).
    clean_exit("incorrect URL or URL not specified in neither $config_file nor command line.")
      unless (exists($config{'url'}) &&
        $config{'url'}  =~ /^(?:http|ftp|file):\/\/\S+.*\.tar\.gz$/);

  # Wget must be found if url is http:// or ftp://.
    clean_exit("\"wget\" not found in PATH.")
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
    my $ok_chars = 'a-zA-Z0-9_~\.\-/';   # allowed chars in filenames in the tar archive

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



# Open all rules files in the temporary directory and disable/modify all
# rules/lines as requested in oinkmaster.conf, and then write back to the
# same files. Also clean unwanted whitespaces and duplicate sids from them.
sub disable_and_modify_rules($ $ $)
{
    my $disable_sid_ref = shift;
    my $modify_sid_ref  = shift;
    my $newfiles_ref    = shift;
    my $num_disabled    = 0;
    my %sids;

    warn("WARNING: all rules that are disabled by default will be re-enabled\n")
      if (!$preserve_comments && !$quiet);

    print STDERR "Disabling rules... "
      unless ($quiet);
    print STDERR "\n"
      if ($verbose);

    foreach my $file (sort(keys(%$newfiles_ref))) {

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
	    $single =~ /$SINGLELINE_RULE_REGEXP/oi;
   	    my ($msg, $sid) = ($1, $2);

          # If we have already seen a rule with this sid, discard this one.
            if (exists($sids{$sid})) {
                $_ = $file;
                $_ =~ s/.*\///;
                warn("\nWARNING: duplicate SID in downloaded file $_, SID=$sid, which has ".
                     "already been seen in $sids{$sid}, discarding rule \"$msg\"\n");
                next RULELOOP;
            }

            $_ = $file;
            $_ =~ s/.*\///;
            $sids{$sid} = $_;

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

    print STDERR "$num_disabled out of " . keys(%sids) . " rules disabled.\n"
      unless ($quiet);

  # Return total number of valid rules.
    return (keys(%sids));
}



# Setup rules hash.
# Format for rules will be:     rh{old|new}{rules{filename}{sid} = rule
# Format for non-rules will be: rh{old|new}{other}{filename}     = array of lines
# List of added files will be stored as rh{added_files}{filename}
sub setup_rules_hash($)
{
    my $new_files_ref = shift;
    my (%rh, %allsids);

    foreach my $file (sort(keys(%$new_files_ref))) {
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
	        $single =~ /$SINGLELINE_RULE_REGEXP/oi;
	        my $sid = $2;
		$rh{new}{rules}{"$file"}{"$sid"} = $single;
		$allsids{new}{"$sid"}++;
	    } else {                                 # add non-rule line to hash
	        push(@{$rh{new}{other}{"$file"}}, $nonrule);
	    }
	}

	# Also read in old file if it exists.
        # We do a sid dup check in these files.
        if (-f "$config{output_dir}/$file") {
            open(OLDFILE, "<$config{output_dir}/$file")
              or clean_exit("could not open $config{output_dir}/$file for reading: $!");
	    my @oldfile = <OLDFILE>;
            close(OLDFILE);

	    while (get_next_entry(\@oldfile, \$single, \$multi, \$nonrule)) {
	        if (defined($single)) {
	            $single =~ /$SINGLELINE_RULE_REGEXP/oi;
		    my $sid = $2;

		    warn("WARNING: duplicate SID in your local rules, SID $sid exists multiple ".
                         "times, please fix this manually!\n")
		      if (exists($allsids{old}{"$sid"}));

	  	    $rh{old}{rules}{"$file"}{"$sid"} = $single;
	  	    $allsids{old}{"$sid"}++;
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

    my $backup_tmp_dir = "$tmpdir/rules-backup-$date";

    print STDERR "Creating backup of old rules..."
      unless ($quiet);

    mkdir("$backup_tmp_dir", 0700)
      or clean_exit("could not create temporary backup directory $backup_tmp_dir: $!");

  # Copy all rules files from the rules dir to the temporary backup dir.
    opendir(OLDRULES, "$src_dir")
      or clean_exit("could not open directory $src_dir: $!");

    while ($_ = readdir(OLDRULES)) {
        if (/$config{update_files}/) {
          copy("$src_dir/$_", "$backup_tmp_dir/")
            or warn("WARNING: error copying $src_dir/$_ to $backup_tmp_dir: $!")
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

  # Print new variables.
    if ($update_vars) {
       if (keys(%{$$ch_ref{new_vars}})) {
            print "\n[*] New variables: [*]\n";
            foreach my $var (keys(%{$$ch_ref{new_vars}})) {
                print "    var $var $$ch_ref{new_vars}{$var}\n";
            }
        } else {
            print "\n[*] New variables: [*]\n    None.\n"
              unless ($super_quiet);
        }
    }


  # Print rules modifications.
    print "\n[*] Rules modifications: [*]\n    None.\n"
      if (!keys(%{$$ch_ref{rules}}) && !$super_quiet);

  # Print added rules.
    if (exists($$ch_ref{rules}{added})) {
        print "\n[+++]          Added rules:          [+++]\n";
	print_changetype($PRINT_NEW, "Added to",
                         \%{$$ch_ref{rules}{added}}, $rh_ref);
    }

  # Print enabled rules.
    if (exists($$ch_ref{rules}{ena})) {
        print "\n[+++]         Enabled rules:         [+++]\n";
	print_changetype($PRINT_NEW, "Enabled in",
                         \%{$$ch_ref{rules}{ena}}, $rh_ref);
    }

  # Print enabled + modified rules.
    if (exists($$ch_ref{rules}{ena_mod})) {
        print "\n[+++]  Enabled and modified rules:   [+++]\n";
	print_changetype($PRINT_BOTH, "Enabled and modified in",
                         \%{$$ch_ref{rules}{ena_mod}}, $rh_ref);
    }

  # Print modified active rules.
    if (exists($$ch_ref{rules}{mod_act})) {
        print "\n[///]     Modified active rules:     [///]\n";
	print_changetype($PRINT_BOTH, "Modified active in",
                         \%{$$ch_ref{rules}{mod_act}}, $rh_ref);
    }

  # Print modified inactive rules.
    if (exists($$ch_ref{rules}{mod_ina})) {
        print "\n[///]    Modified inactive rules:    [///]\n";
	print_changetype($PRINT_BOTH, "Modified active in",
                         \%{$$ch_ref{rules}{mod_ina}}, $rh_ref);
    }

  # Print disabled + modified rules.
    if (exists($$ch_ref{rules}{dis_mod})) {
        print "\n[---]  Disabled and modified rules:  [---]\n";
	print_changetype($PRINT_BOTH, "Disabled and modified in",
                         \%{$$ch_ref{rules}{dis_mod}}, $rh_ref);
    }

  # Print disabled rules.
    if (exists($$ch_ref{rules}{dis})) {
        print "\n[---]         Disabled rules:        [---]\n";
	print_changetype($PRINT_NEW, "Disabled in",
                         \%{$$ch_ref{rules}{dis}}, $rh_ref);
    }

  # Print removed rules.
    if (exists($$ch_ref{rules}{removed})) {
        print "\n[---]         Removed rules:         [---]\n";
	print_changetype($PRINT_OLD, "Removed from",
                         \%{$$ch_ref{rules}{removed}}, $rh_ref);
    }


  # Print non-rule modifications.
    print "\n[*] Non-rule line modifications: [*]\n    None.\n"
      if (!keys(%{$$ch_ref{other}}) && !$super_quiet);

  # Print added non-rule lines.
     if (exists($$ch_ref{other}{added})) {
        print "\n[+++]      Added non-rule lines:     [+++]\n";
        foreach my $file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{other}{added}}))) {
            my $num = $#{$$ch_ref{other}{added}{$file}} + 1;
            print "\n     -> Added to $file ($num):\n";
            foreach my $line (@{$$ch_ref{other}{added}{$file}}) {
                print "        $line";
            }
        }
    }

  # Print removed non-rule lines.
    if (keys(%{$$ch_ref{other}{removed}}) > 0) {
        print "\n[---]     Removed non-rule lines:    [---]\n";
        foreach my $file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{other}{removed}}))) {
            my $num = $#{$$ch_ref{other}{removed}{$file}} + 1;
            print "\n     -> Removed from $file ($num):\n";
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



  # Print list of possibly removed files if requested.
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
sub print_changetype($ $ $ $)
{
    my $type   = shift;   # $PRINT_OLD, $PRINT_NEW or $PRINT_BOTH
    my $string = shift;   # string to print before filename
    my $ch_ref = shift;   # reference to rules changes hash
    my $rh_ref = shift;   # reference to rules hash

    foreach my $file (sort({uc($a) cmp uc($b)} keys(%$ch_ref))) {
        my $num = keys(%{$$ch_ref{$file}});
        print "\n     -> $string $file ($num):\n";
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

  # We have the list of added files (without full path) in $rh_ref{added_files},
  # but we'd rather want to have it in $changes{added_files} now.
    $changes{added_files} = $$rh_ref{added_files};

  # Added files are also regarded as modified since we want to update
  # (i.e. add) those as well. Here we want them with full path.
    foreach my $file (keys(%{$changes{added_files}})) {
        $changes{modified_files}{"$tmpdir/rules/$file"}++;
    }

  # Add list of possibly removed files into $removed_files if requested.
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
                        $changes{modified_files}{$file_w_path}++;

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
                    $changes{modified_files}{$file_w_path}++;
  	            $changes{rules}{added}{$file}{$sid}++;
	        }
        } # foreach sid

      # Check for removed rules, i.e. sids that exist in the old file but not in the new one.
        foreach my $sid (keys(%{$$rh_ref{old}{rules}{$file}})) {
            unless (exists($$rh_ref{new}{rules}{$file}{$sid})) {
                $changes{modified_files}{$file_w_path}++;
	        $changes{rules}{removed}{$file}{$sid}++;
            }
        }

      # Check for added/removed non-rule lines.
        foreach my $other_added (@{$$rh_ref{new}{other}{$file}}) {
            unless (find_line($other_added, \@{$$rh_ref{old}{other}{"$file"}})) {
                $changes{modified_files}{$file_w_path}++;
                push(@{$changes{other}{added}{$file}}, $other_added);
            }
        }

        foreach my $other_removed (@{$$rh_ref{old}{other}{$file}}) {
            unless (find_line($other_removed, \@{$$rh_ref{new}{other}{"$file"}})) {
                $changes{modified_files}{$file_w_path}++;
                push(@{$changes{other}{removed}{$file}}, $other_removed);
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
    my $dst_dir        = shift;
    my @modified_files = @_;

    foreach my $file_w_path (@modified_files) {
        my $file = $file_w_path;
        $file =~ s/.*\///;        # remove path
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



# Create empty temporary directory inside the directory given as argument.
# Will die if we can't create it.
# If successful, the name of the created directory is returned.
sub make_tempdir($)
{
    my $base = shift;

    die("The temporary directory $base does not exist.\nExiting...\n")
      unless (-d "$base");

    my $tmpdir = "$base/oinkmaster.$$";

    mkdir("$tmpdir", 0700)
      or die("Could not create temporary directory $tmpdir: $!\nExiting...\n");

    return ($tmpdir);
}



# Look for variables that exist in dist snort.conf but not in local snort.conf.
sub
get_new_vars($ $ $)
{
    my $ch_ref     = shift;
    my $local_conf = shift;
    my $dist_conf  = shift;
    my %vars;

    unless (-e "$dist_conf") {
        warn("WARNING: distribution file $dist_conf does not exist, ".
             "aborting check for new variables\n");
        return;
    }

    print STDERR "Looking for new variables... "
      unless ($quiet);

    open(DIST_CONF, "<$dist_conf")
      or clean_exit("could not open $dist_conf for reading: $!");

    while ($_ = <DIST_CONF>) {
        $vars{$1} = $2
          if (/^\s*var\s+(\S+)\s+(\S+)/);
    }

    close(DIST_CONF);

    open(LOCAL_CONF, "<$local_conf")
      or clean_exit("could not open $local_conf for reading: $!");

    my @local_conf = <LOCAL_CONF>;

    foreach $_ (@local_conf) {
        delete($vars{$1})
          if (/^\s*var\s+(\S+)\s+(\S+)/);
    }

    close(LOCAL_CONF);

  # Any keys left in %vars are missing in the local config.
    %{$$ch_ref{new_vars}} = %vars;

    print "done.\n"
      unless ($quiet);
}



# Add variables to local snort.conf.
sub
add_new_vars($ $)
{
    my $ch_ref     = shift;
    my $local_conf = shift;

    return unless (keys(%{$$ch_ref{new_vars}}));

    open(OLD_LOCAL_CONF, "<$local_conf")
      or clean_exit("could not open $local_conf for reading: $!");
    my @local_conf = <OLD_LOCAL_CONF>;
    close(OLD_LOCAL_CONF);

    open(NEW_LOCAL_CONF, ">$local_conf")
      or clean_exit("could not open $local_conf for writing: $!");
    foreach my $varname (keys(%{$$ch_ref{new_vars}})) {
        print NEW_LOCAL_CONF "var $varname $$ch_ref{new_vars}{$varname}\n";
    }
    print NEW_LOCAL_CONF @local_conf;
    close(NEW_LOCAL_CONF);
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
