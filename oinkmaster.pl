#!/usr/bin/perl -T -w

# $Id$ #

use strict;
use Cwd;
use File::Basename;
use File::Copy;
use File::Spec;
use File::Path;
use Getopt::Std;

sub show_usage();
sub parse_cmdline($);
sub read_config($ $);
sub sanity_check();
sub download_rules($ $);
sub unpack_rules_archive($);
sub process_rules($ $ $ $);
sub setup_rules_hash($);
sub find_line($ $);
sub print_changes($ $);
sub print_changetype($ $ $ $);
sub make_backup($ $);
sub get_changes($ $);
sub get_new_filenames($ $);
sub update_rules($ @);
sub is_in_path($);
sub get_next_entry($ $ $ $ $ $);
sub make_tempdir($);
sub get_new_vars($ $ $);
sub add_new_vars($ $);
sub write_new_vars($ $);
sub msdos_to_cygwin_path($);
sub parse_mod_expr($ $ $ $);
sub untaint_path($);
sub approve_changes();
sub parse_singleline_rule($ $ $);
sub clean_exit($);


my $VERSION           = 'Oinkmaster v0.9 by Andreas Östling <andreaso@it.su.se>';
my $OUTFILE           = 'snortrules.tar.gz';
my $DIST_SNORT_CONF   = 'rules/snort.conf';

my $PRINT_NEW         = 1;
my $PRINT_OLD         = 2;
my $PRINT_BOTH        = 3;

my $min_rules         = 1;
my $min_files         = 1;

my $config_file       = '/usr/local/etc/oinkmaster.conf';

my $verbose           = 0;
my $careful           = 0;
my $quiet             = 0;
my $super_quiet       = 0;
my $check_removed     = 0;
my $make_backup       = 0;
my $update_vars       = 0;
my $config_test_mode  = 0;
my $interactive       = 0;
my $preserve_comments = 1;


# Regexp to match the start (the first line) of a possible multi-line rule.
my $MULTILINE_RULE_REGEXP  = '^\s*#*\s*(?:alert|drop|log|pass|reject|sdrop)'.
                             '\s.*\\\\\s*\n$'; # ';

# Match var line where var name goes into $1.
my $VAR_REGEXP = '^\s*var\s+(\S+)\s+\S+';

# Allowed characters in misc paths/filenames, including the ones in the tarball.
my $OK_PATH_CHARS = 'a-zA-Z\d\ _\.\-+:\\\/~@,=';

# Set default temporary base directory.
my $tmp_basedir = $ENV{TMP} || $ENV{TMPDIR} || $ENV{TEMPDIR} || '/tmp';


use vars qw
   (
      $opt_b $opt_c $opt_C $opt_e $opt_h $opt_i $opt_o
      $opt_q $opt_Q $opt_r $opt_T $opt_u $opt_U $opt_v $opt_V
   );

my (
      %config, %includes, $tmpdir
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

# Do some basic sanity checking and exit if something fails.
# A new PATH will be set.
sanity_check();

# If we're in config test mode and have come this far, we're done.
if ($config_test_mode) {
    print "No fatal errors in configuration.\n";
    clean_exit("");
}

# Create empty temporary directory.
$tmpdir = make_tempdir($tmp_basedir);

# Set new umask if one was specified in the config file.
umask($config{umask}) if exists($config{umask});

# Download the rules archive. Will exit if it fails.
download_rules("$config{url}", "$tmpdir/$OUTFILE");

# Verify and unpack archive. This will leave us with a directory
# called "rules/" in the same directory as the archive, containing the
# new rules. Will exit if something fails.
unpack_rules_archive("$tmpdir/$OUTFILE");

# Create list of new files (with full path) that we care about from the
# downloaded archive. Filenames (with full path) will be stored as
# %new_files{filenme}.
my $num_files = get_new_filenames(\my %new_files, "$tmpdir/rules/");

# Make sure the number of files is at least $min_files.
clean_exit("not enough rules files in downloaded archive (is it broken?)\n".
           "Number of rules files is $num_files but minimum is set to $min_files.")
  if ($num_files < $min_files);

# Disable/modify/clean downloaded rules.
my $num_rules = process_rules(\%{$config{sid_modify_list}},
                              \%{$config{sid_disable_list}},
                              \%{$config{sid_enable_list}},
                              \%new_files);

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
      $#{$changes{new_vars}} > -1);


# Update files listed in %changes{modified_files} (copy the new files
# from the temporary directory into our output directory) and add new
# variables to the local snort.conf if requested, unless we're running in
# careful mode. Create backup first if running with -b.
my $printed = 0;
if ($something_changed) {
    if ($careful) {
        print STDERR "Skipping backup since we are running in careful mode.\n"
          if ($make_backup && (!$quiet));
    } else {
        if ($interactive) {
            print_changes(\%changes, \%rh) ;
            $printed = 1;
        }

        if (!$interactive || ($interactive && approve_changes)) {
            make_backup($config{output_dir}, $config{backup_dir})
              if ($make_backup);

            add_new_vars(\%changes, $config{varfile})
              if ($update_vars);

            update_rules($config{output_dir}, keys(%{$changes{modified_files}}));
        }
    }
} else {
    print STDERR "No files modified - no need to backup old files, skipping.\n"
      if ($make_backup && !$quiet);
}

print "\nNote: Oinkmaster is running in careful mode - not updating anything.\n"
  if ($something_changed && $careful);

print_changes(\%changes, \%rh)
  if (!$printed && ($something_changed || !$quiet));


# Everything worked. Do a clean exit without any error message.
clean_exit("");


# END OF MAIN #



# Show usage information and exit.
sub show_usage()
{
    my $progname = basename($0);

    print STDERR << "RTFM";

$VERSION

Usage: $progname -o <output dir> [options]

<output dir> is where to put the new files.
This should be the directory where you store the snort rules.

Options:
-b <dir>   Backup your old rules into <dir> before overwriting them
-c         Careful mode - only check for changes and do not update anything
-C <cfg>   Use this configuration file instead of $config_file
-e         Re-enable all rules that are disabled by default in the rules
           distribution (they are disabled for a reason, so use with care)
-h         Show this usage information
-i         Interactive mode - you will be asked to approve the changes (if any)
-q         Quiet mode - no output unless changes were found
-Q         über-quiet mode (like -q but even more quiet when printing results)
-r         Check for rules files that exist in the output directory
           but not in the downloaded rules archive (i.e. files that may
           have been removed from the distribution archive)
-T         Test configuration and then exit
-u <url>   Download from this URL (must be http://, https://, ftp://, file://
           or scp:// ...tar.gz) instead of the URL in the configuration file
-U <file>  Variables that exist in downloaded snort.conf but not in <file>
           will be added to this file (usually your production snort.conf)
-v         Verbose mode
-V         Show version and exit

RTFM
    exit;
}



# Parse the command line arguments and exit if we don't like them.
sub parse_cmdline($)
{
    my $cfg_ref    = shift;
    my $cmdline_ok = getopts('b:cC:ehio:qQrTu:U:vV');

    $config_file          = $opt_C if (defined($opt_C));
    $$cfg_ref{url}        = $opt_u if (defined($opt_u));
    $careful              = 1      if (defined($opt_c));
    $preserve_comments    = 0      if (defined($opt_e));
    $quiet                = 1      if (defined($opt_q));
    $interactive          = 1      if (defined($opt_i));
    $check_removed        = 1      if (defined($opt_r));
    $config_test_mode     = 1      if (defined($opt_T));
    $verbose              = 1      if (defined($opt_v));

    if (defined($opt_Q)) {
        $quiet       = 1;
        $super_quiet = 1;
    }

    if (defined($opt_b)) {
        $$cfg_ref{backup_dir} = File::Spec->canonpath($opt_b);
        $make_backup = 1;
    }

    if (defined($opt_U)) {
        $$cfg_ref{varfile} = $opt_U;
        $update_vars = 1;
    }

    show_usage() if (defined($opt_h));

    if (defined($opt_V)) {
        print "$VERSION\n";
        exit(0);
    }

    show_usage unless ($cmdline_ok);

  # -o <dir> is the only required option in normal usage.
    if (defined($opt_o)) {
        $$cfg_ref{output_dir} = File::Spec->canonpath($opt_o);
    } else {
        show_usage();
    }

  # Don't accept additional arguments, since they're invalid.
    $_ = shift(@ARGV) && show_usage();
}



# Read in stuff from the configuration file.
sub read_config($ $)
{
    my $config_file = shift;
    my $cfg_ref     = shift;
    my $linenum     = 0;

    unless (-e "$config_file") {
        clean_exit("configuration file \"$config_file\" does not exist.\n".
                   "Put it there or use the -C argument.");
    }

  # Basic check to avoid cross-include of files (infinite recursion).
    clean_exit("attempt to load \"$config_file\" twice.")
      if (exists($includes{$config_file}));

    $includes{$config_file}++;

    open(CONF, "<$config_file")
      or clean_exit("could not open configuration file \"$config_file\": $!");
    my @conf = <CONF>;
    close(CONF);

    while ($_ = shift(@conf)) {
        $linenum++;

      # Remove comments unless it's a modifysid line.
        s/\s*\#.*// unless (/^\s*modifysid/i);

      # Remove leading/traling whitespaces.
	s/^\s*//;
	s/\s*$//;

      # Skip blank lines.
        next unless (/\S/);

      # modifysid <SID[,SID, ...]> "substthis" | "withthis"
       if (/^modifysids*\s+(\d+.*)\s+"(.+)"\s+\|\s+"(.*)"\s*$/i) {
            my ($sid_list, $subst, $repl) = ($1, $2, $3);
            warn("WARNING: line $linenum in $config_file is invalid, ignoring\n")
              unless(parse_mod_expr(\%{$$cfg_ref{sid_modify_list}}, 
                                    $sid_list, $subst, $repl));

      # disablesid <SID[,SID, ...]>
        } elsif (/^disablesids*\s+(\d.*)/i) {
	    my $sid_list = $1;
	    foreach my $sid (split(/\s*,\s*/, $sid_list)) {
  	        if ($sid =~ /^\d+$/) {
                    $$cfg_ref{sid_disable_list}{$sid}++;
	        } else {
                    warn("WARNING: line $linenum in $config_file is invalid, ignoring\n");
	        }
	    }

      # enablesid <SID[,SID, ...]>
        } elsif (/^enablesids*\s+(\d.*)/i) {
	    my $sid_list = $1;
	    foreach my $sid (split(/\s*,\s*/, $sid_list)) {
  	        if ($sid =~ /^\d+$/) {
                    $$cfg_ref{sid_enable_list}{$sid}++;
	        } else {
                    warn("WARNING: line $linenum in $config_file is invalid, ignoring\n");
	        }
	    }

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

	} elsif (/^url\s*=\s*(.*)/i) {          # URL to use
	    $$cfg_ref{url} = $1
              unless (defined($opt_u));         # command line wins
        
	} elsif (/^path\s*=\s*(.+)/i) {         # $PATH to be used
	    $$cfg_ref{path} = $1;

	} elsif (/^update_files\s*=\s*(.+)/i) { # regexp of files to be updated
	    $$cfg_ref{update_files} = $1;

        } elsif (/^umask\s*=\s*([0-7]{4})$/i) { # umask
	    $$cfg_ref{umask} = oct($1);

        } elsif (/^min_files\s*=\s*(\d+)/i) {   # min_files
            $min_files = $1;

        } elsif (/^min_rules\s*=\s*(\d+)/i) {   # min_rules
            $min_rules= $1;

        } elsif (/^tmpdir\s*=\s*(.+)/i) {       # tmpdir
            $tmp_basedir = $1;

        } elsif (/^scp_key\s*=\s*(.+)/i) {      # scp_key
            $$cfg_ref{scp_key} = $1;

        } elsif (/^include\s+(\S+.*)/) {        # include <file>
             my $include = $1;
             read_config($include, $cfg_ref);

        } else {                                # invalid line
            warn("WARNING: line $linenum in $config_file is invalid, ignoring\n");
        }
    }
}



# Make a few basic tests to make sure things look ok.
# Will also set a new PATH as defined in the config file.
sub sanity_check()
{
   my @req_params   = qw(path update_files);  # required parameters in conf
   my @req_binaries = qw(gzip tar);           # always required binaries

  # Can't use both -q and -v.
    clean_exit("quiet mode and verbose mode at the same time doesn't make sense.")
      if ($quiet && $verbose);

  # Make sure all required variables are defined in the config file.
    foreach my $param (@req_params) {
        clean_exit("the required parameter \"$param\" is not defined in $config_file.")
          unless (exists($config{$param}));
    }

  # We now know a path was defined in the config, so set it.
  # If we're under cygwin and path was specified as msdos style, convert
  # it to cygwin style to avoid problems.
    if ($^O eq "cygwin" && $config{path} =~ /^[a-zA-Z]:[\/\\]/) {
        $ENV{PATH} = "";
        foreach my $path (split(/;/, $config{path})) {
	    $ENV{PATH} .= "$path:" if (msdos_to_cygwin_path(\$path));
	}
        chop($ENV{PATH});
    } else {
        $ENV{PATH} = $config{path};
    }

  # Reset environment variables that may cause trouble.
    delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};

  # Make sure $config{update_files} is a valid regexp.
    eval {
        "foo" =~ /$config{update_files}/;
    };

    clean_exit("update_files ($config{update_files}) is not a valid regexp: $@")
      if ($@);

  # If a variable file (probably local snort.conf) has been specified,
  # it must exist. It must also be writable unless we're in careful mode.
    if ($update_vars) {
	$config{varfile} = untaint_path($config{varfile});

        clean_exit("variable file $config{varfile} does not exist.")
          unless (-e "$config{varfile}");

        clean_exit("variable file $config{varfile} is not writable by you.")
          if (!$careful && !-w "$config{varfile}");
    }

  # Make sure all required binaries can be found.
  # Wget is not required if user specifies file:// as url. 
    foreach my $binary (@req_binaries) {
        clean_exit("$binary not found in PATH ($ENV{PATH}).")
          unless (is_in_path($binary));
    }

  # Make sure $url is defined (either by -u <url> or url=... in the conf).
    clean_exit("incorrect URL or URL not specified in either $config_file or command line.")
      unless (exists($config{'url'}) &&
        (($config{'url'}) = $config{'url'} =~ /^((?:https*|ftp|file|scp):\/\/.+\.tar\.gz)$/));

  # Wget must be found if url is http[s]:// or ftp://.
    clean_exit("wget not found in PATH ($ENV{PATH}).")
      if ($config{'url'} =~ /^(https*|ftp):/ && !is_in_path("wget"));

  # scp must be found if scp://...
    clean_exit("scp not found in PATH ($ENV{PATH}).")
      if ($config{'url'} =~ /^scp:/ && !is_in_path("scp"));

  # ssh key must exist if specified and url is scp://...
    clean_exit("ssh key $config{scp_key} does not exist.")
      if ($config{'url'} =~ /^scp:/ && exists($config{scp_key})
        && !-e $config{scp_key});

  # Untaint output directory string.
    $config{output_dir} = untaint_path($config{output_dir});

  # Make sure the output directory exists and is readable.
    clean_exit("the output directory \"$config{output_dir}\" doesn't exist ".
               "or isn't readable by you.")
      if (!-d "$config{output_dir}" || !-x "$config{output_dir}");
 
  # Make sure the output directory is writable unless running in careful mode.
    clean_exit("the output directory \"$config{output_dir}\" isn't writable by you.")
      if (!$careful && !-w "$config{output_dir}");

  # Make sure the backup directory exists and is writable if running with -b.
    if ($make_backup) {
        $config{backup_dir} = untaint_path($config{backup_dir});
        clean_exit("the backup directory \"$config{backup_dir}\" doesn't exist or ".
                 "isn't writable by you.")
          if (!-d "$config{backup_dir}" || !-w "$config{backup_dir}");
    }

  # Convert tmp_basedir to cygwin style if running cygwin and msdos style was specified.
    if ($^O eq "cygwin" && $tmp_basedir =~ /^[a-zA-Z]:[\/\\]/) {
        msdos_to_cygwin_path(\$tmp_basedir)
          or clean_exit("could not convert temporary dir to cygwin style");
    }

  # Make sure temporary directory exists.
    clean_exit("the temporary directory $tmp_basedir does not exist or isn't writable by you.")
      if (!-d "$tmp_basedir" || !-w "$tmp_basedir");

  # Also untaint it.
    $tmp_basedir = untaint_path($tmp_basedir);

  # Make sure stdout is a tty if we're running in interactive mode.
    clean_exit("you can not run in interactive mode if standard output is not a TTY.")
      if ($interactive && !-t STDOUT);
}



# Download the rules archive.
sub download_rules($ $)
{
    my $url       = shift;
    my $localfile = shift;

  # Use wget if URL starts with "http[s]" or "ftp".
    if ($url =~ /^(?:https*|ftp)/) {
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

  # Grab file from local filesystem if file://...
    } elsif ($url =~ /^file/) {
        $url =~ s/^file:\/\///;

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

  # Grab file using scp if scp://...
    } elsif ($url =~ /^scp/) {
        $url =~ s/^scp:\/\///;

        my @cmd;
        push(@cmd, "scp");
        push(@cmd, "-i", "$config{scp_key}") if (exists($config{scp_key}));
        push(@cmd, "-q")                     if ($quiet);
        push(@cmd, "-v")                     if ($verbose);
        push(@cmd, "$url", "$localfile");

        print STDERR "Copying rules archive from $url using scp:\n"
          unless ($quiet);

        clean_exit("scp returned error when trying to copy $url to $localfile")
          if (system(@cmd));
    }

  # Make sure the downloaded file actually exists.
    clean_exit("failed to get rules archive: ".
               "local target file $localfile doesn't exist after download.")
      unless (-e "$localfile");

  # Also make sure it's at least non-empty.
    clean_exit("failed to get rules archive: local target file $localfile is empty ".
               "after download (perhaps you're out of diskspace or file in url is empty?)")
      unless (-s "$localfile");
}



# Make a few basic sanity checks on the rules archive and then
# uncompress/untar it if everything looked ok.
sub unpack_rules_archive($)
{
    my $archive  = shift;

    my $old_dir = getcwd or clean_exit("could not get current directory: $!");
    $old_dir = untaint_path($old_dir);

    my $dir = dirname($archive);
    chdir("$dir") or clean_exit("could not change directory to \"$dir\": $!");

  # Run integrity check (gzip -t) on the gzip file.
    clean_exit("integrity check on gzip file failed (file transfer failed or ".
               "file in URL not in gzip format?).")
      if (system("gzip","-t","$archive"));

  # Decompress it.
    system("gzip","-d","$archive")
      and clean_exit("unable to uncompress $archive.");

  # Suffix has now changed from .tar.gz to .tar.
    $archive =~ s/\.gz$//;

  # Make sure the .tar file now exists.
  # (Gzip may not return an error if it was not a gzipped file...)
    clean_exit("failed to unpack gzip file (file transfer failed or ".
               "file in URL not in gzip format?).")
      unless (-e  "$archive");

  # Read output from "tar tf $archive" into @tar_test, unless we're on Windows.
    my @tar_test;

    unless ($^O eq "MSWin32" || $^O =~ /^Windows/) {
        if (open(TAR,"-|")) {
            @tar_test = <TAR>;
        } else {
            exec("tar","tf","$archive");
        }
        close(TAR);
    }

  # For each filename in the archive, do some basic (pretty useless) 
  # sanity checks.
    foreach my $filename (@tar_test) {
       chomp($filename);

      # We don't want to have any weird characters anywhere in the filename.
        clean_exit("illegal characters in filename in tar archive. ".
                   "Offending file/line:\n$filename")
          if ($filename =~ /[^$OK_PATH_CHARS]/);

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

    chdir($old_dir)
      or clean_exit("could not change directory back to $old_dir: $!");

    print STDERR "done.\n" 
      unless ($quiet);
}



# Open all rules files in the temporary directory and disable/modify all
# rules/lines as requested in oinkmaster.conf, and then write back to the
# same files. Also clean unwanted whitespaces and duplicate sids from them.
sub process_rules($ $ $ $)
{
    my $modify_sid_ref  = shift;
    my $disable_sid_ref = shift;
    my $enable_sid_ref  = shift;
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
          unless (-f "$file" && !-l "$file");

        open(INFILE, "<$file")
          or clean_exit("could not open $file for reading: $!");
	my @infile = <INFILE>;
        close(INFILE);

      # Write back to the same file.
	open(OUTFILE, ">$file")
          or clean_exit("could not open $file for writing: $!");

        my ($single, $multi, $nonrule, $msg, $sid);

	RULELOOP:while (get_next_entry(\@infile, \$single, \$multi, \$nonrule, \$msg, \$sid)) {
	    if (defined($nonrule)) {
	        print OUTFILE "$nonrule";
		next RULELOOP;
	    }

          # We've got a valid rule. If we have already seen this sid, discard this rule.
            if (exists($sids{$sid})) {
                $_ = basename($file);
                warn("\nWARNING: duplicate SID in downloaded file $_, ".
                     "SID=$sid, which has already been seen in $sids{$sid}, ".
                     "discarding rule \"$msg\"\n");
                next RULELOOP;
            }

            $sids{$sid} = basename($file);

          # Even if it was a single-line rule, we want a copy in $multi.
	    $multi = $single unless (defined($multi));

          # Some rules may be commented out by default. 
          # Enable them if -e is specified.
	    if ($multi =~ /^#/) {
		unless ($preserve_comments) {
		    print STDERR "Enabling disabled rule (SID $sid): $msg\n"
		      if ($verbose);
                    $multi =~ s/^#*//;
                    $multi =~ s/\n#*/\n/g;
		}
	    }

          # Modify rule if requested.
            foreach my $mod_expr (@{$$modify_sid_ref{$sid}}) {
                my ($subst, $repl) = ($mod_expr->[0], $mod_expr->[1]);

		if ($multi =~ /$subst/) {
  	            print STDERR "Modifying SID $sid, subst=$subst, ".
                                 "repl=$repl\nBefore: $multi\n"
		      if ($verbose);

                    $multi =~ s/$subst/$repl/ee;

  	  	    print STDERR "After:  $multi\n"
                      if ($verbose);
		} else {
                    print STDERR "\nWARNING: SID $sid does not match ".
                                 "modifysid expression \"$subst\", skipping\n";
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

          # Enable rule if requested.
            if (exists($$enable_sid_ref{"$sid"})) {
                print STDERR "Enabling SID $sid: $msg\n"
                  if ($verbose);

                $multi =~ s/^#+//;
                $multi =~ s/\n#+(.+)/\n$1/g;
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

    print STDERR "Setting up rules structures... "
      unless ($quiet);

    foreach my $file (sort(keys(%$new_files_ref))) {
        warn("WARNING: downloaded rules file $file is empty\n")
          if (!-s "$file" && $verbose);

        open(NEWFILE, "<$file")
          or clean_exit("could not open $file for reading: $!");
        my @newfile = <NEWFILE>;
        close(NEWFILE);

      # From now on we don't care about the path, so remove it.
	$file = basename($file);

        my ($single, $multi, $nonrule, $msg, $sid);

	while (get_next_entry(\@newfile, \$single, \$multi, \$nonrule, \$msg, \$sid)) {
	    if (defined($single)) {
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

	    while (get_next_entry(\@oldfile, \$single, \$multi, \$nonrule, undef, \$sid)) {
	        if (defined($single)) {
		    warn("WARNING: duplicate SID in your local rules, SID ".
                         "$sid exists multiple times, please fix this manually!\n")
		      if (exists($allsids{old}{"$sid"}));

	  	    $rh{old}{rules}{"$file"}{"$sid"} = $single;
	  	    $allsids{old}{"$sid"}++;
                } else {                     # add non-rule line
	            push(@{$rh{old}{other}{"$file"}}, $nonrule);
                }
            }
        } else {         # downloaded file did not exist in old rules dir
	    $rh{added_files}{"$file"}++;
        }
    }

    print STDERR "done.\n" 
      unless ($quiet);

    return (%rh);
}



# Try to find a given string in a given array. Return 1 if found, or 0 if not.
# Some things will always be considered as found (lines that we don't care if
# they were added/removed). It's extremely slow and braindead, but who cares.
sub find_line($ $)
{
    my $line    = shift;   # line to look for
    my $arr_ref = shift;   # reference to array to look in

  # Skip blank lines and CVS Id tags.
    return (1) unless ($line =~ /\S/);
    return (1) if     ($line =~ /^\s*#+\s*\$I\S:.+Exp\s*\$/);

    foreach $_ (@$arr_ref) {
        return (1) if ($_ eq $line);
    }

    return (0);
}



# Backup files in output dir matching $config{update_files} into the backup dir.
sub make_backup($ $)
{
    my $src_dir  = shift;    # dir with the rules to be backed up
    my $dest_dir = shift;    # where to put the backup tarball

    (undef, my $min, my $hour, my $mday, my $mon, my $year, undef, undef, undef)
      = localtime(time);

    my $date = sprintf("%d%02d%02d-%02d%02d", 
                       $year + 1900, $mon + 1, $mday, $hour, $min);

    my $backup_tmp_dir = "$tmpdir/rules-backup-$date";

  # Get current directory and untaint it.
    my $old_dir = getcwd or clean_exit("could not get current directory: $!");
    $old_dir = untaint_path($old_dir);

    print STDERR "Creating backup of old rules..."
      unless ($quiet);

    mkdir("$backup_tmp_dir", 0700)
      or clean_exit("could not create temporary backup directory $backup_tmp_dir: $!");

  # Copy all rules files from the rules dir to the temporary backup dir.
    opendir(OLDRULES, "$src_dir")
      or clean_exit("could not open directory $src_dir: $!");

    while ($_ = readdir(OLDRULES)) {
        if (/$config{update_files}/) {
	    my $src_file = untaint_path("$src_dir/$_");
            copy("$src_file", "$backup_tmp_dir/")
              or warn("WARNING: error copying $src_file to $backup_tmp_dir/: $!");
	}
    }

    closedir(OLDRULES);

  # Also backup the -U <file> (as "variable-file.conf") if specified.
    if ($update_vars) {
        copy("$config{varfile}", "$backup_tmp_dir/variable-file.conf")
          or warn("WARNING: error copying $config{varfile} to $backup_tmp_dir: $!")
    }

  # Change directory to $tmpdir (so we'll be right below the directory where
  # we have our rules to be backed up).
    chdir("$tmpdir") or clean_exit("could not change directory to $tmpdir: $!");

  # Execute tar command. This will archive "rules-backup-$date/"
  # into the file rules-backup-$date.tar, placed in $tmpdir.
    warn("WARNING: tar command did not exit with status 0 when archiving backup files.\n")
      if (system("tar","cf","rules-backup-$date.tar","rules-backup-$date"));

    warn("WARNING: gzip command did not exit with status 0 when compressing backup file.\n")
      if (system("gzip","rules-backup-$date.tar"));

  # Change back to old directory (so it will work with -b <directory> as either
  # an absolute or a relative path.
    chdir("$old_dir")
      or clean_exit("could not change directory back to $old_dir: $!");

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

    print "\n[***] Results from Oinkmaster started " . 
          scalar(localtime) . " [***]\n";

  # Print new variables.
    if ($update_vars) {
       if ($#{$changes{new_vars}} > -1) {
            print "\n[*] New variables: [*]\n";
            foreach my $var (@{$changes{new_vars}}) {
                print "    $var";
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
	print_changetype($PRINT_BOTH, "Modified inactive in",
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
    my $ch_ref = shift;   # reference to an entry in the rules changes hash
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

  # We have the list of added files (without full path) in $rh_ref{added_files}
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
              if (/$config{update_files}/ && 
                !exists($config{file_ignore_list}{$_}) && 
                !-e "$tmpdir/rules/$_");
        }

        closedir(OLDRULES);
    }

  # For each new rules file...
    FILELOOP:foreach my $file_w_path (sort(keys(%$new_files_ref))) {
        my $file = basename($file_w_path);

      # Skip comparison if it's an added file.
        next FILELOOP if (exists($$rh_ref{added_files}{$file}));

      # For each sid in the new file...
        foreach my $sid (keys(%{$$rh_ref{new}{rules}{$file}})) {
            my $new_rule = $$rh_ref{new}{rules}{$file}{$sid};

              # Sid also exists in the old file?
                if (exists($$rh_ref{old}{rules}{$file}{$sid})) {
                    my $old_rule = $$rh_ref{old}{rules}{$file}{$sid};

                  # Are they identical?
		    unless ($new_rule eq $old_rule) {
                        $changes{modified_files}{$file_w_path}++;

                      # Find out in which way the rules are different.
                        if ("#$old_rule" eq $new_rule) {
 	                    $changes{rules}{dis}{$file}{$sid}++;
                        } elsif ($old_rule eq "#$new_rule") {
 	                    $changes{rules}{ena}{$file}{$sid}++;
                        } elsif ($old_rule =~ /^\s*#/ && $new_rule !~ /^\s*#/) {
 	                    $changes{rules}{ena_mod}{$file}{$sid}++;
                        } elsif ($old_rule !~ /^\s*#/ && $new_rule =~ /^\s*#/) {
 	                    $changes{rules}{dis_mod}{$file}{$sid}++;
                        } elsif ($old_rule =~ /^\s*#/ && $new_rule =~ /^\s*#/) {
 	                    $changes{rules}{mod_ina}{$file}{$sid}++;
                        } else {
 	                    $changes{rules}{mod_act}{$file}{$sid}++;
	  	        }

		    }
	        } else {    # sid not found in old file, i.e. it's added
                    $changes{modified_files}{$file_w_path}++;
  	            $changes{rules}{added}{$file}{$sid}++;
	        }
        } # foreach sid

      # Check for removed rules, i.e. sids that exist in the old file but 
      # not in the new one.
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

    print STDERR "done.\n" 
      unless ($quiet);

    return (%changes);
}



# Create list of new files (with full path) that we care about.
# I.e. files that match the 'update_files' regexp and isn't listed
# in the ignore list.
sub get_new_filenames($ $)
{
    my $new_files_ref = shift;
    my $new_rules_dir = shift;

    opendir(NEWRULES, "$new_rules_dir")
      or clean_exit("could not open directory $new_rules_dir: $!");

    while ($_ = readdir(NEWRULES)) {
        $new_files{"$new_rules_dir/$_"}++
          if (/$config{update_files}/ && !exists($config{file_ignore_list}{$_}));
    }
    closedir(NEWRULES);

  # Return number of new interesting filenames.
    return (keys(%$new_files_ref));
}



# Simply copy the modified rules files to the output directory.
sub update_rules($ @)
{
    my $dst_dir        = shift;
    my @modified_files = @_;

    print STDERR "Updating rules... "
      if (!$quiet || $interactive);

    foreach my $file_w_path (@modified_files) {
        copy("$file_w_path", "$dst_dir")
          or clean_exit("could not copy $file_w_path to $dst_dir: $!");
    }

    print STDERR "done.\n"
      if (!$quiet || $interactive);
}



# Return true if file is in PATH and is executable.
sub is_in_path($)
{
    my $file = shift;

    foreach my $dir (File::Spec->path()) {
        return (1) if (-x "$dir/$file" || -x "$dir/$file.exe");
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

  # Possible beginning of multi-line rule?
    if ($line =~ /$MULTILINE_RULE_REGEXP/oi) {
        $$single_ref = $line;
        $$multi_ref  = $line;

      # Keep on reading as long as line ends with "\".
        while ($line =~ /\\\s*\n$/) {

          # Remove trailing "\" and newline for single-line version.
            $$single_ref =~ s/\\\s*\n//;

          # If there are no more lines, this can not be a valid multi-line rule.
            if (!($line = shift(@$arr_ref))) {

                warn("WARNING: got EOF while parsing multi-line rule: $$multi_ref\n")
                  if ($verbose);

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
            $line =~ s/^\s*#*\s*//;  # remove leading # in single-line version
            $$single_ref .= $line;

        } # while line ends with "\"

      # Single-line version should now be a valid rule.
      # If not, it wasn't a valid multi-line rule after all.
        if (parse_singleline_rule($$single_ref, $msg_ref, $sid_ref)) {

            $$single_ref =~ s/^\s*//;     # remove leading whitespaces
            $$single_ref =~ s/^#+\s*/#/;  # remove whitespaces next to leading #
            $$single_ref =~ s/\s*\n$/\n/; # remove trailing whitespaces

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
     } elsif (parse_singleline_rule($line, $msg_ref, $sid_ref)) {  # regular single-line rule?
        $$single_ref = $line;
        $$single_ref =~ s/^\s*//;     # remove leading whitespaces
        $$single_ref =~ s/^#+\s*/#/;  # remove whitespaces next to leading #
        $$single_ref =~ s/\s*\n$/\n/; # remove trailing whitespaces

        return (1);   # return single
    } else {                          # non-rule line

      # Do extra check and warn if it *might* be a rule anyway, 
      # but that we just couldn't parse for some reason.
        warn("WARNING: line may be a rule but it could not be parsed: $line\n")
          if ($verbose && $line =~ /^\s*alert .+msg\s*:\s*".+"\s*;/);

        $$nonrule_ref = $line;
        $$nonrule_ref =~ s/\s*\n$/\n/;

        return (1);   # return non-rule
    }
}



# Create empty temporary directory inside the directory given as argument.
# Will die if we can't create it.
# If successful, the name of the created directory is returned.
sub make_tempdir($)
{
    my $base   = shift;
    my $tmpdir = "$base/oinkmaster.$$";

    mkdir("$tmpdir", 0700)
      or clean_exit("could not create temporary directory $tmpdir: $!");

    return ($tmpdir);
}



# Look for variables that exist in dist snort.conf but not in local snort.conf.
sub get_new_vars($ $ $)
{
    my $ch_ref     = shift;
    my $local_conf = shift;
    my $dist_conf  = shift;
    my @new_vars;
    my %old_vars;

    unless (-e "$dist_conf") {
        $_ = basename($dist_conf);
        warn("WARNING: no $_ found in downloaded archive, ".
             "aborting check for new variables\n");
        return;
    }

    print STDERR "Looking for new variables... "
      unless ($quiet);


  # Read in variables from old file.
    open(LOCAL_CONF, "<$local_conf")
      or clean_exit("could not open $local_conf for reading: $!");

    my @local_conf = <LOCAL_CONF>;

    foreach $_ (@local_conf) {
        $old_vars{lc($1)}++ if (/$VAR_REGEXP/i);
    }

    close(LOCAL_CONF);


  # Read in variables from new file.
    open(DIST_CONF, "<$dist_conf")
      or clean_exit("could not open $dist_conf for reading: $!");

    while ($_ = <DIST_CONF>) {
        push(@new_vars, $_)
          if (/$VAR_REGEXP/i && !exists($old_vars{lc($1)}));
    }

    close(DIST_CONF);

    @{$$ch_ref{new_vars}} = @new_vars;

    print STDERR "done.\n"
      unless ($quiet);
}



# Add variables to local snort.conf.
sub add_new_vars($ $)
{
    my $ch_ref  = shift;
    my $varfile = shift;
    my $new_content;

    return unless ($#{$changes{new_vars}} > -1);

    open(OLD_LOCAL_CONF, "<$varfile")
      or clean_exit("could not open $varfile for reading: $!");
    my @old_content = <OLD_LOCAL_CONF>;
    close(OLD_LOCAL_CONF);

    open(NEW_LOCAL_CONF, ">$varfile")
      or clean_exit("could not open $varfile for writing: $!");

    my @old_vars = grep(/$VAR_REGEXP/i, @old_content);


  # If any vars exist in old file, find last one before inserting new ones.
    if ($#old_vars > -1) {
        while ($_ = shift(@old_content)) {
            print NEW_LOCAL_CONF $_;
            last if ($_ eq $old_vars[$#old_vars]);
        }
    }

    print NEW_LOCAL_CONF @{$changes{new_vars}};
    print NEW_LOCAL_CONF @old_content;

    close(NEW_LOCAL_CONF);
}



# Convert msdos style path to cygwin style.
sub msdos_to_cygwin_path($)
{
    my $path_ref = shift;

    if ($$path_ref =~ /^([a-zA-Z]):[\/\\](.*)/) {
        my ($drive, $dir) = ($1, $2);
	$dir =~ s/\\/\//g;
	$$path_ref = "/cygdrive/$drive/$dir";
        return (1);
    }

    return (0);
}



# Parse and process a modifysid expression. 
# Return 1 if valid, or otherwise 0.
sub parse_mod_expr($ $ $ $)
{
    my $mod_list_ref = shift;  # where to store valid entries
    my $sid_list     = shift;  # comma-separated list of SIDs
    my $subst        = shift;  # regexp to look for
    my $repl         = shift;  # regexp to replace it with

    $sid_list =~ s/\s+$//;

    foreach my $sid (split(/\s*,\s*/, $sid_list)) {
        return (0) unless ($sid =~ /^\d+$/);

      # Make sure the regexps don't generate invalid code.
        my $repl_qq = "qq/$repl/";
        my $dummy   = "foo";

        eval '$dummy =~ s/$subst/$repl/ee';

        if ($@) {
            warn("Invalid regexp: $@");
            return (0);
        }

      # It's valid, so add to list.
        push(@{$$mod_list_ref{$sid}}, [$subst, $repl_qq]);
    }

    return (1);
}



# Untaint a path. Die if it contains illegal chars.
sub untaint_path($)
{
    my $path          = shift;
    my $orig_path     = $path;

    (($path) = $path =~ /^([$OK_PATH_CHARS]+)$/)
      or clean_exit("illegal characterss in path/filename ".
                    "\"$orig_path\", allowed are $OK_PATH_CHARS\n");

    return ($path);
}



# Ask user to approve changes. Return 1 for yes, 0 for no.
sub approve_changes()
{
    my $answer = "";

    while ($answer !~ /^[yn]/i) {
        print "Do you approve these changes? [Yn] ";
        $answer = <STDIN>;
        $answer = "y" unless ($answer =~ /\S/);
    }

    return ($answer =~ /^y/);
}



# Check a string and return 1 if it's a valid snort rule, or otherwise 0.
# Msg string is put in second arg, and sid in third.
sub parse_singleline_rule($ $ $)
{
    my $line    = shift;
    my $msg_ref = shift;
    my $sid_ref = shift;

    if ($line =~ /^\s*#*\s*(?:alert|drop|log|pass|reject|sdrop)\s.+;\s*\)\s*$/oi) {

        if ($line =~ /msg\s*:\s*"(.+?)"\s*;/oi) {
            $$msg_ref = $1;
        } else {
            return (0);
        }

        if ($line =~ /sid\s*:\s*(\d+)\s*;/oi) {
            $$sid_ref = $1;
        } else {
            return (0);
        }

        return (1);
    }

    return (0);
}



# Remove temporary directory and exit.
# If a non-empty string is given as argument, it will be regarded
# as an error message and we will use die() with the message instead
# of just exit(0).
sub clean_exit($)
{
    if (defined($tmpdir)) {
        chdir(File::Spec->rootdir());
        rmtree("$tmpdir", 0, 1);
    }

    if ($_[0] eq "") {
        exit(0);
    } else {
        $_ = $_[0];
	chomp;
        die("\n$0: Error: $_\n\nOink, oink. Exiting...\n");
    }
}



#### EOF ####
