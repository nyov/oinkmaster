#!/usr/bin/perl -w

# $Id$ #

# Copyright (C) 2002-2004 Andreas �stling <andreaso@it.su.se>

use 5.006001;

use strict;
use File::Basename;
use File::Copy;
use File::Path;
use File::Spec;
use Getopt::Long;
use File::Temp qw(tempdir);

sub show_usage();
sub parse_cmdline($);
sub read_config($ $);
sub sanity_check();
sub download_file($ $);
sub unpack_rules_archive($ $);
sub process_rules($ $ $ $);
sub setup_rules_hash($ $);
sub get_first_only($ $ $);
sub print_changes($ $);
sub print_changetype($ $ $ $);
sub make_backup($ $);
sub get_changes($ $ $);
sub get_new_filenames($ $);
sub update_rules($ @);
sub is_in_path($);
sub get_next_entry($ $ $ $ $ $);
sub get_new_vars($ $ $);
sub add_new_vars($ $);
sub write_new_vars($ $);
sub msdos_to_cygwin_path($);
sub parse_mod_expr($ $ $ $);
sub untaint_path($);
sub approve_changes();
sub parse_singleline_rule($ $ $);
sub catch_sigint();
sub clean_exit($);


my $VERSION            = 'Oinkmaster v1.0-beta1 by Andreas �stling <andreaso@it.su.se>';
my $OUTFILE            = 'snortrules.tar.gz';
my $RULES_DIR          = 'rules';
my $DIST_SNORT_CONF    = "$RULES_DIR/snort.conf";

my $PRINT_NEW          = 1;
my $PRINT_OLD          = 2;
my $PRINT_BOTH         = 3;

my %config = (
    careful            => 0,
    check_removed      => 0,
    config_test_mode   => 0,
    enable_all         => 0,
    interactive        => 0,
    make_backup        => 0,
    min_files          => 1,
    min_rules          => 1,
    quiet              => 0,
    super_quiet        => 0,
    update_vars        => 0,
    use_external_bins  => 1,
    verbose            => 0,
    rule_actions       => "alert|drop|log|pass|reject|sdrop|activate|dynamic",
    tmp_basedir        => $ENV{TMP} || $ENV{TMPDIR} || $ENV{TEMPDIR} || '/tmp',
);


# Regexp to match the start of a multi-line rule.
# %ACTIONS% will be replaced with content of $config{actions} later.
# sid and msg will then be looked for in parse_singleline_rule().
my $MULTILINE_RULE_REGEXP  = '^\s*#*\s*(?:%ACTIONS%)'.
                             '\s.*\\\\\s*\n$'; # ';

# Regexp to match a single-line rule.
# sid and msg will then be looked for in parse_singleline_rule().
my $SINGLELINE_RULE_REGEXP = '^\s*#*\s*(?:%ACTIONS%)'.
                             '\s.+;\s*\)\s*$'; # ';

# Match var line where var name goes into $1.
my $VAR_REGEXP = '^\s*var\s+(\S+)\s+\S+';

# Allowed characters in misc paths/filenames, including the ones in the tarball.
my $OK_PATH_CHARS = 'a-zA-Z\d\ _\(\)\[\]\.\-+:\\\/~@,=';

# Default locations for configuration file.
my @DEFAULT_CONFIG_FILES = qw(
    /etc/oinkmaster.conf
    /usr/local/etc/oinkmaster.conf
);

my (%loaded, $tmpdir);



#### MAIN ####

# No buffering.
select(STDERR);
$| = 1;
select(STDOUT);
$| = 1;


my $start_date = scalar(localtime);

# Assume the required Perl modules are available if we're on Windows.
$config{use_external_bins} = 0 if ($^O eq "MSWin32");

# Parse command line arguments and add at least %config{output_dir}.
parse_cmdline(\%config);

# If no config was specified on command line, look for one in default locations.
if ($#{$config{config_files}} == -1) {
    foreach my $config (@DEFAULT_CONFIG_FILES) {
        if (-e "$config") {
            push(@{${config{config_files}}}, $config);
            last;
        }
    }
}

# If config is still not defined, we can't continue.
if ($#{$config{config_files}} == -1) {
    clean_exit("configuration file not found in default locations\n".
               "(@DEFAULT_CONFIG_FILES)\n".
               "Put it there or use the \"-C\" argument.");
}

read_config($_, \%config) for @{$config{config_files}};

# Now substitute "%ACTIONS%" with $config{rule_actions}, which may have
# been modified after reading the config file.
$SINGLELINE_RULE_REGEXP =~ s/%ACTIONS%/$config{rule_actions}/;
$MULTILINE_RULE_REGEXP  =~ s/%ACTIONS%/$config{rule_actions}/;

# If we're told not to use external binaries, load the Perl modules now.
unless ($config{use_external_bins}) {
    print STDERR "Loading Perl modules.\n" if ($config{verbose});

    eval {
        require IO::Zlib;
        require Archive::Tar;
        require LWP::UserAgent;
    };

    clean_exit("failed to load required Perl modules:\n\n$@\n".
               "Install them or set use_external_bins to 1 ".
               "if you want to use external binaries instead.")
      if ($@);
}


# Do some basic sanity checking and exit if something fails.
# A new PATH will be set.
sanity_check();

$SIG{INT} = \&catch_sigint;

# Create temporary dir.
$tmpdir = tempdir("oinkmaster.XXXXXXXXXX", DIR => File::Spec->rel2abs($config{tmp_basedir}))
  or clean_exit("could not create temporary directory in $config{tmp_basedir}: $!");

# If we're in config test mode and have come this far, we're done.
if ($config{config_test_mode}) {
    print "No fatal errors in configuration.\n";
    clean_exit("");
}

umask($config{umask}) if exists($config{umask});

# Download the rules archive. Will exit if it fails.
download_file("$config{url}", "$tmpdir/$OUTFILE");

# Verify and unpack archive. This will leave us with a directory
# called $RULES_DIR in the same directory as the archive, containing the
# new rules. Will exit if something fails.
unpack_rules_archive("$tmpdir/$OUTFILE", $RULES_DIR);

# Create list of new files that we care about from the downloaded
# Filenames (with full path) will be stored as %new_files{filename}.
my $num_files = get_new_filenames(\my %new_files, "$tmpdir/$RULES_DIR");

# Make sure we have at least the minumum number of files.
clean_exit("not enough rules files in downloaded archive (is it broken?)\n".
           "Number of rules files is $num_files but minimum is set to $config{min_files}.")
  if ($num_files < $config{min_files});

# Disable/modify/clean downloaded rules.
my $num_rules = process_rules(\%{$config{sid_modify_list}},
                              \%{$config{sid_disable_list}},
                              \%{$config{sid_enable_list}},
                              \%new_files);

# Make sure we have at least the minumum number of rules.
clean_exit("not enough rules in downloaded archive (is it broken?)\n".
           "Number of rules is $num_rules but minimum is set to $config{min_rules}.")
  if ($num_rules < $config{min_rules});

# Setup a hash containing the content of all rules files.
my %rh = setup_rules_hash(\%new_files, $config{output_dir});

# Compare the new rules to the old ones.
my %changes = get_changes(\%rh, \%new_files, $RULES_DIR);

# Check for variables that exist in dist snort.conf but not in local snort.conf.
get_new_vars(\%changes, $config{varfile}, "$tmpdir/$DIST_SNORT_CONF")
  if ($config{update_vars});


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
    if ($config{careful}) {
        print STDERR "Skipping backup since we are running in careful mode.\n"
          if ($config{make_backup} && (!$config{quiet}));
    } else {
        if ($config{interactive}) {
            print_changes(\%changes, \%rh);
            $printed = 1;
        }

        if (!$config{interactive} || ($config{interactive} && approve_changes)) {
            make_backup($config{output_dir}, $config{backup_dir})
              if ($config{make_backup});

            add_new_vars(\%changes, $config{varfile})
              if ($config{update_vars});

            update_rules($config{output_dir}, keys(%{$changes{modified_files}}));
        }
    }
} else {
    print STDERR "No files modified - no need to backup old files, skipping.\n"
      if ($config{make_backup} && !$config{quiet});
}

print "\nNote: Oinkmaster is running in careful mode - not updating anything.\n"
  if ($something_changed && $config{careful});

print_changes(\%changes, \%rh)
  if (!$printed && ($something_changed || !$config{quiet}));


# Everything worked. Do a clean exit without any error message.
clean_exit("");


# END OF MAIN #



# Show usage information and exit.
sub show_usage()
{
    my $progname = basename($0);

    print STDERR << "RTFM";

$VERSION

Usage: $progname -o <output directory> [options]

<output directory> is where to put the new files.
This should be the directory where you store your Snort rules.

Options:
-b <dir>   Backup your old rules into <dir> before overwriting them
-c         Careful mode - only check for changes and do not update anything
-C <cfg>   Use this configuration file instead of the default
           May be specified multiple times to load multiple files
-e         Enable all rules that are disabled by default
-h         Show this usage information
-i         Interactive mode - you will be asked to approve the changes (if any)
-q         Quiet mode - no output unless changes were found
-Q         super-quiet mode (like -q but even more quiet when printing results)
-r         Check for rules files that exist in the output directory
           but not in the downloaded rules archive
-T         Test configuration and then exit
-u <url>   Download from this URL instead of the one in the configuration file
           (must be http://, https://, ftp://, file:// or scp:// ... .tar.gz)
-U <file>  Merge new variables from downloaded snort.conf into <file>
-v         Verbose mode
-V         Show version and exit

RTFM
    exit;
}



# Parse the command line arguments and exit if we don't like them.
sub parse_cmdline($)
{
    my $cfg_ref = shift;

    Getopt::Long::Configure("bundling");

    my $cmdline_ok = GetOptions(
        "b=s" => \$$cfg_ref{backup_dir},
        "c"   => \$$cfg_ref{careful},
        "C=s" => \@{$$cfg_ref{config_files}},
        "e"   => \$$cfg_ref{enable_all},
        "h"   => \&show_usage,
        "i"   => \$$cfg_ref{interactive},
        "o=s" => \$$cfg_ref{output_dir},
        "q"   => \$$cfg_ref{quiet},
        "Q"   => \$$cfg_ref{super_quiet},
        "r"   => \$$cfg_ref{check_removed},
        "T"   => \$$cfg_ref{config_test_mode},
        "u=s" => \$$cfg_ref{url},
        "U=s" => \$$cfg_ref{varfile},
        "v"   => \$$cfg_ref{verbose},
        "V"   => sub {
                     print "$VERSION\n";
                     exit(0);
                 }
    );

    show_usage unless ($cmdline_ok && $#ARGV == -1);

    $$cfg_ref{quiet}       = 1 if ($$cfg_ref{super_quiet});
    $$cfg_ref{update_vars} = 1 if ($$cfg_ref{varfile});

    if ($$cfg_ref{backup_dir}) {
        $$cfg_ref{backup_dir} = File::Spec->canonpath($$cfg_ref{backup_dir});
        $$cfg_ref{make_backup} = 1;
    }

  # -o <dir> is the only required option in normal usage.
    if ($$cfg_ref{output_dir}) {
        $$cfg_ref{output_dir} = File::Spec->canonpath($$cfg_ref{output_dir});
    } else {
        warn("Error: no output directory specified.\n");
        show_usage();
    }

  # Mark that url was set on command line (so we don't override it later).
    $$cfg_ref{cmdline_url} = 1 if ($$cfg_ref{url});
}



# Read in stuff from the configuration file.
sub read_config($ $)
{
    my $config_file = shift;
    my $cfg_ref     = shift;
    my $linenum     = 0;

    clean_exit("configuration file \"$config_file\" does not exist.\n")
      unless (-e "$config_file");

    print STDERR "Loading " . File::Spec->rel2abs($config_file) . "\n"
      unless ($config{quiet});

    my ($dev, $ino) = (stat($config_file))[0,1]
      or clean_exit("unable to stat $config_file: $!");

  # Avoid loading the same file multiple times to avoid infinite recursion.
    clean_exit("attempt to load \"$config_file\" twice.")
      if ($loaded{$dev, $ino}++);

    open(CONF, "<", "$config_file")
      or clean_exit("could not open configuration file \"$config_file\": $!");
    my @conf = <CONF>;
    close(CONF);

    while ($_ = shift(@conf)) {
        $linenum++;

      # Remove comments unless it's a modifysid line
      # (the "#" may be part of the modifysid expression).
        s/\s*\#.*// unless (/^\s*modifysid/i);

      # Remove leading/traling whitespaces.
	s/^\s*//;
	s/\s*$//;

      # Skip blank lines.
        next unless (/\S/);


       # modifysid <SID[,SID, ...]> "substthis" | "withthis"
       if (/^modifysids*\s+(\d+.*|\*)\s+"(.+)"\s+\|\s+"(.*)"\s*(?:#.*)*$/i) {
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
                    $config{verbose} && print STDERR "Adding file to ignore list: $file.\n";
                    $$cfg_ref{file_ignore_list}{$file}++;
		} else {
                    warn("WARNING: line $linenum in $config_file is invalid, ignoring\n");
		}
	    }

	} elsif (/^url\s*=\s*(.*)/i) {          # URL to use
	    $$cfg_ref{url} = $1
              unless ($$cfg_ref{cmdline_url});  # command line wins

	} elsif (/^path\s*=\s*(.+)/i) {         # $PATH to be used
	    $$cfg_ref{path} = $1;

	} elsif (/^update_files\s*=\s*(.+)/i) { # regexp of files to be updated
	    $$cfg_ref{update_files} = $1;

	} elsif (/^rule_actions\s*=\s*(.+)/i) { # regexp of rule action keywords
	    $$cfg_ref{rule_actions} = $1;

        } elsif (/^umask\s*=\s*([0-7]{4})$/i) { # umask
	    $$cfg_ref{umask} = oct($1);

        } elsif (/^min_files\s*=\s*(\d+)/i) {   # min_files
            $$cfg_ref{min_files} = $1;

        } elsif (/^min_rules\s*=\s*(\d+)/i) {   # min_rules
            $$cfg_ref{min_rules} = $1;

        } elsif (/^tmpdir\s*=\s*(.+)/i) {       # tmpdir
            $$cfg_ref{tmp_basedir} = $1;

        } elsif (/^use_external_bins\s*=\s*([01])/i) {
            $$cfg_ref{use_external_bins} = $1;

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
   my @req_binaries = qw(gzip tar);           # required binaries (unless we use modules)

  # Can't use both -q and -v.
    clean_exit("quiet mode and verbose mode at the same time doesn't make sense.")
      if ($config{quiet} && $config{verbose});

  # Make sure all required variables are defined in the config file.
    foreach my $param (@req_params) {
        clean_exit("the required parameter \"$param\" is not defined in configuration file.")
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

    clean_exit("update_files (\"$config{update_files}\") is not a valid regexp: $@")
      if ($@);

  # Make sure $config{rule_actions} is a valid regexp.
    eval {
        "foo" =~ /$config{rule_actions}/;
    };

    clean_exit("rule_actions (\"$config{rule_actions}\") is not a valid regexp: $@")
      if ($@);

  # If a variable file (probably local snort.conf) has been specified,
  # it must exist. It must also be writable unless we're in careful mode.
    if ($config{update_vars}) {
	$config{varfile} = untaint_path($config{varfile});

        clean_exit("variable file \"$config{varfile}\" does not exist.")
          unless (-e "$config{varfile}");

        clean_exit("variable file \"$config{varfile}\" is not writable by you.")
          if (!$config{careful} && !-w "$config{varfile}");
    }

  # Make sure all required binaries can be found, unless
  # we're used to use Perl modules instead.
  # Wget is only required if url is http[s] or ftp.
    if ($config{use_external_bins}) {
        foreach my $binary (@req_binaries) {
            clean_exit("$binary not found in PATH ($ENV{PATH}).")
              unless (is_in_path($binary));
        }
    }

  # Make sure $url is defined (either by -u <url> or url=... in the conf).
    clean_exit("incorrect URL or URL not specified in either configuration file or command line.")
      unless (defined($config{'url'}) &&
        (($config{'url'}) = $config{'url'} =~ /^((?:https*|ftp|file|scp):\/\/.+\.tar\.gz)$/));

  # Wget must be found if url is http[s]:// or ftp://.
    if ($config{use_external_bins}) {
        clean_exit("wget not found in PATH ($ENV{PATH}).")
          if ($config{'url'} =~ /^(https*|ftp):/ && !is_in_path("wget"));
    }

  # scp must be found if scp://...
    clean_exit("scp not found in PATH ($ENV{PATH}).")
      if ($config{'url'} =~ /^scp:/ && !is_in_path("scp"));

  # ssh key must exist if specified and url is scp://...
    clean_exit("ssh key \"$config{scp_key}\" does not exist.")
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
      if (!$config{careful} && !-w "$config{output_dir}");

  # Make sure we have read permission on all rules files in the output dir,
  # and also write permission unless we're in careful mode.
  # This is to avoid bailing out in the middle of an execution if a copy
  # fails because of permission problem.
    opendir(OUTDIR, "$config{output_dir}")
      or clean_exit("could not open directory $config{output_dir}: $!");

    while ($_ = readdir(OUTDIR)) {
        next if (/^\.\.?$/ || exists($config{file_ignore_list}{$_}));

        if (/$config{update_files}/) {
            clean_exit("no read permission on \"$config{output_dir}/$_\"\n".
                       "(Read permission is required on all rules files ".
                       "inside the output directory.)\n")
              unless (-r "$config{output_dir}/$_");

            clean_exit("no write permission on \"$config{output_dir}/$_\"\n".
                       "(Write permission is required on all rules files ".
                       "inside the output directory.)\n")
              if (!$config{careful} && !-w "$config{output_dir}/$_");
	}
    }

    closedir(OUTDIR);

  # Make sure the backup directory exists and is writable if running with -b.
    if ($config{make_backup}) {
        $config{backup_dir} = untaint_path($config{backup_dir});
        clean_exit("the backup directory \"$config{backup_dir}\" doesn't exist or ".
                 "isn't writable by you.")
          if (!-d "$config{backup_dir}" || !-w "$config{backup_dir}");
    }

  # Convert tmp_basedir to cygwin style if running cygwin and msdos style was specified.
    if ($^O eq "cygwin" && $config{tmp_basedir} =~ /^[a-zA-Z]:[\/\\]/) {
        msdos_to_cygwin_path(\$config{tmp_basedir})
          or clean_exit("could not convert temporary dir to cygwin style");
    }

  # Make sure temporary directory exists.
    clean_exit("the temporary directory \"$config{tmp_basedir}\" does not ".
               "exist or isn't writable by you.")
      if (!-d "$config{tmp_basedir}" || !-w "$config{tmp_basedir}");

  # Also untaint it.
    $config{tmp_basedir} = untaint_path($config{tmp_basedir});

  # Make sure stdin and stdout are ttys if we're running in interactive mode.
    clean_exit("you can not run in interactive mode when STDIN/STDOUT is not a TTY.")
      if ($config{interactive} && !(-t STDIN && -t STDOUT));
}



# Download the rules archive.
sub download_file($ $)
{
    my $url       = shift;
    my $localfile = shift;
    my $log       = "$tmpdir/wget.log";
    my $ret;

  # If there seems to be a password in the url, replace it with "*password*"
  # and use new string when printing the url to screen.
    my $obfuscated_url = $url;
    $obfuscated_url = "$1:*password*\@$2"
      if ($obfuscated_url =~ /^(\S+:\/\/.+?):.+?@(.+)/);

  # Use wget if URL starts with "http[s]" or "ftp" and we use external binaries.
    if ($config{use_external_bins} && $url =~ /^(?:https*|ftp)/) {
        print STDERR "Downloading file from $obfuscated_url... "
          unless ($config{quiet});

        if ($config{verbose}) {
            print STDERR "\n";
            clean_exit("could not download file")
              if (system("wget", "-v", "-O", "$localfile", "$url"));
        } else {
            if (system("wget", "-v", "-o", "$log", "-O", "$localfile", "$url")) {
                open(LOG, "<", "$log")
                  or clean_exit("could not open $log for reading: $!");
                my @log = <LOG>;
                close(LOG);
                clean_exit("could not download file. Output from wget follows:\n\n @log");
            }
            print STDERR "done.\n" unless ($config{quiet});
        }

  # Use LWP if URL starts with "http[s]" or "ftp" and use_external_bins=0.
    } elsif (!$config{use_external_bins} && $url =~ /^(?:https*|ftp)/) {
        print STDERR "Downloading file from $obfuscated_url... "
          unless ($config{quiet});

        my $ua = LWP::UserAgent->new();
        $ua->env_proxy;
        my $response = $ua->get($url, ':content_file' => $localfile);

        clean_exit("could not download file: " . $response->status_line)
          unless $response->is_success;

        print "done.\n" unless ($config{quiet});

  # Grab file from local filesystem if file://...
    } elsif ($url =~ /^file/) {
        $url =~ s/^file:\/\///;

	clean_exit("the file $url does not exist.")
          unless (-e "$url");

	clean_exit("the file $url is empty.")
          unless (-s "$url");

        print STDERR "Copying file from $url... "
          unless ($config{quiet});

        copy("$url", "$localfile")
          or clean_exit("unable to copy $url to $localfile: $!");

        print STDERR "done.\n"
	  unless ($config{quiet});

  # Grab file using scp if scp://...
    } elsif ($url =~ /^scp/) {
        $url =~ s/^scp:\/\///;

        my @cmd;
        push(@cmd, "scp");
        push(@cmd, "-i", "$config{scp_key}") if (exists($config{scp_key}));
        push(@cmd, "-q")                     if ($config{quiet});
        push(@cmd, "-v")                     if ($config{verbose});
        push(@cmd, "$url", "$localfile");

        print STDERR "Copying file from $url using scp:\n"
          unless ($config{quiet});

        clean_exit("scp returned error when trying to copy $url")
          if (system(@cmd));

  # Unknown download method.
    } else {
        clean_exit("unknown or unsupported download method\n");
    }

  # Make sure the downloaded file actually exists.
    clean_exit("failed to download file: ".
               "local target file $localfile doesn't exist after download.")
      unless (-e "$localfile");

  # Also make sure it's at least non-empty.
    clean_exit("failed to download file: local target file $localfile is empty ".
               "after download (perhaps you're out of diskspace or file in url is empty?)")
      unless (-s "$localfile");
}



# Make a few basic sanity checks on the rules archive and then
# uncompress/untar it if everything looked ok.
sub unpack_rules_archive($ $)
{
    my $archive   = shift;
    my $rules_dir = shift;

    my ($tar, @tar_content);

    my $old_dir = untaint_path(File::Spec->rel2abs(File::Spec->curdir()));

    my $dir = dirname($archive);
    chdir("$dir") or clean_exit("could not change directory to \"$dir\": $!");

    if ($config{use_external_bins}) {

      # Run integrity check on the gzip file.
        clean_exit("integrity check on gzip file failed (file transfer failed or ".
                   "file in URL not in gzip format?).")
          if (system("gzip", "-t", "$archive"));

      # Decompress it.
        system("gzip", "-d", "$archive")
          and clean_exit("unable to uncompress $archive.");

      # Suffix has now changed from .tar.gz to .tar.
        $archive =~ s/\.gz$//;

      # Make sure the .tar file now exists.
      # (Gzip may not return an error if it was not a gzipped file...)
        clean_exit("failed to unpack gzip file (file transfer failed or ".
                   "file in URL not in gzip format?).")
          unless (-e  "$archive");

        my $stdout_file = "$tmpdir/tar_content.out";

        open(my $oldout, ">&STDOUT")      or clean_exit("could not dup STDOUT: $!");
        open(STDOUT, '>', "$stdout_file") or clean_exit("could not redirect STDOUT: $!");

        my $ret = system("tar", "tfP", "$archive");

        close(STDOUT);
        open(STDOUT, ">&", $oldout) or clean_exit("could not dup STDOUT: $!");

        clean_exit("could not list files in tar archive (is it broken?)")
          if ($ret);

        open(TAR, "$stdout_file") or clean_exit("failed to open $stdout_file: $!");
        @tar_content = <TAR>;
        close(TAR);

 # use_external_bins=0
    } else {
        $tar = Archive::Tar->new($archive, 1);
        clean_exit("could not read $archive\n")
          unless (defined($tar));
        @tar_content = $tar->list_files();
    }

  # Make sure we could grab some content from the tarball.
    clean_exit("could not list files in tar archive (is it broken?)")
      if ($#tar_content < 0);

  # For each filename in the archive, do some basic sanity checks.
    foreach my $filename (@tar_content) {
       chomp($filename);

      # We don't want absolute filename.
        clean_exit("archive contains absolute filename. ".
                   "Offending file/line:\n$filename")
          if ($filename =~ /^\//);

      # We don't want to have any weird characters anywhere in the filename.
        clean_exit("illegal character in filename in tar archive. Allowed are ".
                   "$OK_PATH_CHARS\nOffending file/line:\n$filename")
          if ($filename =~ /[^$OK_PATH_CHARS]/);

      # We don't want to unpack any "../../" junk (check is useless now though).
        clean_exit("filename in tar archive contains \"..\".\n".
                   "Offending file/line:\n$filename")
          if ($filename =~ /\.\./);
    }

 # Looks good. Now we can untar it.
    print STDERR "Archive successfully downloaded, unpacking... "
      unless ($config{quiet});

    if ($config{use_external_bins}) {
        clean_exit("failed to untar $archive.")
          if system("tar", "xf", "$archive");
    } else {
        mkdir("$rules_dir") or clean_exit("could not create \"$rules_dir\" directory: $!\n");
        foreach my $file ($tar->list_files) {
            next unless ($file =~ /^$rules_dir\/[^\/]+$/);  # only ^rules/<file>$

            my $content = $tar->get_content($file);

            open(RULEFILE, ">", "$file")
              or clean_exit("could not open \"$file\" for writing: $!\n");
            print RULEFILE $content;
            close(RULEFILE);
        }
    }

    clean_exit("no \"$rules_dir\" directory found in tar file.")
      unless (-d "$dir/$rules_dir");

    chdir($old_dir)
      or clean_exit("could not change directory back to $old_dir: $!");

    print STDERR "done.\n"
      unless ($config{quiet});
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
    my %sids;

    my %stats = (
        disabled => 0,
        enabled  => 0,
        modified => 0,
    );

    warn("WARNING: all rules that are disabled by default will be enabled\n")
      if ($config{enable_all} && !$config{quiet});

    print STDERR "Processing downloaded rules... "
      unless ($config{quiet});

    print STDERR "\n"
      if ($config{verbose});

    foreach my $file (sort(keys(%$newfiles_ref))) {

      # Make sure it's a regular file.
        clean_exit("$file is not a regular file.")
          unless (-f "$file" && !-l "$file");

        open(INFILE, "<", "$file")
          or clean_exit("could not open $file for reading: $!");
	my @infile = <INFILE>;
        close(INFILE);

      # Write back to the same file.
	open(OUTFILE, ">", "$file")
          or clean_exit("could not open $file for writing: $!");

        my ($single, $multi, $nonrule, $msg, $sid);

	RULELOOP:while (get_next_entry(\@infile, \$single, \$multi, \$nonrule, \$msg, \$sid)) {
	    if (defined($nonrule)) {
	        print OUTFILE "$nonrule";
		next RULELOOP;
	    }

          # We've got a valid rule. If we have already seen this sid, discard this rule.
            if (exists($sids{$sid})) {
                warn("\nWARNING: duplicate SID in downloaded archive, SID $sid in ".
                     basename($file) . " has already been seen in " .
                     basename($sids{$sid}). ", discarding rule \"$msg\"\n");
                next RULELOOP;
            }

            $sids{$sid} = $file;

          # Even if it was a single-line rule, we want a copy in $multi.
	    $multi = $single unless (defined($multi));

          # Some rules may be commented out by default.
          # Enable them if -e is specified.
	    if ($multi =~ /^#/ && $config{enable_all}) {
  	        print STDERR "Enabling disabled rule (SID $sid): $msg\n"
	          if ($config{verbose});
                $multi =~ s/^#*//;
                $multi =~ s/\n#*/\n/g;
	    }

          # Modify rule if requested.
            my @all_mod = @{$$modify_sid_ref{'*'}}
              if (exists($$modify_sid_ref{'*'}));

            my @sid_mod = @{$$modify_sid_ref{$sid}}
              if (exists($$modify_sid_ref{$sid}));

            foreach my $mod_expr (@sid_mod, @all_mod) {

                my ($subst, $repl) = ($mod_expr->[0], $mod_expr->[1]);
		if ($multi =~ /$subst/s) {
  	            print STDERR "Modifying SID $sid, subst=$subst, ".
                                 "repl=$repl\nBefore: $multi\n"
		      if ($config{verbose});

                    $multi =~ s/$subst/$repl/see;

  	  	    print STDERR "After:  $multi\n"
                      if ($config{verbose});

                    $stats{modified}++;
		} else {
                    print STDERR "\nWARNING: SID $sid does not match ".
                                 "modifysid expression \"$subst\", skipping\n"
                      unless (exists($$modify_sid_ref{'*'}));
                }
	    }

          # Disable rule if requested and it's not already disabled.
            if (exists($$disable_sid_ref{$sid}) && $multi !~ /^\s*#/) {
                print STDERR "Disabling SID $sid: $msg\n"
                  if ($config{verbose});
                $multi = "#$multi";
                $multi =~ s/\n([^#].+)/\n#$1/g;
                $stats{disabled}++;
	    }

          # Enable rule if requested and it's not already enabled.
            if (exists($$enable_sid_ref{$sid}) && $multi =~ /^\s*#/) {
                print STDERR "Enabling SID $sid: $msg\n"
                  if ($config{verbose});
                $multi =~ s/^#+//;
                $multi =~ s/\n#+(.+)/\n$1/g;
                $stats{enabled}++;
	    }

          # Write rule back to the same rules file.
            print OUTFILE $multi;
        }

        close(OUTFILE);
    }

    print STDERR "disabled $stats{disabled}, enabled $stats{enabled}, ".
                 "modified $stats{modified}, total=" . keys(%sids) . ".\n"
      unless ($config{quiet});

  # Warn on attempt at processing non-existent sids.
    if ($config{verbose}) {
        foreach my $sid (keys(%$modify_sid_ref)) {
            next unless ($sid =~ /^\d+$/);    # don't warn on wildcard match
            warn("WARNING: attempt to modify non-existent SID $sid\n")
              unless (exists($sids{$sid}));
        }
        foreach my $sid (keys(%$enable_sid_ref)) {
            warn("WARNING: attempt to enable non-existent SID $sid\n")
              unless (exists($sids{$sid}));
        }
        foreach my $sid (keys(%$disable_sid_ref)) {
            warn("WARNING: attempt to disable non-existent SID $sid\n")
              unless (exists($sids{$sid}));
        }
    }

  # Return total number of valid rules.
    return (keys(%sids));
}



# Setup rules hash.
# Format for rules will be:     rh{old|new}{rules{filename}{sid} = rule
# Format for non-rules will be: rh{old|new}{other}{filename}     = array of lines
# List of added files will be stored as rh{added_files}{filename}
sub setup_rules_hash($ $)
{
    my $new_files_ref = shift;
    my $output_dir    = shift;

    my (%rh, %old_sids);

    print STDERR "Setting up rules structures... "
      unless ($config{quiet});

    foreach my $file (sort(keys(%$new_files_ref))) {
        warn("\nWARNING: downloaded rules file $file is empty\n")
          if (!-s "$file" && $config{verbose});

        open(NEWFILE, "<", "$file")
          or clean_exit("could not open $file for reading: $!");
        my @newfile = <NEWFILE>;
        close(NEWFILE);

      # From now on we don't care about the path, so remove it.
	$file = basename($file);

        my ($single, $multi, $nonrule, $msg, $sid);

	while (get_next_entry(\@newfile, \$single, \$multi, \$nonrule, \$msg, \$sid)) {
	    if (defined($single)) {
		$rh{new}{rules}{"$file"}{"$sid"} = $single;
	    } else {
	        push(@{$rh{new}{other}{"$file"}}, $nonrule);
	    }
	}

	# Also read in old (aka local) file if it exists.
        # We do a sid dup check in these files.
        if (-f "$output_dir/$file") {
            open(OLDFILE, "<", "$output_dir/$file")
              or clean_exit("could not open $output_dir/$file for reading: $!");
	    my @oldfile = <OLDFILE>;
            close(OLDFILE);

	    while (get_next_entry(\@oldfile, \$single, \$multi, \$nonrule, undef, \$sid)) {
	        if (defined($single)) {
		    warn("\nWARNING: duplicate SID in your local rules, SID ".
                         "$sid exists multiple times, please fix this manually!\n")
		      if (exists($old_sids{$sid}));

	  	    $rh{old}{rules}{"$file"}{"$sid"} = $single;
	  	    $old_sids{$sid}++;
                } else {
	            push(@{$rh{old}{other}{"$file"}}, $nonrule);
                }
            }
        } else {
	    $rh{added_files}{"$file"}++;
        }
    }

    print STDERR "done.\n"
      unless ($config{quiet});

    return (%rh);
}



# Return lines that exist only in first array but not in second one.
sub get_first_only($ $ $)
{
    my $first_only_ref = shift;
    my $first_arr_ref  = shift;
    my $second_arr_ref = shift;
    my %arr_hash;

    @arr_hash{@$second_arr_ref} = ();

    foreach my $line (@$first_arr_ref) {

      # Skip blank lines and CVS Id tags.
        next unless ($line =~ /\S/);
        next if     ($line =~ /^\s*#+\s*\$I\S:.+Exp\s*\$/);

        push(@$first_only_ref, $line)
          unless(exists($arr_hash{$line}));
    }
}



# Backup files in output dir matching $config{update_files} into the backup dir.
sub make_backup($ $)
{
    my $src_dir  = shift;    # dir with the rules to be backed up
    my $dest_dir = shift;    # where to put the backup tarball

    my ($sec, $min, $hour, $mday, $mon, $year) = (localtime)[0 .. 5];

    my $date = sprintf("%4d%02d%02d-%02d%02d%02d",
                       $year + 1900, $mon + 1, $mday, $hour, $min, $sec);

    my $backup_tarball = "rules-backup-$date.tar";
    my $backup_tmp_dir = File::Spec->catdir("$tmpdir", "rules-backup-$date");
    my $dest_file      = File::Spec->catfile("$dest_dir", "$backup_tarball.gz");

    print STDERR "Creating backup of old rules..."
      unless ($config{quiet});

    mkdir("$backup_tmp_dir", 0700)
      or clean_exit("could not create temporary backup directory $backup_tmp_dir: $!");

  # Copy all rules files from the rules dir to the temporary backup dir.
    opendir(OLDRULES, "$src_dir")
      or clean_exit("could not open directory $src_dir: $!");

    while ($_ = readdir(OLDRULES)) {
        next if (/^\.\.?$/);
        if (/$config{update_files}/) {
	    my $src_file = untaint_path("$src_dir/$_");
            copy("$src_file", "$backup_tmp_dir/")
              or warn("WARNING: could not copy $src_file to $backup_tmp_dir/: $!");
	}
    }

    closedir(OLDRULES);

  # Also backup the -U <file> (as "variable-file.conf") if specified.
    if ($config{update_vars}) {
        copy("$config{varfile}", "$backup_tmp_dir/variable-file.conf")
          or warn("WARNING: could not copy $config{varfile} to $backup_tmp_dir: $!")
    }

    my $old_dir = untaint_path(File::Spec->rel2abs(File::Spec->curdir()));

  # Change directory to $tmpdir (so we'll be right below the directory where
  # we have our rules to be backed up).
    chdir("$tmpdir") or clean_exit("could not change directory to $tmpdir: $!");

    if ($config{use_external_bins}) {
        clean_exit("tar command returned error when archiving backup files.\n")
          if (system("tar","cf","$backup_tarball","rules-backup-$date"));

        clean_exit("gzip command returned error when compressing backup file.\n")
          if (system("gzip","$backup_tarball"));

        $backup_tarball .= ".gz";

    } else {
        my $tar = Archive::Tar->new;
        opendir(RULES, "rules-backup-$date")
          or clean_exit("unable to open directory \"rules-backup-$date\": $!");

        while ($_ = readdir(RULES)) {
            next if (/^\.\.?$/);
            $tar->add_files("rules-backup-$date/$_");
        }

        closedir(RULES);

        $backup_tarball .= ".gz";

        $tar->write("$backup_tarball", 1)
          or clean_exit("could not create backup archive: ".
                        $tar->error());
    }

  # Change back to old directory (so it will work with -b <directory> as either
  # an absolute or a relative path.
    chdir("$old_dir")
      or clean_exit("could not change directory back to $old_dir: $!");

    copy("$tmpdir/$backup_tarball", "$dest_file")
      or clean_exit("unable to copy $tmpdir/$backup_tarball to $dest_file/: $!\n");

    print STDERR " saved as $dest_file.\n"
      unless ($config{quiet});
}



# Print all changes.
sub print_changes($ $)
{
    my $ch_ref = shift;
    my $rh_ref = shift;

    print "\n[***] Results from Oinkmaster started " .
          scalar(localtime) . " [***]\n";

  # Print new variables.
    if ($config{update_vars}) {
       if ($#{$$ch_ref{new_vars}} > -1) {
            print "\n[*] New variables: [*]\n";
            foreach my $var (@{$$ch_ref{new_vars}}) {
                print "    $var";
            }
        } else {
            print "\n[*] New variables: [*]\n    None.\n"
              unless ($config{super_quiet});
        }
    }


  # Print rules modifications.
    print "\n[*] Rules modifications: [*]\n    None.\n"
      if (!keys(%{$$ch_ref{rules}}) && !$config{super_quiet});

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
      if (!keys(%{$$ch_ref{other}}) && !$config{super_quiet});

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
        print "\n[+] Added files: [+]\n\n";
        foreach my $added_file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{added_files}}))) {
            print "    -> $added_file\n";
        }
    } else {
        print "\n[*] Added files: [*]\n    None.\n"
          unless ($config{super_quiet});
    }



  # Print list of possibly removed files if requested.
    if ($config{check_removed}) {
        if (keys(%{$$ch_ref{removed_files}})) {
            print "\n[-] Files possibly removed from the archive ".
                  "(consider removing them from your snort.conf): [-]\n\n";
            foreach my $removed_file (sort({uc($a) cmp uc($b)} keys(%{$$ch_ref{removed_files}}))) {
                print "    -> $removed_file\n";
	    }
        } else {
             print "\n[*] Files possibly removed from the archive: [*]\n    None.\n"
               unless ($config{super_quiet});
        }
    }

    print "\n";
}



# Helper for print_changes().
sub print_changetype($ $ $ $)
{
    my $type   = shift;   # $PRINT_OLD|$PRINT_NEW|$PRINT_BOTH
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
sub get_changes($ $ $)
{
    my $rh_ref        = shift;
    my $new_files_ref = shift;
    my $rules_dir     = shift;
    my %changes;

    print STDERR "Comparing new files to the old ones... "
      unless ($config{quiet});

  # We have the list of added files (without full path) in $rh_ref{added_files}
  # but we'd rather want to have it in $changes{added_files} now.
    $changes{added_files} = $$rh_ref{added_files};

  # New files are also regarded as modified since we want to update
  # (i.e. add) those as well. Here we want them with full path.
    foreach my $file (keys(%{$changes{added_files}})) {
        $changes{modified_files}{"$tmpdir/$rules_dir/$file"}++;
    }

  # Add list of possibly removed files if requested.
    if ($config{check_removed}) {
        opendir(OLDRULES, "$config{output_dir}")
          or clean_exit("could not open directory $config{output_dir}: $!");

        while ($_ = readdir(OLDRULES)) {
            next if (/^\.\.?$/);
            $changes{removed_files}{"$_"}++
              if (/$config{update_files}/ && 
                !exists($config{file_ignore_list}{$_}) &&
                !-e "$tmpdir/$rules_dir/$_");
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

      # Check for added non-rule lines.
        get_first_only(\my @added,
                       \@{$$rh_ref{new}{other}{$file}},
                       \@{$$rh_ref{old}{other}{$file}});

        if (scalar(@added)) {
            @{$changes{other}{added}{$file}} = @added;
            $changes{modified_files}{$file_w_path}++;
        }

      # Check for removed non-rule lines.
        get_first_only(\my @removed,
                       \@{$$rh_ref{old}{other}{$file}},
                       \@{$$rh_ref{new}{other}{$file}});

        if (scalar(@removed)) {
            @{$changes{other}{removed}{$file}} = @removed;
            $changes{modified_files}{$file_w_path}++;
        }

    } # foreach new file

    print STDERR "done.\n" unless ($config{quiet});

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
        next if (/^\.\.?$/);
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
      if (!$config{quiet} || $config{interactive});

    foreach my $file_w_path (@modified_files) {
        copy("$file_w_path", "$dst_dir")
          or clean_exit("could not copy $file_w_path to $dst_dir: $!");
    }

    print STDERR "done.\n"
      if (!$config{quiet} || $config{interactive});
}



# Return true if file is in PATH and is executable.
sub is_in_path($)
{
    my $file = shift;

    foreach my $dir (File::Spec->path()) {
        if ((-f "$dir/$file" && -x "$dir/$file")
          || (-f "$dir/$file.exe" && -x "$dir/$file.exe")) {
            print STDERR "Found $file binary in $dir\n"
              if ($config{verbose});
            return (1);
        }
    }

    return (0);
}



# get_next_entry() will parse the array referenced in the first arg
# and return the next entry. The array should contain a rules file,
# and the returned entry will be removed from the array.
# An entry is one of:
# - single-line rule (put in 2nd ref)
# - multi-line rule (put in 3rd ref)
# - non-rule line (put in 4th ref)
# If the entry is a multi-line rule, its single-line version is also
# returned (put in the 2nd ref).
# If it's a rule, the msg string will be put in 4th ref and sid in 5th.
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

      # Invalid multi-line rule.
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

  # Check if it's a regular single-line rule.
    } elsif (parse_singleline_rule($line, $msg_ref, $sid_ref)) {
        $$single_ref = $line;
        $$single_ref =~ s/^\s*//;
        $$single_ref =~ s/^#+\s*/#/;
        $$single_ref =~ s/\s*\n$/\n/;

        return (1);   # return single

  # Non-rule line.
    } else {

      # Do extra check and warn if it *might* be a rule anyway,
      # but that we just couldn't parse for some reason.
        warn("\nWARNING: line may be a rule but it could not be parsed ".
             "(missing sid?): $line\n")
          if ($config{verbose} && $line =~ /^\s*alert .+msg\s*:\s*".+"\s*;/);

        $$nonrule_ref = $line;
        $$nonrule_ref =~ s/\s*\n$/\n/;

        return (1);   # return non-rule
    }
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
      unless ($config{quiet});


  # Read in variable names from old file.
    open(LOCAL_CONF, "<", "$local_conf")
      or clean_exit("could not open $local_conf for reading: $!");

    my @local_conf = <LOCAL_CONF>;

    foreach $_ (@local_conf) {
        $old_vars{lc($1)}++ if (/$VAR_REGEXP/i);
    }

    close(LOCAL_CONF);


  # Read in variables from new file.
    open(DIST_CONF, "<", "$dist_conf")
      or clean_exit("could not open $dist_conf for reading: $!");

    while ($_ = <DIST_CONF>) {
        push(@new_vars, $_)
          if (/$VAR_REGEXP/i && !exists($old_vars{lc($1)}));
    }

    close(DIST_CONF);

    @{$$ch_ref{new_vars}} = @new_vars;

    print STDERR "done.\n"
      unless ($config{quiet});
}



# Add new variables to local snort.conf.
sub add_new_vars($ $)
{
    my $ch_ref      = shift;
    my $varfile     = shift;
    my $tmp_varfile = "$tmpdir/tmp_varfile.conf";
    my $new_content;

    return unless ($#{$changes{new_vars}} > -1);

    open(OLD_LOCAL_CONF, "<", "$varfile")
      or clean_exit("could not open $varfile for reading: $!");
    my @old_content = <OLD_LOCAL_CONF>;
    close(OLD_LOCAL_CONF);

    open(NEW_LOCAL_CONF, ">", "$tmp_varfile")
      or clean_exit("could not open $tmp_varfile for writing: $!");

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

    clean_exit("could not copy $tmp_varfile to $varfile: $!")
      unless (copy("$tmp_varfile", "$varfile"));
}



# Convert msdos style path to cygwin style, e.g.
# c:\foo => /cygdrive/c/foo
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
        return (0) unless ($sid =~ /^\d+$/ || $sid eq "*");

      # Make sure the regexp is valid.
        my $repl_qq = "qq/$repl/";
        my $dummy   = "foo";

        eval {
            $dummy =~ s/$subst/$repl_qq/ee;
        };

        if ($@) {
            warn("Invalid regexp: $@");
            return (0);
        }

        push(@{$$mod_list_ref{$sid}}, [$subst, $repl_qq]);
    }

    return (1);
}



# Untaint a path. Die if it contains illegal chars.
sub untaint_path($)
{
    my $path      = shift;
    my $orig_path = $path;

    (($path) = $path =~ /^([$OK_PATH_CHARS]+)$/)
      or clean_exit("illegal character in path/filename ".
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

    return ($answer =~ /^y/i);
}



# Check a string and return 1 if it's a valid single-line snort rule.
# Msg string is put in second arg, sid in third (those are the only
# required keywords, besides the leading rule actions).
sub parse_singleline_rule($ $ $)
{
    my $line    = shift;
    my $msg_ref = shift;
    my $sid_ref = shift;

    undef($$msg_ref);
    undef($$sid_ref);

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



# Catch SIGINT.
sub catch_sigint()
{
    $SIG{INT} = 'IGNORE';
    print STDERR "\nInterrupted, cleaning up.\n";
    sleep(1);
    clean_exit("interrupted by signal");
}



# Remove temporary directory and exit.
# If a non-empty string is given as argument, it will be regarded
# as an error message and we will use die() with the message instead
# of just exit(0).
sub clean_exit($)
{
    my $err_msg = shift;

    $SIG{INT} = 'DEFAULT';

    if (defined($tmpdir) && -d "$tmpdir") {
        chdir(File::Spec->rootdir());
        rmtree("$tmpdir", 0, 1);
        undef($tmpdir);
    }

    if (!defined($err_msg) || $err_msg eq "") {
        exit(0);
    } else {
	chomp($err_msg);
        die("\n$0: Error: $err_msg\n\nOink, oink. Exiting...\n");
    }
}



#### EOF ####
