#!/usr/bin/perl -w

# $Id$ #

use strict;
use Getopt::Std;
use File::Copy;
use POSIX qw(strftime);
use Cwd;

sub show_usage;
sub parse_cmdline;
sub read_config;
sub sanity_check;
sub download_rules;
sub unpack_rules_archive;
sub disable_rules;
sub setup_rule_hashes;
sub find_line;
sub do_backup;
sub clean_exit;

my $version           = 'Oinkmaster v0.7 by Andreas Östling <andreaso@it.su.se>';
my $config_file       = "./oinkmaster.conf";
my $tmpdir            = "/tmp/oinkmaster.$$";
my $outfile           = "snortrules.tar.gz";
my $verbose           = 0;
my $careful           = 0;
my $quiet             = 0;
my $rules_changed     = 0;
my $other_changed     = 0;
my $something_changed = 0;
my $check_removed     = 0;
my $preserve_comments = 1;

# Regexp to match a snort rule line.
# The msg string will go into $1 and the sid will go into $2.
my $snort_rule_regexp = '^\s*#*\s*(?:alert|log|pass) .+msg\s*:\s*"(.+?)"\s*;.+sid\s*:\s*(\d+)\s*;';

use vars qw
   (
      $opt_b $opt_c $opt_C $opt_e $opt_h $opt_o $opt_q $opt_r $opt_u $opt_v
   );

my (
      $output_dir, $sid, $old_rule, $new_rule, $file, $backup_dir,
      $start_date, $added_files, $removed_files, $url, $skip_diff_files
   );

my (
      %sid_disable_list, %file_ignore_list, %config, %changes, %added_files,
      %new_files, %new_rules, %new_other, %old_rules, %old_other, %printed,
      %modified_files, %sid_modify_list
   );



#### MAIN ####

select(STDERR); $| = 1;         # No buffering.
select(STDOUT); $| = 1;

$start_date = scalar(localtime);

# Parse command line arguments. Will exit if something is wrong.
parse_cmdline;

# Why would anyone want to run as root?
die("Don't run as root!\nExiting") if (!$>);

# Read in $config_file. Will exit if something is wrong.
read_config;

# Do some basic sanity checking and exit if something fails.
# A new PATH will be set.
sanity_check;

# Create empty temporary directory.
mkdir("$tmpdir", 0700)
  or die("Could not create temporary directory $tmpdir: $!\nExiting");

# Download the rules archive.
# This will leave us with the file $tmpdir/$outfile (/tmp/oinkmaster.$$/snortrules.tar.gz).
download_rules;

# Verify and unpack archive. This will leave us with a directory
# called "rules/" in the temporary directory, containing the new rules.
unpack_rules_archive;

# Add filenames to update from the downloaded archive to the list of new
# files, unless filename exists in %file_ignore_list.
opendir(NEWRULES, "$tmpdir/rules")
  or clean_exit("Could not open directory $tmpdir/rules: $!");
while ($_ = readdir(NEWRULES)) {
    $new_files{$_}++
      if (/$config{update_files}/ && !exists($file_ignore_list{$_}));
}
closedir(NEWRULES);

# Make sure there is at least one file to be updated.
clean_exit("Found no files in archive matching \"$config{update_files}\".")
  if (keys(%new_files) < 1);

# Disable (#comment out) all rules listed in %sid_disable_list.
# All files will still be left in the temporary directory.
disable_rules;

# Setup %new_rules, %old_rules, %new_other and %old_other.
# As a bonus, we get list of added files in %added_files.
setup_rule_hashes;

# Time to compare the new rules to the old ones.
# For each rule in the new file, check if the rule also exists
# in the old file.  If it does then check if it has been modified,
# but if it doesn't, it must have been added.

print STDERR "Comparing new files to the old ones... "
  unless ($quiet);

FILELOOP:foreach $file (keys(%new_files)) {                  # for each new file
    next FILELOOP if (exists($added_files{$file}));          # skip diff if it's an added file

  # Skip diff if file maches skip_diff regexp. Not documented and perhaps not even working?
    if (exists($config{skip_diff}) && $file =~ /$config{skip_diff}/) {
	$skip_diff_files .= "\n    -> $file";
	$skip_diff_files .= " (local copy updated)" unless ($careful);
	$skip_diff_files .= "\n";
	$modified_files{$file}++;
        next FILELOOP;
    }

  # This one will tell us if the filename info has been printed or not.
    undef(%printed);

    foreach $sid (keys(%{$new_rules{$file}})) {         # for each sid in the new file
        $new_rule = $new_rules{$file}{$sid};            # save the rule in $new_rule for easier access
            if (exists($old_rules{$file}{$sid})) {      # does this sid also exist in the old rules file?
                $old_rule = $old_rules{$file}{$sid};    # yes, put old rule in $old_rule

		unless ($new_rule eq $old_rule) {                             # are they identical?
		    $rules_changed = 1;
                    if ("#$old_rule" eq $new_rule) {                          # rule disabled?
			fix_fileinfo("removed_dis", $file);
                        $changes{removed_dis}       .= "       $new_rule";
                    } elsif ($old_rule eq "#$new_rule") {                     # rule enabled?
			fix_fileinfo("added_ena", $file);
                        $changes{added_ena}         .= "       $new_rule";
                    } elsif ($old_rule =~ /^\s*#/ && $new_rule !~ /^\s*#/) {  # rule enabled and modified?
			fix_fileinfo("added_ena_mod", $file);
                        $changes{added_ena_mod}     .= "       Old: $old_rule       New: $new_rule";
                    } elsif ($old_rule !~ /^\s*#/ && $new_rule =~ /^\s*#/) {  # rule disabled and modified?
			fix_fileinfo("removed_dis_mod", $file);
                        $changes{removed_dis_mod}   .= "       Old: $old_rule       New: $new_rule";
                    } elsif ($old_rule =~ /^\s*#/ && $new_rule =~ /^\s*#/) {  # inactive rule modified?
			fix_fileinfo("modified_inactive", $file);
                        $changes{modified_inactive} .= "       Old: $old_rule       New: $new_rule";
                    } else {                                                  # active rule modified?
			fix_fileinfo("modified_active", $file);
                        $changes{modified_active}   .= "       Old: $old_rule       New: $new_rule";
	  	    }
		}

	    } else {    # sid not found in old file so it must have been added
	        $rules_changed = 1;
 		fix_fileinfo("added_new", $file);
	        $changes{added_new} .= "       $new_rule";
	    }
    } # foreach sid

  # Check for removed rules, i.e. sids that exist in the old file but not in the new one.
    foreach $sid (keys(%{$old_rules{$file}})) {
        unless (exists($new_rules{$file}{$sid})) {
            $rules_changed = 1;
            $old_rule = $old_rules{$file}{$sid};
	    fix_fileinfo("removed_del", $file);
            $changes{removed_del} .= "       $old_rule";
        }
    }

  # First check for added non-rule lines.
    foreach $_ (@{$new_other{$file}}) {
        unless (find_line($_, @{$old_other{$file}})) {
            fix_fileinfo("other_added", $file);
            $changes{other_added} .= "       $_";
            $other_changed = 1;
        }
    }

  # Check for removed non-rule lines.
    foreach $_ (@{$old_other{$file}}) {
        unless (find_line($_, @{$new_other{$file}})) {
            fix_fileinfo("other_removed", $file);
            $changes{other_removed} .= "       $_";
            $other_changed = 1;
        }
    }

} # foreach new file

# Add list of possibly removed files into $removed_files if -r is specified.
if ($check_removed) {
    opendir(OLDRULES, "$output_dir")
      or clean_exit("Could not open directory $output_dir: $!");

    while ($_ = readdir(OLDRULES)) {
        $removed_files .= "    -> $_\n"
          if (/$config{update_files}/ && !exists($file_ignore_list{$_})
            && !exists($new_files{$_}));
    }
    closedir(OLDRULES);
}

print STDERR "done.\n" unless ($quiet);

# Update files listed in %modified_files (move the new files from the temporary
# directory into our -o <dir>, unless we're running in careful mode.
# Also create backup first if running with -b.
if ($rules_changed || $other_changed || defined($skip_diff_files)) {
    if ($careful) {
        print STDERR "No need to backup old files (running in careful mode), skipping.\n"
          if (defined($backup_dir) && (!$quiet));
    }  else {
        do_backup if (defined($backup_dir));               # backup old rules if -b

      # Move each modified file from the temporary directory to the output directory.
        foreach $_ (keys(%modified_files)) {
            move("$tmpdir/rules/$_", "$output_dir/$_")
              or clean_exit("Could not move $tmpdir/rules/$_ to $output_dir/$_: $!")
        }
    }
} else {
    print STDERR "No files modified - no need to backup old files, skipping.\n"
      if (defined($backup_dir) && !$quiet);
}

# Move files listed in %added_files into our output directory unless careful mode.
unless ($careful) {
    foreach $_ (keys(%added_files)) {
        move("$tmpdir/rules/$_", "$output_dir/$_")
          or clean_exit("Could not move $tmpdir/rules/$_ to $output_dir/$_: $!")
    }
}

# Time to print the results.

$something_changed = 1
  if ($rules_changed || $other_changed
      || keys(%added_files) > 0 || defined($removed_files));

if ($something_changed || !$quiet) {
    print "\nNote: Oinkmaster is running in careful mode - not updating/adding anything.\n"
      if ($careful && $something_changed);
    print "\n[***] Results from Oinkmaster started $start_date [***]\n";

  # Print rule changes.
    print "\n[*] Rules added/removed/modified: [*]\n";

    if ($rules_changed) {
        print "\n  [+++]           Added:           [+++]\n $changes{added_new}"
          if (exists($changes{added_new}));
        print "\n  [+++]          Enabled:          [+++]\n $changes{added_ena}"
          if (exists($changes{added_ena}));
        print "\n  [+++]    Enabled and modified:   [+++]\n $changes{added_ena_mod}"
          if (exists($changes{added_ena_mod}));
        print "\n  [---]          Removed:          [---]\n $changes{removed_del}"
          if (exists($changes{removed_del}));
        print "\n  [---]          Disabled:         [---]\n $changes{removed_dis}"
          if (exists($changes{removed_dis}));
        print "\n  [---]    Disabled and modified:  [---]\n $changes{removed_dis_mod}"
          if (exists($changes{removed_dis_mod}));
        print "\n  [///]       Modified active:     [///]\n $changes{modified_active}"
          if (exists($changes{modified_active}));
        print "\n  [///]      Modified inactive:    [///]\n $changes{modified_inactive}"
          if (exists($changes{modified_inactive}));
        print "\n";
    } else {
        print "    None.\n";
    }

  # Print non-rule changes.
    print "\n[*] Non-rule lines added/removed: [*]\n";
    if ($other_changed) {
        print "\n  [+++]       Added lines:       [+++]\n $changes{other_added}"
          if (exists($changes{other_added}));
        print "\n  [---]      Removed lines:      [---]\n $changes{other_removed}"
          if (exists($changes{other_removed}));
        print "\n";
    } else {
        print "    None.\n";
    }

  # Print list of added files.
    if (keys(%added_files) > 0) {
        print "\n[*] Added files (consider updating your snort.conf to include them): [*]\n" .
              "$added_files";
    } else {
         print "\n[*] Added files: [*]\n" .
               "    None.\n";
    }

  # Print list of files possibly removed from the downloaded archive if -r is specified.
    if ($check_removed) {
        if (defined($removed_files)) {
            print "\n[*] Possibly removed files (consider removing them from your".
                  " snort.conf): [*]\n$removed_files";
        } else {
            print "\n[*] Files possibly removed from archive: [*]\n    None.\n";
        }
    }

  # Print list of possibly modified files that matched config{skip_diff}
    if (defined($skip_diff_files)) {
        print "\n[*] Possibly modified files where diff excluded by request: [*]\n".
              "$skip_diff_files";
    }

    print "\n";
}

clean_exit;

# END OF MAIN #



sub show_usage
{
    print STDERR "$version\n\n".
                 "Usage: $0 -o <dir> [options]\n\n".
		 "<dir> is where to put the new files.\n".
	         "This should be the directory where you store your snort.org rules.\n".
                 "Note that your current files will be overwritten by the new ones\n".
                 "if they had been modified.\n".
                 "\nOptions:\n".
		 "-C <cfg>   Use this config file instead of the default ($config_file)\n".
		 "-b <dir>   Backup old rules into <dir> if anything had changed\n".
		 "-u <url>   Download from this URL (http://, ftp:// or file:// ...tar.gz)\n".
                 "           instead of the URL specified in $config_file\n".
		 "-c         Careful mode. Don't update anything, just check for changes\n".
		 "-e         Re-enable all rules that are disabled by default in the rules distribution.\n".
                 "           (They are disabled for a reason so use with care)\n".
                 "-r         Check for rules files that exist in the output directory\n".
                 "           but not in the downloaded rules archive (i.e. files that may\n".
                 "           have been removed from the archive).\n".
                 "-q         Quiet mode. No output unless changes were found\n".
		 "-v         Verbose mode\n".
                 "-h         Show usage help\n\n";
    exit(0);
}



sub parse_cmdline
{
    my $cmdline_ok = getopts('b:cC:eho:pqru:v');

    $backup_dir    = $opt_b if (defined($opt_b));
    $config_file   = $opt_C if (defined($opt_C));
    $url           = $opt_u if (defined($opt_u));
    $careful           = 1  if (defined($opt_c));
    $preserve_comments = 0  if (defined($opt_e));
    $quiet             = 1  if (defined($opt_q));
    $check_removed     = 1  if (defined($opt_r));
    $verbose           = 1  if (defined($opt_v));
    show_usage              if (defined($opt_h));
    show_usage unless ($cmdline_ok);

    if (defined($opt_o)) {       # -o <dir>, the only required option.
        $output_dir = $opt_o;
    } else {
        show_usage;
    }

  # Remove possible trailing slash (just for cosmetic reasons).
    $output_dir =~ s/\/+$//;
    $backup_dir =~ s/\/+$// if (defined($backup_dir));
}



sub read_config
{
    my ($args, $linenum);

    $linenum = 0;

    open(CONF, "<$config_file") or die("Could not open $config_file: $!\nExiting");

    while (<CONF>) {
        $linenum++;

      # Remove comments unless it's a modifysid line.
        s/\s*\#.*// unless (/^\s*modifysid/i);

      # Remove leading/traling whitespaces.
	s/^\s*//;
	s/\s*$//;

        next unless (/\S/);   # skip blank lines

        if (/^disablesids*\s+(\d.*)/i) {                           # disablesid
	    $args = $1;
	    foreach $_ (split(/\s*,\s*/, $args)) {
  	        if (/^\d+$/) {
                    $sid_disable_list{$_}++;
	        } else {
                    print STDERR ("WARNING: line $linenum in $config_file is invalid, ignoring\n")
	        }
	    }
        } elsif (/^modifysid\s+(\d+)\s+(.*)/i) {                   # modifysid
            push(@{$sid_modify_list{$1}}, $2);
        } elsif (/^skipfiles*\s+(.*)/i) {                          # skipfile
	    $args = $1;
	    foreach $_ (split(/\s*,\s*/, $args)) {
	        if (/^\S.*\S$/) {
                    $verbose && print STDERR "Adding file to ignore list: $_.\n";
                    $file_ignore_list{$_}++;
		} else {
                    print STDERR ("WARNING: line $linenum in $config_file is invalid, ignoring\n")
		}
	    }
	} elsif (/^url\s*=\s*(.*)/i) {                             # URL to use
	    $url = $1 unless (defined($url));                      # may already be defined by -u <url>
	} elsif (/^path\s*=\s*(.*)/i) {                            # $PATH to be used
	    $config{path} = $1;
	} elsif (/^update_files\s*=\s*(.*)/i) {                    # regexp of files to be updated
	    $config{update_files} = $1;
	} elsif (/^skip_diff\s*=\s*(.*)/i) {                       # regexp of files to skip comparison for
	    $config{skip_diff} = $1;
        } else {                                                   # invalid line
            print STDERR ("WARNING: line $linenum in $config_file is invalid, ignoring\n")
        }

    }
    close(CONF)
}



# Make a few basic tests to make sure things look ok.
# Will also set a new (temporary) PATH as defined in the config file.
sub sanity_check
{
   my @req_config   = qw (path update_files);
   my @req_binaries = qw (which gzip rm tar wget);

  # Can't use both -q and -v.
    die("Both quiet mode and verbose mode at the same time doesn't make sense.\nExiting")
      if ($quiet && $verbose);

  # Make sure all required variables is defined in the config file.
    foreach $_ (@req_config) {
        die("$_ not defined in $config_file\nExiting")
          unless (exists($config{$_}));
    }

  # We now know a path was defined in the config, so set it.
    $ENV{"PATH"} = $config{path};
    $ENV{'IFS'}  = '';

  # Make sure all required binaries can be found.
    foreach $_ (@req_binaries) {
        die("\"$_\" binary not found\nExiting")
          if (system("which \"$_\" >/dev/null 2>&1"));
    }

  # Make sure $url is defined (either by -u <url> or url=... in the conf).
    die("Incorrect URL or URL not specified in neither $config_file nor command line.\nExiting")
      unless (defined($url) && $url =~ /^(?:http|ftp|file):\/\/\S+.*\.tar\.gz$/);

  # Make sure the output directory exists and is writable.
    die("The output directory \"$output_dir\" doesn't exist or isn't writable by you.\nExiting")
      if (! -d "$output_dir" || ! -w "$output_dir");

  # Make sure the backup directory exists and is writable, if running with -b.
    die("The backup directory \"$backup_dir\" doesn't exist or isn't writable by you.\nExiting")
      if (defined($backup_dir) && (! -d "$backup_dir" || ! -w "$backup_dir"));
}



# Pull down the rules archive.
sub download_rules
{
    if ($url =~ /^(?:http|ftp)/) {     # Use wget if URL starts with http:// or ftp://
        print STDERR "Downloading rules archive from $url...\n" unless ($quiet);
        if ($quiet) {
            clean_exit("Unable to download rules.\n".
                       "Consider running in non-quiet mode if the problem persists.")
              if (system("wget","-q","-nv","-O","$tmpdir/$outfile","$url"));   # quiet mode
        } elsif ($verbose) {
            clean_exit("Unable to download rules.")
              if (system("wget","-v","-O","$tmpdir/$outfile","$url"));         # verbose mode
        } else {
            clean_exit("Unable to download rules.")
              if (system("wget","-nv","-O","$tmpdir/$outfile","$url"));        # normal mode
        }
    } else {                           # Grab file from local filesystem.
        $url =~ s/^file:\/\///;        # Remove file://, the rest is the actual filename.
	clean_exit("The file $url does not exist.\n")       unless (-e "$url");
        print STDERR "Copying rules archive from $url...\n" unless ($quiet);
        copy("$url", "$tmpdir/$outfile") or clean_exit("Unable to copy $url to $tmpdir/$outfile: $!");
    }
}



# Make a few checks on $outfile (the downloaded rules archive)
# and then uncompress/untar it if everything looked ok.
sub unpack_rules_archive
{
    my ($old_dir, $ok_chars, $tmpoutfile);

    $ok_chars = 'a-zA-Z0-9_\.\-/\n :';     # allowed characters for filenames in the tar archive
    $tmpoutfile = $outfile;                # so we don't modify the global $outfile variable

    $old_dir = getcwd or clean_exit("Could not get current directory: $!");
    chdir("$tmpdir")  or clean_exit("Could not change directory to $tmpdir: $!");

    unless (-s "$tmpoutfile") {
        clean_exit("Failed to get rules archive: ".
                   "$tmpdir/$tmpoutfile doesn't exist or hasn't non-zero size.");
    }

  # Run integrity check (gzip -t) on the gzip file.
    clean_exit("Integrity check on gzip file failed (file transfer failed or ".
               "file in URL not in gzip format?)")
      if (system("gzip","-t","$tmpoutfile"));

  # Decompress it.
    system("gzip","-d","$tmpoutfile") and clean_exit("Unable to uncompress $outfile.");

  # Suffix has now changed from .tar.gz to .tar.
    $tmpoutfile =~ s/\.gz$//;

  # Look for uncool stuff in the archive.
    if (open(TAR,"-|")) {
        @_ = <TAR>;                       # read output of the "tar vtf" command into @_
    } else {
        exec("tar","vtf","$tmpoutfile")
          or die("Unable to execute untar/unpack command: $!\nExiting");
    }

    foreach $_ (@_) {
      # We don't want to have any weird characters in the tar file.
       clean_exit("Forbidden characters in tar archive. Offending file/line:\n$_")
          if (/[^$ok_chars]/);
      # We don't want to unpack any "../../" junk.
        clean_exit("File in tar archive contains \"..\" in filename.\nOffending file/line:\n$_")
          if (/\.\./);
      # Links in the tar archive are not allowed
      # (should be detected because of illegal chars above though).
        clean_exit("File in tar archive contains link: refuse to unpack file.\nOffending file/line:\n$_")
          if (/->/ || /=>/ || /==/);
    }

  # Looks good. Now we can finally untar it.
    print STDERR "Archive successfully downloaded, unpacking... "
      unless ($quiet);
    clean_exit("Failed to untar $tmpoutfile.")
      if system("tar","xf","$tmpoutfile");
    clean_exit("No \"rules/\" directory found in tar file.")
      unless (-d "rules");

    chdir("$old_dir") or clean_exit("Could not change directory back to $tmpdir: $!");

    print STDERR "done.\n" unless ($quiet);
}



# Open all rules files in temporary directory and disable (#comment out) all rules
# listed in %sid_disable_list. All files will still be left in the temporary directory.
sub disable_rules
{
    my ($num_disabled, $msg, $sid, $line, $file);

    $num_disabled = 0;

    if (!$preserve_comments && !$quiet) {
        print STDERR "Warning: all rules that are disabled by default will be re-enabled\n";
    }

    print STDERR "Disabling rules according to $config_file... " unless ($quiet);
    print STDERR "\n" if ($verbose);

    foreach $file (keys(%new_files)) {
        open(INFILE, "<$tmpdir/rules/$file") or clean_exit("Could not open $tmpdir/rules/$file: $!");
	@_ = <INFILE>;
        close(INFILE);

      # Write back to the same file.
	open(OUTFILE, ">$tmpdir/rules/$file") or clean_exit("Could not open $tmpdir/rules/$file: $!");
	RULELOOP:foreach $line (@_) {
            unless ($line =~ /$snort_rule_regexp/) {    # only care about snort rules
	        print OUTFILE $line;
		next RULELOOP;
	    }
	    ($msg, $sid) = ($1, $2);

          # Remove leading/trailing whitespaces and whitespaces next to the leading #.
	    $line =~ s/^\s*//;
	    $line =~ s/\s*\n$/\n/;
	    $line =~ s/^#+\s*/#/;

          # Some rules may be commented out by default. Enable them if -e is specified.
	    if ($line =~ /^#/) {
		if ($preserve_comments) {
		    print STDERR "Preserving disabled rule (sid $sid): $msg\n"
		      if ($verbose);
		} else {
		    print STDERR "Enabling disabled rule (sid $sid): $msg\n"
		      if ($verbose);
		    $line =~ s/^#*//;
		}
	    }

          # Modify rule, if requested.
            foreach $_ (@{$sid_modify_list{$sid}}) {
	        print STDERR "Modifying sid $sid with expression: $_\n  Before:$line"
		  if ($verbose);
		eval "\$line =~ $_";
		print STDERR "WARNING: error in expression \"$_\": $@\n"
		  if ($@);
		print STDERR "  After:$line\n"
                  if ($verbose);
	    }

          # Disable rule, if requested.
            if (exists($sid_disable_list{$sid})) {
                print STDERR "Disabling sid $sid: $msg\n" if ($verbose);
                $line = "#$line" unless ($line =~ /^#/);
                $num_disabled++;
	    }

	    chomp($line);
	    $line .= "\n";
            print OUTFILE $line;       # Write line back to the rules file.
        }
        close(OUTFILE);
    }
    print STDERR "$num_disabled rules disabled.\n" unless ($quiet)
}


# Setup %new_rules, %old_rules, %new_other and %old_other.
# Format will be %new_rules{filename}{sid} = rule
# and:
# %new_other{filename} = @array_with_non-rule_lines
# As a bonus, we get list of added files in %added_files.
sub setup_rule_hashes
{
    my ($file, $sid);

    foreach $file (keys(%new_files)) {
        open(NEWFILE, "<$tmpdir/rules/$file") or clean_exit("Could not open $tmpdir/rules/$file: $!");
	while (<NEWFILE>) {
	    if (/$snort_rule_regexp/) {
	        $sid = $2;
		print STDERR "WARNING: duplicate SID in downloaded rules archive: SID $sid\n"
		  if (exists($new_rules{"$file"}{"$sid"}) && !$quiet);
	        $new_rules{"$file"}{"$sid"} = $_;
	    } else {
	        push(@{$new_other{"$file"}}, $_);  # use array so the lines stay sorted
	    }
	}
	close(NEWFILE);

     # Also read in old file if it exists.
        if (-f "$output_dir/$file") {
            open(OLDFILE, "<$output_dir/$file") or clean_exit("Could not open $output_dir/$file: $!");
	    while (<OLDFILE>) {
                if (/$snort_rule_regexp/) {
		    $sid = $2;
		    s/^\s*//;     # remove leading whitespaces
		    s/\s*\n$/\n/; # remove trailing whitespaces
		    s/^#+\s*/#/;  # make sure comment syntax is how we like it
		    print STDERR "WARNING: duplicate SID in your local rules: SID $sid\n"
		      if (exists($old_rules{"$file"}{"$sid"}) && !$quiet);
                    $old_rules{$file}{$sid} = $_;
                } else {
                    push(@{$old_other{$file}}, $_);
                }
            }
            close(OLDFILE);
        } else {
	    $added_files .= "    -> $file\n" unless (exists($added_files{"$file"}));
	    $added_files{"$file"}++;
        }
    }

}



# Try to find a given string in a given array. Return 1 if found, or 0 if not.
# Some things will always be considered as found (lines that we don't care if
# they were added/removed). It's extremely slow, but who cares.
sub find_line
{
    my $line = shift;   # line to look for
    my @arr  = @_;      # array to look in

    return 1 unless ($line =~ /\S/);                         # skip blank lines
    return 1 if     ($line =~ /^\s*#+\s*\$I\S:.+Exp\s*\$/);  # also skip CVS Id tag

    foreach $_ (@arr) {
        return 1 if ($_ eq $line);                           # string found
    }

    return 0;                                                # string not found
}



# Add filename info to given "changelog" array, unless already done.
# Also update list of modified files.
sub fix_fileinfo
{
    my $type     = shift;   # type of change (added_new/removed_del/modified_active etc)
    my $filename = shift;

    unless (exists($printed{$type})) {                         # filename info already added?
        $changes{$type} .= "\n    -> File \"$filename\":\n";   # nope, add it.
        $printed{$type}++;                                     # so we know it has now been added
    }

  # Add filename to list of modified files.
    $modified_files{$filename}++;
}



# Backup files in $output_dir matching $config{update_files} into $backup_dir.
sub do_backup
{
    my ($date, $tmpbackupdir, $old_dir);

    $date = strftime("%Y%m%d-%H%M", localtime);
    $tmpbackupdir = "$tmpdir/rules-backup-$date";

    print STDERR "Creating backup of old rules..." unless ($quiet);

    mkdir("$tmpbackupdir", 0700)
      or clean_exit("Could not create temporary backup directory $tmpbackupdir: $!");

    opendir(OLDRULES, "$output_dir") or clean_exit("Could not open directory $output_dir: $!");
    while ($_ = readdir(OLDRULES)) {
        copy("$output_dir/$_", "$tmpbackupdir/")
          or print STDERR "WARNING: error copying $output_dir/$_ to $tmpbackupdir: $!"
            if (/$config{update_files}/ && !exists($file_ignore_list{$_}));
    }
    closedir(OLDRULES);

  # Change directory to $tmpdir (so we'll be right below the directory where
  # we have our rules to be backed up).
    $old_dir = getcwd or clean_exit("Could not get current directory: $!");
    chdir("$tmpdir")  or clean_exit("Could not change directory to $tmpdir: $!");

  # Execute tar command. This will archive "rules-backup-$date/"
  # into the file rules-backup-$date.tar, placed in $tmpdir.
    print STDERR "WARNING: tar command did not exit with status 0 when archiving backup files.\n"
      if (system("tar","cf","rules-backup-$date.tar","rules-backup-$date"));

  # Compress it.
    print STDERR "WARNING: gzip command did not exit with status 0 when compressing backup file.\n"
      if (system("gzip","rules-backup-$date.tar"));

  # Change back to old directory (so it will work with -b <directory> as either
  # an absolute or a relative path.
    chdir("$old_dir") or clean_exit("Could not change directory back to $old_dir: $!");

  # Move the archive to the backup directory.
    move("$tmpdir/rules-backup-$date.tar.gz", "$backup_dir/")
      or print STDERR "WARNING: unable to move $tmpdir/rules-backup-$date.tar.gz to $backup_dir/: $!\n";

    print STDERR " saved as $backup_dir/rules-backup-$date.tar.gz.\n"
      unless ($quiet);

}



# Remove temporary directory and exit.
sub clean_exit
{
    system("rm","-r","-f","$tmpdir")
      and print STDERR "WARNING: unable to remove temporary directory $tmpdir.\n";

    if (defined($_[0])) {
        $_ = $_[0];
	chomp;
        die("$_\nExiting");
    } else {
        exit(0);
    }
}



#### EOF ####
