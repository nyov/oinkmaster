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
sub find_line;
sub do_backup;

my $version           = 'Oinkmaster v0.4 by Andreas Östling <andreaso@it.su.se>';
my $config_file       = "./oinkmaster.conf";
my $tmpdir            = "/tmp/oinkmaster.$$";
my $outfile           = "snortrules.tar.gz";
my $verbose           = 0;
my $careful           = 0;
my $quiet             = 0;
my $rules_changed     = 0;
my $other_changed     = 0;
my $check_removed     = 0;

# Regexp to match a Snort rule line.
# The msg string will go into $1, and the sid will go into $2.
my $snort_rule_regexp = '^\s*#*\s*(?:alert|log|pass) .+msg\s*:\s*"(.+?)"\s*;.+sid\s*:\s*(\d+)\s*;';

use vars qw
   (
      $opt_h $opt_v $opt_o $opt_q $opt_c $opt_b $opt_r $opt_u
      $opt_C
   );

my (
      $output_dir, $sid, $old_rule, $new_rule, $file, $backup_dir,
      $start_date, $added_files, $removed_files, $url
   );

my (
      %sid_disable_list, %file_ignore_list, %config, %changes, %added_files,
      %new_files, %new_rules, %new_other, %old_rules, %old_other, %printed,
      %modified_files
   );



#### MAIN ####

select(STDERR); $| = 1;         # No buffering.
select(STDOUT); $| = 1;

$start_date = scalar(localtime);

parse_cmdline;
# die("Don't run as root!\nExiting") if (!$>);
read_config;
sanity_check;

# Set new (temporary) PATH.
local $ENV{"PATH"} = $config{path};

# Create empty temporary directory.
mkdir("$tmpdir", 0700) or die("could not create temporary directory $tmpdir: $!\nExiting");

# Pull down the rules archive.
# Die if wget doesn't exit with status level 0.
if ($quiet) {
    if (system("wget","-q","-nv","-O","$tmpdir/$outfile","$url")) {
        die("Unable to download rules.\n".
            "Consider running in non-quiet mode if the problem persists.\nExiting");
    }
} else {
    print STDERR "Downloading rules archive from $url...\n";
    if (system("wget","-nv","-O","$tmpdir/$outfile","$url")) {
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

# Make sure there is at least one file to be updated.
die("Found no files in archive to be updated\nExiting")
  if (keys(%new_files) < 1);

# Disable (#comment out) all rules listed in %sid_disable_list.
# All files will still be left in the temporary directory.
disable_rules;

# Setup %new_rules, %old_rules, %new_other and %old_other.
# As a bonus, we get list of added files in %added_files.
setup_rule_hashes;

# Time to compare the new rules files to the old ones.
# For each rule in the new rule set, check if the rule also exists
# in the old rule set.  If it does then check if it has been modified, 
# but if it doesn't, it must have been added.

print STDERR "Comparing your old files to the new ones... "
  unless ($quiet);

foreach $file (keys(%new_files)) {                      # for each new file
    next if ($file =~ /$config{skip_diff}/);            # skip comparing for files listed in skip_diff
    next if (exists($added_files{$file}));              # also skip of its an added file

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
                    } elsif ($old_rule =~ /^\s*#/ && $new_rule !~ /^\s*#/) {  # rule enabled and  modified?
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

	    } else {
	        $rules_changed  = 1;
 		fix_fileinfo("added_new", $file);
	        $changes{added_new} .= "   $new_rule";
	    }
    } # foreach sid

  # Check for removed rules, i.e. sids that exist in the new rules file but not in the old one.
    foreach $sid (keys(%{$old_rules{$file}})) {
        unless (exists($new_rules{$file}{$sid})) {
            $old_rule = $old_rules{$file}{$sid};
	    fix_fileinfo("removed_del", $file);
            $changes{removed_del} .= "       $old_rule";
        }
    }

  # First check for added non-rule lines.
    foreach $_ (@{$new_other{$file}}) {
        unless (find_line($_, @{$old_other{$file}})) {  # Does this line also exist in the old rules file?
            fix_fileinfo("other_added", $file);         # Nope, it's an added line.
            $changes{other_added} .= "       $_";
            $other_changed = 1;
        }
    }

  # Check for removed non-rule lines.
    foreach $_ (@{$old_other{$file}}) {
        unless (find_line($_, @{$new_other{$file}})) {  # Does this line also exist in the new rules file?
            fix_fileinfo("other_removed", $file);       # Nope, it's a removed line.
            $changes{other_removed} .= "       $_";
            $other_changed = 1;
        }
    }

} # foreach new file

# Creaste list of possibly removed files if -r is specified.
if ($check_removed) {
    opendir(OLDRULES, "$output_dir") or die("could not open directory $output_dir: $!\nExiting");

    while ($_ = readdir(OLDRULES)) {
        $removed_files .= "    -> $_\n"
          if (/$config{update_files}/ && !exists($file_ignore_list{$_}) && !exists($new_files{$_}));
    }
    closedir(OLDRULES);
}

print STDERR "done.\n" unless ($quiet);

# Update files listed in %modified_files (move the new files from the temporary
# directory into our -o <outout directory>, unless we're running in careful mode.
# Also create backup first if running with -b.
if ($rules_changed || $other_changed) {
    if ($careful) {
        print STDERR "Running in careful mode - not updating any files.\n";
        print STDERR "No need to backup old files, skipping.\n"
          if (defined($backup_dir) && (!$quiet));
    }  else {
        do_backup if (defined($backup_dir));                      # backup old rules if -b

      # Move each modified file from the temporary directory to the output directory.
        foreach $_ (keys(%modified_files)) {
            move("$tmpdir/rules/$_", "$output_dir/$_")
              or die("\nWarning: could not move $tmpdir/rules/$_ to $output_dir/$_: $!\nExiting")
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
          or die("\nWarning: could not move $tmpdir/rules/$_ to $output_dir/$_: $!\nExiting")
    }
}

# Remove temporary directory.
system("/bin/rm","-r","-f","$tmpdir")
  and print STDERR "Warning: unable to remove temporary directory $tmpdir.\n";

# Time to print the results.

if (($rules_changed || $other_changed || keys(%added_files) > 0 || defined($removed_files))
     || !$quiet) {
    print "\n[***] Results from Oinkmaster started $start_date [***]\n";
    print "\nNote: Oinkmaster was running in careful mode - no files were really updated or added.\n"
      if ($careful && $rules_changed || $other_changed || keys(%added_files) > 0);

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
        print "\n  [+++]       Added line(s):       [+++]\n $changes{other_added}"
          if (exists($changes{other_added}));
        print "\n  [---]      Removed line(s):      [---]\n $changes{other_removed}"
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

  # Print list of possibly deleted files if -r is specified.
    if ($check_removed) {
        if (defined($removed_files)) {
            print "\n[*] Possibly removed files (consider removing them from your".
                  " snort.conf): [*]\n$removed_files";
        } else {
            print "\n[*] Files possibly removed from archive: [*]\n    None.\n";
        }
    }

    print "\n";
}
# END OF MAIN #



sub show_usage
{
    print STDERR "$version\n\n".
                 "Usage: $0 -o <dir> [options]\n\n".
		 "<dir> is where to put the new rules files. This should be the\n".
                 "directory where you store your snort.org rules\n".
                 "\nOptions:\n".
		 "-C <cfg>  Use this config file instead of the default $config_file\n".
		 "-b <dir>  Backup old rules into <dir> if anything had changed\n".
		 "-u <url>  Download from this URL (http:// or ftp:// ...tar.gz)\n".
                 "          Overrides URL= value in oinkmaster.conf\n".
		 "-c        Careful mode. Don't update anything, just check for changes\n".
                 "-r        Check for rules files that exist in the output directory\n".
                 "          but not in the downloaded rules archive (i.e. files that may\n".
                 "          have been removed from the archive).\n".
                 "-q        Quiet mode. No output unless changes were found\n".
		 "-v        Verbose mode\n".
                 "-h        Show usage help\n\n";
    exit;
}



sub parse_cmdline
{
    my $cmdline_ok = getopts('b:cC:ho:qru:v');

    $backup_dir    = $opt_b if (defined($opt_b));
    $config_file   = $opt_C if (defined($opt_C));
    $url           = $opt_u if (defined($opt_u));
    $quiet         = 1      if (defined($opt_q));
    $verbose       = 1      if (defined($opt_v));
    $careful       = 1      if (defined($opt_c));
    $check_removed = 1      if (defined($opt_r));
    show_usage              if (defined($opt_h));

    show_usage unless ($cmdline_ok);

    if (defined($opt_o)) {                # -o <dir>, the only required option.
        $output_dir = $opt_o;
    } else {
        show_usage;
    }

  # Can't use both -q and -v.
    die("Both quiet mode and verbose mode at the same time doesn't make sense.\nExiting")
      if ($quiet && $verbose);
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
	} elsif (/^URL\s*=\s*(.*)/i) {                        # URL to use
	    $url = $1 unless (defined($url));                 # may already be defined by -u <url>
	} elsif (/^PATH\s*=\s*(.*)/i) {                       # $PATH to be used
	    $config{path} = $1;
	} elsif (/^update_files\s*=\s*(.*)/i) {               # regexp of files to be updated
	    $config{update_files} = $1;
	} elsif (/^skip_diff\s*=\s*(.*)/i) {                  # regexp of files to skip comparison for
	    $config{skip_diff} = $1;
        } else {                                              # invalid line
            print STDERR "Warning: line $line in $config_file is invalid, skipping line.\n";
        }
    }

    close(CONF)
}



sub sanity_check
{
   my @req_config   = qw (path update_files);
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

  # Make sure $url is defined (either by -u <url> or url=... in the conf.
    die("Incorrect URL, or URL not specified in neither $config_file nor command line.\nExiting")
      unless (defined($url) && $url =~ /^(?:http|ftp):\/\/\S+.*\.tar\.gz$/);

  # Make sure the output directory exists and is writable.
    die("The output directory \"$output_dir\" doesn't exist or isn't writable by you.\nExiting")
      if (! -d "$output_dir" || ! -w "$output_dir");

  # Make sure the backup directory exists and is writable if running with -b.
    die("The backup directory \"$backup_dir\" doesn't exist or isn't writable by you.\nExiting")
      if (defined($backup_dir) && (! -d "$backup_dir" || ! -w "$backup_dir"));
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
    print STDERR "Archive successfully downloaded, unpacking... " unless ($quiet);

    die("Failed to untar $filename\nExiting")
      if system("tar","xf","$filename");

    die("No \"rules/\" directory found in tar file.\nExiting")
      unless (-d "rules");

  # Change back to old dir.
    chdir("$old_dir") or die("could not change directory back to $tmpdir: $!\nExiting");

    print STDERR "done.\n" unless ($quiet);
}



# Disable (#comment out) all rules listed in %sid_disable_list.
# All files will still be left in the temporary directory.
sub disable_rules
{
    my ($num_disabled, $msg, $sid, $line, $file);

    $num_disabled = 0;
    print STDERR "Disabling rules according to $config_file... " unless ($quiet);
    print STDERR "\n" if ($verbose);

    foreach $file (keys(%new_files)) {
        open(INFILE, "<$tmpdir/rules/$file") or die("could not open $tmpdir/rules/$file: $!\nExiting");
	@_ = <INFILE>;
        close(INFILE);

      # Write back to the same file.
	open(OUTFILE, ">$tmpdir/rules/$file") or die("could not open $tmpdir/rules/$file: $!\nExiting");
	RULELOOP:foreach $line (@_) {
            unless ($line =~ /$snort_rule_regexp/) {    # only care about snort rules
	        print OUTFILE $line;
		next RULELOOP;
	    }

	    ($msg, $sid) = ($1, $2);
            if (exists($sid_disable_list{$sid})) {      # should this sid be disabled?
                if ($verbose) {
                    $_ = $file;
                    $_ =~ s/.+\///;                     # remove path, just keep the filename
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
    print STDERR "$num_disabled rules disabled.\n" unless ($quiet)
}


# Setup %new_rules, %old_rules, %new_other and %old_other.
# Format will be %new_rules{filename}{sid} = rule
# and:
# %new_other{filename} = @array_with_non-rule_lines
# As a bonus, we get list of added files in %added_files.
sub setup_rule_hashes
{
    my ($file);

    foreach $file (keys(%new_files)) {
        open(NEWFILE, "$tmpdir/rules/$file") or die("could not open $tmpdir/rules/$file: $!\n");
	while (<NEWFILE>) {
	    if (/$snort_rule_regexp/) {
	        $new_rules{"$file"}{"$2"} = $_;
	    } else {
	        push(@{$new_other{"$file"}}, $_);  # use array so the lines stay sorted
	    }
	}
	close(NEWFILE);

     # Also read in old file if it exists.
        if (-f "$output_dir/$file") {
            open(OLDFILE, "$output_dir/$file") or die("could not open $output_dir/$file: $!\nExiting");
	    while (<OLDFILE>) {
                if (/$snort_rule_regexp/) {
                    $old_rules{$file}{$2} = $_;
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



# Try to find a given string in a given array. Return 1 if found, otherwise 0.
# Some things will always be considered as found (lines that we don't care if
# they were added/removed). It's extremely slow, but who cares.
sub find_line
{
    my $line = shift;   # line to look for
    my @arr  = @_;      # array to look in

    return 1 unless ($line =~ /\S/);                       # skip blank lines (always consider them as found)
    return 1 if     ($line =~ /\s*#+\s*\$Id$/);  # also skip CVS $Id tag

    foreach $_ (@arr) {
        return 1 if ($_ eq $line);                         # string found
    }

    return 0;                                              # string not found
}



# Add filename info to given "changelog" array, unless already done.
# Also update list of modified files.
sub fix_fileinfo
{
    my $type     = shift;   # type of change (added_new/removed_del/modified_active etc).
    my $filename = shift;

    unless (exists($printed{$type})) {                         # Filename info already added?
        $changes{$type} = "   -> File \"$filename\":\n";       # Nope, add it.
        $printed{$type}++;                                     # So we know it has now been added.
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
      or die("Could not create directory $tmpbackupdir: $!\nExiting");

    opendir(OLDRULES, "$output_dir") or die("could not open directory $output_dir: $!\nExiting");
    while ($_ = readdir(OLDRULES)) {
        copy("$output_dir/$_", "$tmpbackupdir/")
          or print STDERR "Warning: error copying $output_dir/$_ to $tmpbackupdir: $!"
            if (/$config{update_files}/ && !exists($file_ignore_list{$_}));
    }
    closedir(OLDRULES);

  # Change directory to $tmpdir (so we'll be right below the directory where
  # we have our rules to be backed up).
    $old_dir = getcwd or die("Could not get current directory: $!\nExiting");
    chdir("$tmpdir")  or die("Could not change directory to $tmpdir: $!\nExiting");

  # Execute tar command.
  # This will archive "rules-backup-$date/" into the file rules-backup-$date.tar, placed in $tmpdir.
    print STDERR "Warning: tar command did not exit with status 0 when archiving backup files.\n"
      if (system("tar","cf","rules-backup-$date.tar","rules-backup-$date"));

  # Compress it.
    print STDERR "Warning: gzip command did not exit with status 0 when compressing backup file.\n"
      if (system("gzip","rules-backup-$date.tar"));

  # Change back to old directory (so it will work with -b <directory> as either
  # an absolute or a relative path.
    chdir("$old_dir") or die("could not change directory back to $old_dir: $!\nExiting");

  # Move the archive to the backup directory.
    move("$tmpdir/rules-backup-$date.tar.gz", "$backup_dir/")
      or print STDERR "Warning: unable to move $tmpdir/rules-backup-$date.tar.gz to $backup_dir/: $!\n";

    print STDERR " saved as $backup_dir/rules-backup-$date.tar.gz.\n"
      unless ($quiet);

}

#### EOF ####
