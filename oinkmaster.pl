#!/usr/bin/perl -w


use strict;
use Getopt::Std;
use File::Copy;
use POSIX qw(strftime);
use File::Copy;
use Cwd;


use vars
qw (
      $opt_V $opt_h $opt_o $opt_u $opt_v $opt_q $opt_w $opt_t 
      $opt_i $opt_q $opt_c $opt_b $opt_g $opt_a
   );   

my (
      $outdir, $olddir, $file, $old_rule, $new_rule, $sid, 
      $added_files, $msg
   );

my (
      @new_files, @modified_files
   );

my (
      %sid_disable_list, %file_ignore_list, %printed, %changes, 
      %old_rules, %new_rules, %new_other, %old_other
   );


sub parse_cmdline;
sub usage;
sub fix_comments;
sub find_line;
sub fix_fileinfo;
sub unpack_snortarchive;
sub backup_rules;
sub setup_rule_hashes;


my $version 	      = 'Oinkmaster v0.2 by Andreas Östling, andreaso@it.su.se.';

# Some defaults.
my $url               = "http://snort.sourcefire.com/downloads/snortrules.tar.gz";      # Default URL.
my $wget_bin          = "/usr/local/bin/wget";						# Default wget location.
my $gzip_bin	      = "/usr/bin/gzip";                                                # Default gzip location.
my $tar_bin           = "/bin/tar";							# Default tar location.
my $ignore_file       = "./rules.ignore";						# Default ignore file.
my $tmpdir            = "/tmp";                                                         # Tmpdir, change this if needed. 
my $outfile           = "snortrules.tar.gz";						# What to call the archive locally.

my $attempts          = 3;      # Number of default download attempts before giving up.
my $checkout          = 0;      # Not checkout mode by default.
my $verbose           = 0;      # Not verbose mode by default.
my $quiet	      = 0;      # Not quiet mode by default.
my $backup_dir        = 0;      # Default is not to backup old rules.
my $rules_changed     = 0;	# No rule changes yet.
my $other_changed     = 0;	# No other changes yet.

# Regexp to match a Snort rule line. The msg string will go into $1, and the sid will go into $2.
my $rule_regexp = '^\s*#*\s*(?:alert|log|pass) .+msg\s*:\s*"(.+?)"\s*;.+sid\s*:\s*(\d+)\s*;';


#### MAIN ####

select(STDERR); $| = 1;         # No buffering.
select(STDOUT); $| = 1;

parse_cmdline;		        # Check command line arguments and die we don't like them.
				# Will also die if Oinkmaster is running as root.

# Create empty temporary directory. Die if it already exists.
if (-e "$tmpdir") {
    die("Temporary directory $tmpdir already exists.\n\nExiting");
}
else {
    mkdir("$tmpdir",0700) or die("Could not create temporary directory $tmpdir: $!\nExiting");      
}

# Open ignore file and read sids to be disabled (#commented) into %sid_disable_list
# and also read files to be skipped into %file_ignore_list.
open(IGNORE, $ignore_file) or die("Could not open $ignore_file: $!.\nExiting");
@_ = <IGNORE>;
close(IGNORE);

for $_ (0 .. $#_) {					   # For each line in the ignore file...
    $_[$_] =~ s/\s*\#.*//;				   # Remove #comments.
    next unless ($_[$_] =~ /\S/);			   # Skip blank lines.

    if ($_[$_] =~ /^\s*sid\s*(\d+)/i) {			   # Try to grab a sid.
        $sid_disable_list{$1}++;			   # Put this sid in the disable list.
    }
    elsif ($_[$_] =~ /^\s*file\s*(\S+)/i) {  		   # Try to grab a file to be ignored.
	$verbose && print STDERR "File $1 will be ignored.\n";	
	$file_ignore_list{$1}++;			   # Put this file in the ignore list.
    }
    else {						   # Invalid line.
	print STDERR "Warning: line ", $_ +1, " in $ignore_file is invalid.\n";
    }
}

# Pull down the rules. Die if wget doesn't exit with status level 0.
if ($quiet) {     	        			   # Execute wget command in quiet mode. 
    if (system("$wget_bin","-q","-nv","-t",$attempts,"-O","$tmpdir/$outfile","$url")) {
	print STDERR "Maximum number of download attempts reached ($attempts). Giving up.\n";
	die("Consider running in non-quiet mode if the problem persists.\n\nExiting");
    }
}
else {   		        			   # Execute wget command in non-quiet mode.
    print STDERR "Downloading ruleset from $url...\n";
    die("Maximum number of download attempts reached ($attempts). Giving up.\n\nExiting")
      if (system("$wget_bin","-nv","-t",$attempts,"-O","$tmpdir/$outfile","$url"));
}

# Change to temporary directory and verify/unpack archive.
# This will hopefully leave us with a directory called "rules/" in the temporary directory,
# containing the new rules.
$olddir = getcwd or die("Could not get current directory.\n");  # Save old dir so we can change back.
chdir("$tmpdir") or die("Could not change directory to $tmpdir: $!\nExiting");

if (-s "$outfile") {			   		   # It's a good start if it is larger than 0 bytes.
    unpack_snortarchive($outfile);
}
else {
    die("Failed to get $url! (The file \"$tmpdir/$outfile\" doesn't exist or hasn't non-zero size)\n\nExiting");
}

# Change back.
chdir("$olddir") or die("Could not change directory to $tmpdir: $!\nExiting");


# Add *.rules and classification.config from the downloaded archive to the list of new files,
# unless filename exists in %file_ignore_list.

opendir(NEWRULES, "$tmpdir/rules") or die("Could not open directory $tmpdir/rules: $!\nExiting");
@_ = readdir(NEWRULES);
closedir(NEWRULES);
 
foreach $_ (@_) {
    push(@new_files, $_)
      if ((/\.rules$/ || /^classification\.config$/) && !exists($file_ignore_list{$_}));
}

print STDERR "Found ", $#new_files + 1, " rules files in archive to be checked for updates.\n" unless ($quiet);

fix_comments;		# Disable rules listed in the ignore file.
setup_rule_hashes;  	# Read rules and other lines into %new_rules/%old_rules and %new_other/%old_other.

print STDERR "Checking for differences between old and new rulesets...\n" unless ($quiet);

# For each file in the file list (the new files), disable rules listed in %sid_disable_list and check 
# for differences between the old file and the new file.

FILELOOP:foreach $file (@new_files) {

  # It's a new file if we don't have a file with that filename in our output directory.
    unless (exists($old_rules{$file}) || exists($old_other{$file})) {
	$added_files .= "Added file: $outdir/$file\n";
	unless ($checkout) {
	    move("$tmpdir/rules/$file", "$outdir/$file")  # New file, move to $outdir/.
	      or die("Could not move $tmpdir/rules/$file to $outdir/$file: $!\nExiting");
	}
	next FILELOOP;	  # No need to check for changes, just jump to the next new file.
    }

    undef(%printed);	  # This one will tell us if the filename info has been printed or not.

  # Time to compare the old rules file to the new rules file.
  # For each rule in the new rule set, check if the rule also exists in the old rule set. 
  # If it does then check if it has been modified, but if it doesn't, it must have been added.

    foreach $sid (keys(%{$new_rules{$file}})) { 			# For each sid in the new ruleset file...

	if (exists($old_rules{$file}{$sid})) {				# Does this sid also exist in the old ruleset?

	    $old_rule = $old_rules{$file}{$sid};			# Yes. Put old rule in $old_rule.
	    $new_rule = $new_rules{$file}{$sid};			# Also grab the new rule so we can compare them.

            unless ($old_rule eq $new_rule) {				# Do they match?
		$rules_changed = 1;                             	# Nope. Let's check what has been changed.

                if ("#$old_rule" eq $new_rule) {			# Rule disabled? (if only "#" has been prepended).
		    fix_fileinfo("removed_dis", $file);			# Add filename banner, unless already done.
		    $changes{removed_dis} .= "    $new_rule";
                }
                elsif ($old_rule eq "#$new_rule") {		        # Rule enabled? (if only leading "#" has been removed.
		    fix_fileinfo("added_ena", $file); 
                    $changes{added_ena} .= "    $new_rule";
                }
                elsif ($old_rule =~ /^\s*#/ && $new_rule !~ /^\s*#/) {  # Rule enabled and also modified?
		    fix_fileinfo("added_ena_mod", $file);
		    $changes{added_ena_mod} .= "    Old: $old_rule    New: $new_rule"; 
                }
                elsif ($old_rule !~ /^\s*#/ && $new_rule =~ /^\s*#/) {	# Rule disabled and also modified?
		    fix_fileinfo("removed_dis_mod", $file); 
		    $changes{removed_dis_mod} .= "    Old: $old_rule    New: $new_rule"; 
                }
                elsif ($old_rule =~ /^\s*#/ && $new_rule =~ /^\s*#/) {	# Commented (inactive) rule modified?
		    fix_fileinfo("modified_inactive", $file); 
		    $changes{modified_inactive} .= "    Old: $old_rule    New: $new_rule";
                }
                else {							# Active rule modified?
		    fix_fileinfo("modified_active", $file);  
		    $changes{modified_active} .= "    Old: $old_rule    New: $new_rule";
                }

            }
	}
        else {                      # Could not find this sid in the old ruleset so it must have been added.
	    fix_fileinfo("added_new", $file);
	    $changes{added_new} .= "    $new_rule";
	    $rules_changed = 1;
        }
    }

  # Check for removed rules (i.e. sids that exist in the old ruleset but not in the new one.
    foreach $sid (keys(%{$old_rules{$file}})) {
	unless (exists($new_rules{$file}{$sid})) {
	    $old_rule = $old_rules{$file}{$sid};
	    fix_fileinfo("removed_del", $file);  
	    $changes{removed_del} .= "    $old_rule"; 
	    $rules_changed = 1;
        }
    }  

  # Now check for other changes (lines that aren't Snort rules).
  # (if a line exists several times, it will be considered as found even if one of them has been added/removed,
  # but that's no big deal...)

  # First check for added lines.
    foreach $_ (@{$new_other{$file}}) {
	unless (find_line($_, @{$old_other{$file}})) {		# Does this line also exist in the old ruleset?
	    fix_fileinfo("other_added", $file);		  	# Nope, it's an added line.
	    $changes{other_added} .= "    $_";
	    $other_changed = 1; 
	} 
    }

  # Check for removed lines.
    foreach $_ (@{$old_other{$file}}) {
        unless (find_line($_, @{$new_other{$file}})) {          # Does this line also exist in the new ruleset?
            fix_fileinfo("other_removed", $file);               # Nope, it's a removed line.
            $changes{other_removed} .= "    $_";
            $other_changed = 1;
        }
    }
}

# Update rules files listed in @modified_files (move the new files from the temporary directory to
# our -o <outdir> directory), unless we're running in checkout mode.
# Also create backup first if running with -b.

if ($rules_changed || $other_changed) {
    if ($checkout) {
	print STDERR "Running in checkout mode: not updating any files.\n";
	print STDERR "No need to backup rules files.\n" if ($backup_dir) && (!$quiet);
    }
    else {
	backup_rules if ($backup_dir);					# Create backup if -b.
	print STDERR "Updating file(s) in directory \"$outdir/\":" unless ($quiet);

      # Move each modified file from the temporary directory to the output directory. 
	foreach $_ (@modified_files) {
	    print STDERR " $_" unless ($quiet);
	    move("$tmpdir/rules/$_", "$outdir/$_") or die("Could not move $tmpdir/rules/$_ to $outdir/$_: $!\nExiting")
	}
	print STDERR ".\n" unless ($quiet);   
    }
}

# Remove temporary directory.
system("/bin/rm","-r","-f","$tmpdir") and print STDERR "Warning: error removing temporary directory $tmpdir.\n";

# Print rule changes, if any.
if ($rules_changed) {
    print "\n" unless ($quiet);
    print "Rule changes since last update:\n";
    print "\n[+++]            Added (new):           [+++]\n $changes{added_new}"         if (exists($changes{added_new}));
    print "\n[+++]          Added (enabled):         [+++]\n $changes{added_ena}"         if (exists($changes{added_ena}));
    print "\n[+++]   Added (enabled) and modified:   [+++]\n $changes{added_ena_mod}"     if (exists($changes{added_ena_mod}));
    print "\n[---]         Removed (deleted):        [---]\n $changes{removed_del}"       if (exists($changes{removed_del}));
    print "\n[---]         Removed (disabled):       [---]\n $changes{removed_dis}"       if (exists($changes{removed_dis}));
    print "\n[---] Removed (disabled) and modified:  [---]\n $changes{removed_dis_mod}"   if (exists($changes{removed_dis_mod})); 
    print "\n[///]          Modified active:         [///]\n $changes{modified_active}"   if (exists($changes{modified_active}));
    print "\n[///]         Modified inactive:        [///]\n $changes{modified_inactive}" if (exists($changes{modified_inactive})); 
    print "\n";
}
else {
    print "No rule changes since last update.\n" unless ($quiet);
}

# Print other changes, if any.
if ($other_changed) {
    print "Non-rule changes since last update:\n";
    print "\n[+++]           Added line(s):          [+++]\n $changes{other_added}"   if (exists($changes{other_added}));
    print "\n[---]          Removed line(s):         [---]\n $changes{other_removed}" if (exists($changes{other_removed}));
    print "\n";
}
else {
    print "No non-rule lines in rulesets added or removed since last update.\n" unless ($quiet);
}

# Print list of added files, if any.
if (defined($added_files)) {
    if ($checkout) {
	print "At least one new file in new ruleset archive (checkout mode: not adding anything):\n$added_files";
    }
    else {
	print "At least one rules file has been added since last update.\n";
	print "Please have a look at it/them and consider updating your Snort configuration file.\n$added_files";
    }
}


#### END OF MAIN ####



# Parse the command line and do some sanity checking.
sub parse_cmdline
{
    my $cmdline_ok = getopts('ho:Vvu:w:t:i:qcb:g:a:');

    usage 	      if (defined($opt_h));		# Show usage info and quit if running with -h.
    die("$version\n") if (defined($opt_V));		# Show version and quit if running with -V.
    usage unless ($cmdline_ok);				# Show usage info and quit if we don't like the command line.     

    if (defined($opt_o)) {				# -o <outdir>, the only required option.
	$outdir = $opt_o;
    }
    else {						# -o wasn't specified so show usage info and die.
	print STDERR "You must specify where to put the rules with -o <rules directory>.\n\n";
	usage;
    }

    die("Don't run as root!\n\nExiting") if (! $>); 
 
    $url = $opt_u if (defined($opt_u));         	# Use URL specified with -u <url> instead of the default.

  # URL must start with http:// or ftp://
    die("$url is not a valid URL - It should start with \"http://\" or \"ftp://\"\n\nExiting")
      unless ($url =~ /^http:\/\/\S+/ || $url =~ /^ftp:\/\/\S+/);
   
  # Check for wget in /usr/bin/.
    $wget_bin = "/usr/bin/wget" if (-f "/usr/bin/wget");

  # Check for tar in /usr/local/bin/, /usr/bin/ and /usr/sbin.
    $tar_bin = "/usr/local/bin/tar"   if (-f "/usr/local/bin/tar"); 
    $tar_bin = "/usr/sbin/tar"        if (-f "/usr/sbin/tar");
    $tar_bin = "/usr/bin/tar"         if (-f "/usr/bin/tar");

  # Check for gzip in /bin/.
    $gzip_bin = "/bin/gzip" if (-f "/bin/gzip");

    $verbose           = 1      if (defined($opt_v));  	 # -v (verbose mode).
    $quiet             = 1      if (defined($opt_q));    # -q (quiet mode).
    $checkout          = 1      if (defined($opt_c));    # -c (checkout mode).
    $backup_dir        = $opt_b if (defined($opt_b));    # -b <backup directory>
    $wget_bin          = $opt_w if (defined($opt_w));    # -w <wget binary>.
    $gzip_bin          = $opt_g if (defined($opt_g));    # -g <gzip binary>.
    $tar_bin           = $opt_t if (defined($opt_t));    # -t <tar binary>.
    $ignore_file       = $opt_i if (defined($opt_i));    # -i <ignore file>.   
    $attempts          = $opt_a if (defined($opt_a));    # -a <attempts>.

  # Make sure that the wget binary exists.
    die("Could not find wget binary. Please specify correct path/filename of wget with -w <wget>.\n\nExiting")
      unless (-f "$wget_bin");

  # Make sure that the tar binary exists. 
    die("Could not find tar binary. Please specify correct path/filename of tar with -t <tar>.\n\nExiting")
      unless (-f "$tar_bin");

  # Make sure that the gzip binary exists.
    die("Could not find gzip binary. Please specify correct path/filename of gzip with -g <gzip>.\n\nExiting")
      unless (-f "$gzip_bin");

  # Make sure that the ignore file exists.
    unless (-f "$ignore_file") {
        print STDERR "The file \"$ignore_file\" does not exist. Please specify correct path/filename with -i <ignore file>.\n";
        print STDERR "Just create an empty file If you don't want to ignore any rules at all.\n";
	die("\nExiting");
    }

  # Make sure the temporary directory exists and is writable.
    if (! -d "$tmpdir" || ! -w "$tmpdir") {
	die("The temporary directory \"$tmpdir\" doesn't exist or isn't writable by you.\n\nExiting");
    }
    else {
	$tmpdir .= "/snortrules.temp.$$";	# We will be living in a sub directory of the original $tmpdir.
    }

  # Make sure the output directory exists and is writable.
    die("The directory \"$outdir\" doesn't exist or isn't writable by you.\n\nExiting")
      if (! -d "$outdir" || ! -w "$outdir");

    $outdir     =~ s/\/$//;			# Remove possible trailing slash (just for cosmetic reasons).
    $backup_dir =~ s/\/$//;

  # Make sure the backup directory exists and is writable if running with -b.
    die("The backup directory \"$backup_dir\" doesn't exist or isn't writable by you.\n\nExiting")
      if ($backup_dir && (! -d "$backup_dir" || ! -w "$backup_dir"));

  # Can't use both -q and -v.
    die("Both quiet mode and verbose mode at the same time doesn't make sense.\n\nExiting")
      if ($quiet && $verbose); 

  # Make sure number of download attempts looks ok.
    if (defined($opt_a)) { 
        die("$attempts is not a valid number of download attempts (should be 1-9).\n\nExiting")
	  if ($attempts !~ /^\d$/ || $attempts < 1);
    }
}



# ShowTF(ine)M and quit.
sub usage
{
    select(STDERR);

    print "$version\n";
    print "Usage:\n";
    print "$0 -o <rules directory> [options]\n\n";
    print "-o <rules directory> Where to put the new rules files (must be a directory).\n";
    print "                     This should be where you store your snort.org rules.\n";
    print "                     The new rules files will be compared to the ones in here.\n";
    print "                     Note that the current rules files will be overwritten by\n";
    print "                     the new ones if they had been modified (but check out\n";
    print "                     the \"-b\" option).\n";
    print "\nOptions:\n";
    print "-v                   Verbose mode - gives some more output.\n";
    print "-c                   Checkout (Careful?) mode - don't update any rules, just download the\n";
    print "                     new rules and check for differences.\n";
    print "-a <attempts>        Maximum number of download attempts before giving up.\n";
    print "                     Must be a number between 1 and 9. Default is $attempts.\n";
    print "-b <directory>       If any rules file had changed, backup the old ones (*.rules\n";
    print "                     and classification.config in <rules directory>) to\n";
    print "                     <directory> before updating them.\n";
    print "-i <ignore file>     The file containing information about which rules/files that\n";
    print "                     should be disabled/ignored. Default is $ignore_file.\n";
    print "-u <url>             Get ruleset from this URL (http:// or ftp://) instead of\n";
    print "                     the default, $url.\n";
    print "                     This file must be in .tar.gz format and have the rule\n";
    print "                     files in a directory called \"rules/\" in it.\n";
    print "-w <wget>            Where to find the wget binary. Not needed if available as\n";
    print "                     /usr/bin/wget or /usr/local/bin/wget.\n";
    print "-g <gzip>            Where to find the gzip binary. Not needed if available as\n";
    print "                     /bin/gzip or /usr/bin/gzip.\n";
    print "-t <tar>             Where to find the tar binary. Not needed if tar is in\n";
    print "                     /bin/, /usr/bin/, /usr/sbin/ or /usr/local/bin/.\n";
    print "-q                   Quiet mode. No output unless anything had changed.\n";
    print "                     Warnings and errors will still be printed.\n";
    print "\nOther:\n";
    print "-V                   Show version and exit.\n";
    print "-h                   Show help and exit.\n";

    select(STDOUT);
    exit(1);
}



# Open each new rules file, #comment rules listed in the ignore file, and write rules file back to disk. 
sub fix_comments
{
    my($rulefile, @rules, $line, $sid, $num);

    $num = 0;						# Keep track of number of disabled rules.

    print STDERR "Fixing rules to be disabled...\n" unless ($quiet);

    foreach $rulefile (@new_files) {

      # Make sure it's a regular file.    
	die("$rulefile isn't a regular file.\n\nExiting") 
	  unless (-f "$tmpdir/rules/$rulefile" && ! -l "$tmpdir/rules/$rulefile");  

	open(RULES_IN, "$tmpdir/rules/$rulefile") or die("Could not open $tmpdir/rules/$rulefile: $!\nExiting");
	@rules = <RULES_IN>;
	close(RULES_IN);  

	open(RULES_OUT, ">$tmpdir/rules/$rulefile") 	# Write back to the same file.
          or die("Could not open $tmpdir/rules/$rulefile for writing: $!\nExiting");

	LINELOOP:foreach $line (@rules) {
	    unless ($line =~ /$rule_regexp/) {		# Only care about Snort rule lines, other
	        print RULES_OUT $line;			# lines will just be put right back into the file.
	        next LINELOOP;
	    }

	    ($msg, $sid) = ($1, $2);			# Grab msg string and the sid from the rule.

	    if (exists($sid_disable_list{$sid})) {   	# Should this sid be disabled?
	        if ($verbose) {				# Yepp.
		    $_ = $rulefile;
		    $_ =~ s/.+\///;			# Remove path, just keep the filename.
		    $_ = sprintf("Disabling sid %-5s in file %-20s (%s)\n", $sid, $_, $msg);
		    print STDERR "$_";
	        }
	        $line = "#$line" unless ($line =~ /^\s*#/);     # Comment this rule, unless already done by default.
		$num++;
	    }
 	    else {			 # Sid was not listed in the ignore file.
	        $line =~ s/^\s*#*\s*//;	 # Uncomment this rule to be sure, since some rules may be commented by default.
	    }

 	    print RULES_OUT $line;	 # Write line back to the rules file.
        }

        close(RULES_OUT);
    }
    print STDERR "Disabled $num rule(s).\n" unless ($quiet);
}



# Try to find a given string in a given array. Return 1 if found, otherwise 0.
# Some things will always be considered as found (lines that we don't care if they were added/removed). 
sub find_line
{
    my $line = shift;	# Line to look for.
    my @arr  = @_;	# Array to look in.

    return 1 unless ($line =~ /\S/);                       # Skip blank lines  (always consider them as found).
    return 1 if     ($line =~ /\s*#+\s*\$Id$/);  # Also skip tag.
 
    foreach $_ (@arr) {
        return 1 if ($_ eq $line);			   # String found.
    }
 
    return 0;						   # String not found.
}



# Add filename info to given "changelog" array, unless already done.
sub fix_fileinfo
{
    my $type     = shift;   # Change "type" (added_new/removed_del/modified_active etc).
    my $filename = shift;   # Filename string.

    unless (exists($printed{$type})) {			# Filename info already added?
	$changes{$type} .= "-> File: $filename:\n";	# Nope, add it.
	$printed{$type}++;				# So we know it has now been added.
    }

  # Add filename to list of modified files, unless its already in there. These files will then be updated.
    push(@modified_files, $filename) unless (grep(/^$filename$/, @modified_files));
}



# Do some basic sanity checking on the Snort rules archive, and then unpack it.
# Die if it doesn't look good.
sub unpack_snortarchive
{
    my (@tar, $archive, $ok);

    $archive = shift;				# Filename of the .tar.gz file.
    $ok = 'a-zA-Z0-9_\.\-/\n :';  		# Allowed characters in the tar archive.

  # First run 'gzip -t' on it.
    die("gzip integrity check failed (file transfer failed or file in URL not in gzip format?).\nExiting")
      if (system("$gzip_bin","-t","$archive")); 

  # Unpack it.
    system("$gzip_bin","-d","$archive") and die("Unable to unpack $archive, broken download?\n");

  # Suffix has now changed from .tar.gz to .tar.
    $archive =~ s/\.gz$//;

    if (open(TAR,"-|")) {
	open(STDERR, ">&STDOUT");
        @tar = <TAR>;				# Read output of the "tar vtf" command into @tar.
    }
    else {
        exec("$tar_bin","vtf","$archive")
          or die("Unable to execute untar/unpack command: $!\nExiting");
    }

  # Look for uncool stuff in the archive.
    foreach $_ (@tar) {
      # We don't want to have any weird characters in the tar file.
	die("Forbidden characters in tar archive: refuse to unpack file.\nOffending file:\n$_\nExiting")
	  if (/[^$ok]/);
      # We don't want to unpack any "../../" junk.
	die("Error: file in tar archive contains \"..\" in filename: refuse to unpack file.\nOffending file:\n$_\nExiting")
	  if (/\.\./);
      # And there should be no links in the tar archive.
	die("Error: file in tar archive contains link: refuse to unpack file.\nOffending file:\n $_\nExiting")
 	  if (/->/ || /=>/);		# (">" isn't an allowed character anyway so we won't come this far right now...)
    }

  # Looks good. Now we can untar it.
    print STDERR "Rules successfully downloaded, unpacking...\n" unless ($quiet); 

    die("Failed to untar $archive, broken download?\n\nExiting")
      if system("$tar_bin","xf","$archive");

    die("No \"rules/\" directory found in tar file.\n\nExiting")
      unless (-d "rules");
}



# Backup old rules files into -b <directory>.
sub backup_rules
{
    my ($date, $tmpbackupdir, @files, $olddir);

    print STDERR "Backing up old rules..." unless ($quiet);

    $date         = strftime("%Y%m%d-%H%M", localtime);
    $tmpbackupdir = "$tmpdir/rules-backup-$date";	# Temporary directory where rules to be backed up will be put.

    mkdir("$tmpbackupdir", 0700) or die("Could not create directory $tmpbackupdir: $!\nExiting");

  # Add *.rules and classification.config (the old files in $outdir) to list of files that should be backed up.
    @files = glob("$outdir/*.rules");
    push (@files, "$outdir/classification.config") if (-f "$outdir/classification.config");

  # Copy files that should be backed up into our temporary directory.
    foreach $_ (@files) {
	copy("$_", "$tmpbackupdir/") or print STDERR "Warning: error copying $_ to $tmpbackupdir: $!";
    }

  # Change directory to $tmpdir (so we'll be right below the directory where we have our rules to be backed up).
    $olddir = getcwd or die("Could not get current directory.\n"); 	# So we can change back.
    chdir("$tmpdir") or die("Could not change directory to $tmpdir: $!\nExiting"); 

  # Execute tar command. 
  # This will archive "rules-backup-$date/" into the file rules-backup-$date.tar, placed in $tmpdir.
    print STDERR "Warning: tar command did not exit with status 0 when archiving backup files.\n"
      if (system("$tar_bin","cf","rules-backup-$date.tar","rules-backup-$date"));

  # Compress it.
    print STDERR "Warning: gzip command did not exit with status 0 when compressing backup file.\n"
      if (system("$gzip_bin","rules-backup-$date.tar"));

  # Change back to old directory (so it will work with -b <directory> as either an absolute or a relative path.
    chdir("$olddir") or die("Could not change directory to $olddir: $!\nExiting"); 

  # Move the archive to the backup directory.
    move("$tmpdir/rules-backup-$date.tar.gz", "$backup_dir/")
      or print STDERR "Warning: unable to move $tmpdir/rules-backup-$date.tar.gz to $backup_dir/: $!\n";

    print STDERR "saved as $backup_dir/rules-backup-$date.tar.gz.\n" unless ($quiet);
}



# Open new rules files and read the rules/other lines into the hashes %new_rules/%new_other.
# Also open old rules files and read the rules/other lines into the hashes %old_rules/%old_other.
# Rule hashes will be built like %new_rules{%filename}{sid} = rule
# *_other hashes will be built like %new_other{%filename} = @lines
# (we must keep track of the filenames since a rule may be moved from one ruleset to another, and we
# might have the latter disabled in snort.conf, so we want to be notified of such changes)

sub setup_rule_hashes
{
    my ($file, $line, @old_ruleset, @new_ruleset);

    foreach $file (@new_files) {
	open(NEW, "$tmpdir/rules/$file") or die("Could not open $tmpdir/rules/$file: $!\nExiting");
	@new_ruleset = <NEW>;
	close(NEW);

        foreach $line (@new_ruleset) {
	    if ($line =~ /$rule_regexp/) {
	        $new_rules{$file}{$2} = $line;			   # New rule line, add to %new_rules.
	    }
	    else {
		push(@{$new_other{$file}}, $line);		   # New non-rule line, add to %new_other.

	    }
        }

      # Also read in old rules file if it exists (i.e. if a file with that filename also exists in our output directory).
	if (-f "$outdir/$file") {
	    open(OLD, "$outdir/$file") or die("Could not open $outdir/$file: $!\nExiting"); 
	    @old_ruleset = <OLD>;
	    close(OLD);
	
	    foreach $line (@old_ruleset) {    
		if ($line =~ /$rule_regexp/) { 	
		    $old_rules{$file}{$2} = $line;		   # Old rule line, add to %old_rules.
		}
		else {
		    push(@{$old_other{$file}}, $line);             # Old non-rule line, add to %old_other.  
		}
	    }

        }
    }
}



# May the pig be with you.
# EOF
