#!/usr/bin/perl -w



use strict;
use Getopt::Std;
use File::Copy;
use POSIX qw(strftime);
use Cwd;



use vars
qw (
      $opt_V $opt_h $opt_o $opt_u $opt_v $opt_q $opt_w $opt_t 
      $opt_i $opt_q $opt_c $opt_b $opt_g $opt_a $opt_r
   );   

my (
      $out_dir, $old_dir, $file, $old_rule, $new_rule, $sid,
      $added_files, $removed_files, $msg, $start_date
   );

my (
      @new_rules_files, @modified_files
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



my $version 	      = 'Oinkmaster v0.3 by Andreas Östling, andreaso@it.su.se.';

# Some defaults.
my $url               = "http://www.snort.org/downloads/snortrules.tar.gz";  		# Default URL.
my $path	      = "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"; # Set PATH.
my $wget_bin          = "wget";		     # Default name of wget binary (will be searched for in $path).
my $gzip_bin	      = "gzip";              # Same goes for the gzip binary.
my $tar_bin           = "tar";		     # Same goes for the tar binary.
my $conf_file         = "oinkmaster.conf";   # Default configuration file.
my $tmpdir            = "/tmp";              # Temporary directory. Change this if needed. 
my $outfile           = "snortrules.tar.gz"; # What to call the local archive file after download.

my $attempts          = 5;      # Number of default download attempts before giving up.
my $careful           = 0;      # Not careful mode by default.
my $verbose           = 0;      # Not verbose mode by default.
my $quiet	      = 0;      # Not quiet mode by default.
my $backup_dir        = 0;      # Default is not to backup old rules.
my $check_removed     = 0;      # Default is not to check for files possibly removed from the archive.
my $rules_changed     = 0;	# No rule changes yet.
my $other_changed     = 0;	# No other changes yet.
my $something_changed = 0;      # No changes at all yet.

# Regexp to match a Snort rule line. The msg string will go into $1, and the sid will go into $2.
my $snortrule_regexp = '^\s*#*\s*(?:alert|log|pass) .+msg\s*:\s*"(.+?)"\s*;.+sid\s*:\s*(\d+)\s*;';

# Regexp to match filenames we're interested in.
my $interesting_files = '\.rules$|\.config$|\.conf$|\.map$|\.txt$';



#### MAIN ####

select(STDERR); $| = 1;         # No buffering.
select(STDOUT); $| = 1;

$start_date = scalar(localtime);

# Check command line arguments and die we don't like them.
parse_cmdline;

# Create empty temporary directory.
mkdir("$tmpdir",0700) or die("Could not create temporary directory $tmpdir: $!\nExiting");      

# Open config file and read sids to be disabled (#commented) into %sid_disable_list
# and also read files to be skipped into %file_ignore_list.
open(CONF, $conf_file) or die("Could not open $conf_file: $!\nExiting");
@_ = <CONF>;
close(CONF);

for $_ (0 .. $#_) {					   # For each line in the config file...
    $_[$_] =~ s/\s*\#.*//;				   # Remove #comments.
    next unless ($_[$_] =~ /\S/);			   # Skip blank lines.

    if ($_[$_] =~ /^\s*sid\s*(\d+)/i) {			   # Try to grab a sid.
        $sid_disable_list{$1}++;			   # Put this sid in the disable list.
    }
    elsif ($_[$_] =~ /^\s*file\s*(\S+)/i) {  		   # Try to grab a file to be ignored.
	$verbose && print STDERR "Adding file to ignore list: $1.\n";	
	$file_ignore_list{$1}++;			   # Put this file in the ignore list.
    }
    else {						   # Invalid line.
	print STDERR "Warning: line " , $_ +1 , " in $conf_file is invalid (skipping line).\n";
    }
}

# Pull down the rules archive. Die if wget doesn't exit with status level 0.
if ($quiet) {     	        			   # Execute wget command in quiet mode. 
    if (system("$wget_bin","-q","-nv","-t",$attempts,"-O","$tmpdir/$outfile","$url")) {
	print STDERR "Unable to download rules: fatal error or maximum number of download attempts reached.\n";
	die("Consider running in non-quiet mode if the problem persists.\n\nExiting");
    }
}
else {   		        			   # Execute wget command in non-quiet mode.
    print STDERR "Downloading rules archive from $url...\n";
    die("Unable to download rules: fatal error or maximum number of download attempts reached.\n\nExiting")
      if (system("$wget_bin","-nv","-t",$attempts,"-O","$tmpdir/$outfile","$url"));
}

# Change to temporary directory and verify/unpack archive.
# This will hopefully leave us with a directory called "rules/" in the temporary directory,
# containing the new rules.
$old_dir = getcwd or die("Could not get current directory: $!\nExiting");  # Save old dir so we can change back.
chdir("$tmpdir") or die("Could not change directory to $tmpdir: $!\nExiting");

if (-s "$outfile") {			   		   # It's a good start if it is larger than 0 bytes.
    unpack_snortarchive($outfile);
}
else {
    die("Failed to get $url! (The file \"$tmpdir/$outfile\" doesn't exist or hasn't non-zero size)\n\nExiting");
}

# Change back.
chdir("$old_dir") or die("Could not change directory to $tmpdir: $!\nExiting");


# Add interesting filenames from the downloaded archive to the list of new files,
# unless filename exists in %file_ignore_list.

opendir(NEWRULES, "$tmpdir/rules") or die("Could not open directory $tmpdir/rules: $!\nExiting");
@_ = readdir(NEWRULES);
closedir(NEWRULES);
 
foreach $_ (@_) {
    push(@new_rules_files, $_)
      if (/$interesting_files/ && !exists($file_ignore_list{$_}));
}

# Make sure there is still at least one file in the archive that we care about.
$_ = $#new_rules_files + 1;  # (ignored files are not counted)
if ($_ < 1) {
    die("The rules archive does not contain any rules files.\n\nExiting");
}
else {
    print STDERR "Found $_ interesting file(s) in archive.\n" 
      unless ($quiet);
}

fix_comments;		# Disable rules listed in the config file.
setup_rule_hashes;  	# Read rules and other lines into %new_rules/%old_rules and %new_other/%old_other.

print STDERR "Comparing your old files to the new ones, hang on...\n" unless ($quiet);

# Check for added files.
FILELOOP:foreach $file (@new_rules_files) {
  # It's a new file if we don't have a file with that filename in our output directory.
    unless (exists($old_rules{$file}) || exists($old_other{$file})) {
	$added_files .= "    -> $file\n";
	unless ($careful) {
	    move("$tmpdir/rules/$file", "$out_dir/$file")  # New file, move to $out_dir/.
	      or die("Could not move $tmpdir/rules/$file to $out_dir/$file: $!\nExiting");
	}
	next FILELOOP;	  # No need to check for changes, just jump to the next new file.
    }

    undef(%printed);	  # This one will tell us if the filename info has been printed or not.

  # Time to compare the old rules files to the new ones.
  # For each rule in the new rule set, check if the rule also exists in the old rule set. 
  # If it does then check if it has been modified, but if it doesn't, it must have been added.

    foreach $sid (keys(%{$new_rules{$file}})) { 		# For each sid in the new rules file...
	$new_rule = $new_rules{$file}{$sid};			# Save the rule in $new_rule for easier access.

	if (exists($old_rules{$file}{$sid})) {			# Does this sid also exist in the old rules file?
	    $old_rule = $old_rules{$file}{$sid};		# Yes. Put old rule in $old_rule.

            unless ($old_rule eq $new_rule) {			# Do they match?
		$rules_changed = 1;                             # Nope. Let's check what has been changed.

                if ("#$old_rule" eq $new_rule) {		# Rule disabled? (if only "#" has been prepended).
		    fix_fileinfo("removed_dis", $file);		# Add filename banner, unless already done.
		    $changes{removed_dis} .= "       $new_rule";
                }
                elsif ($old_rule eq "#$new_rule") {		# Rule enabled? (if only leading "#" has been removed.
		    fix_fileinfo("added_ena", $file); 
                    $changes{added_ena} .= "       $new_rule";
                }
                elsif ($old_rule =~ /^\s*#/ && $new_rule !~ /^\s*#/) {  # Rule enabled and also modified?
		    fix_fileinfo("added_ena_mod", $file);
		    $changes{added_ena_mod} .= "       Old: $old_rule       New: $new_rule"; 
                }
                elsif ($old_rule !~ /^\s*#/ && $new_rule =~ /^\s*#/) {	# Rule disabled and also modified?
		    fix_fileinfo("removed_dis_mod", $file); 
		    $changes{removed_dis_mod} .= "       Old: $old_rule       New: $new_rule"; 
                }
                elsif ($old_rule =~ /^\s*#/ && $new_rule =~ /^\s*#/) {	# Commented (inactive) rule modified?
		    fix_fileinfo("modified_inactive", $file); 
		    $changes{modified_inactive} .= "       Old: $old_rule       New: $new_rule";
                }
                else {							# Active rule modified?
		    fix_fileinfo("modified_active", $file);  
		    $changes{modified_active} .= "       Old: $old_rule       New: $new_rule";
                }

            }
	}
        else {                  # Could not find this sid in the old rules file so it must have been added.
	    fix_fileinfo("added_new", $file);
	    $changes{added_new} .= "       $new_rule";
	    $rules_changed = 1;
        }
    }

  # Check for removed rules (i.e. sids that exist in the old rules file but not in the new one).
    foreach $sid (keys(%{$old_rules{$file}})) {
	unless (exists($new_rules{$file}{$sid})) {
	    $old_rule = $old_rules{$file}{$sid};
	    fix_fileinfo("removed_del", $file);  
	    $changes{removed_del} .= "       $old_rule"; 
	    $rules_changed = 1;
        }
    }  

  # Now check for other changes (lines that aren't Snort rules).
  # (if a line exists several times, it will be considered as found even if one of them has been added/removed,
  # but that's probably no big deal...)

  # First check for added lines.
    foreach $_ (@{$new_other{$file}}) {
	unless (find_line($_, @{$old_other{$file}})) {	# Does this line also exist in the old rules file?
	    fix_fileinfo("other_added", $file);		# Nope, it's an added line.
	    $changes{other_added} .= "       $_";
	    $other_changed = 1; 
	} 
    }

  # Check for removed lines.
    foreach $_ (@{$old_other{$file}}) {
        unless (find_line($_, @{$new_other{$file}})) {  # Does this line also exist in the new rules file?
            fix_fileinfo("other_removed", $file);       # Nope, it's a removed line.
            $changes{other_removed} .= "       $_";
            $other_changed = 1;
        }
    }
}

# If -r was specified, check for interesting files that exist in the output directory but
# not in the rules archive, i.e. files that may have been removed from the rules archive.

if ($check_removed) {
    opendir(OLDRULES, "$out_dir") or die("Could not open directory $out_dir: $!\nExiting");
    @_ = readdir(OLDRULES);
    closedir(OLDRULES);

    foreach $_ (@_) {
	$removed_files .= "    -> $_\n"
	  if (/$interesting_files/ && !exists($new_rules{$_}) && !exists($new_other{$_})
              && !exists($file_ignore_list{$_}));
    }
}


# Update files listed in @modified_files (move the new files from the temporary directory to
# our -o <outout directory>, unless we're running in careful mode.
# Also create backup first if running with -b.

if ($rules_changed || $other_changed) {
    if ($careful) {
	print STDERR "Running in careful mode - not updating any files.\n";
	print STDERR "No need to backup old files, skipping.\n" if ($backup_dir) && (!$quiet);
    }
    else {
	backup_rules if ($backup_dir);					# Create backup if -b.
	print STDERR "Updating file(s) in directory \"$out_dir/\":" unless ($quiet);

      # Move each modified file from the temporary directory to the output directory. 
	foreach $_ (@modified_files) {
	    print STDERR " $_" unless ($quiet);
	    move("$tmpdir/rules/$_", "$out_dir/$_")
	      or die("Could not move $tmpdir/rules/$_ to $out_dir/$_: $!\nExiting")
	}
	print STDERR ".\n" unless ($quiet);   
    }
} 
else {
    print STDERR "No updates - no need to backup old files, skipping.\n"
      if ($backup_dir && !$quiet);
}

# Remove temporary directory.
system("/bin/rm","-r","-f","$tmpdir")
  and print STDERR "Warning: error removing temporary directory $tmpdir.\n";

# Time to print the results.

$something_changed = 1
  if ($rules_changed || $other_changed || defined($added_files) || defined($removed_files));

unless (!$something_changed && $quiet) {	# Skip if quiet mode and nothing had changed.

    print "\n[***] Results from Oinkmaster started $start_date [***]\n";
    print "\nNote: Oinkmaster was running in careful mode - no files were really updated or added.\n"
      if ($careful && $something_changed);

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
    }
    else {
	print "    None.\n";   
    }

  # Print non-rule changes.
    print "\n[*] Non-rule lines added/removed/modified: [*]\n";
    if ($other_changed) {
	print "\n  [+++]       Added line(s):       [+++]\n $changes{other_added}"
	  if (exists($changes{other_added}));
	print "\n  [---]      Removed line(s):      [---]\n $changes{other_removed}"
	  if (exists($changes{other_removed}));
	print "\n";
    }
    else {
	print "    None.\n";
    }

  # Print list of added files.
    if (defined($added_files)) {
	print "\n[*] Added files (consider updating your Snort configuration file to include them): [*]\n" .
	      "$added_files";
    }
    else {
	 print "\n[*] Added files: [*]\n" .
	       "    None.\n"; 
    }

  # Print list of deleted files if running with "-r".
    if ($check_removed) {
	if (defined($removed_files)) {
	    print "\n[*] Possibly removed files (consider removing them from your system and snort.conf as well): [*]\n" .
	          "$removed_files";
	}
	else {
	    print "\n[*] Files possibly removed from archive: [*]\n" .
		  "    None.\n";
	}
    }

    print "\n";
}


#### END OF MAIN ####



# Parse the command line and do some sanity checking.
sub parse_cmdline
{
    my $cmdline_ok = getopts('ho:Vvu:w:t:i:qcb:g:a:r');

    usage 	      if (defined($opt_h));		# Show usage info and quit if running with -h.
    die("$version\n") if (defined($opt_V));		# Show version and quit if running with -V.
    usage unless ($cmdline_ok);				# Show usage info and quit if we don't like the command line.     

    if (defined($opt_o)) {				# -o <output directory>, the only required option.
	$out_dir = $opt_o;
    }
    else {						# -o wasn't specified so show usage info and die.
	print STDERR "You must specify where to put the rules with -o <output directory>.\n\n";
	usage;
    }

#    die("Don't run $0 as root!\n\nExiting") if (!$>); 
 
    $url = $opt_u if (defined($opt_u));         	# Use URL specified with -u <URL> instead of the default.

  # URL must start with http:// or ftp://
    die("\"$url\" is not a valid URL (It must start with \"http://\" or \"ftp://\")\n\nExiting")
      unless ($url =~ /^http:\/\/\S+/ || $url =~ /^ftp:\/\/\S+/);

    $verbose           = 1      if (defined($opt_v));  	 # -v (verbose mode).
    $quiet             = 1      if (defined($opt_q));    # -q (quiet mode).
    $careful           = 1      if (defined($opt_c));    # -c (careful mode).
    $check_removed     = 1      if (defined($opt_r));    # -r (check for removed files).
    $backup_dir        = $opt_b if (defined($opt_b));    # -b <backup directory>
    $wget_bin          = $opt_w if (defined($opt_w));    # -w <wget binary>.
    $gzip_bin          = $opt_g if (defined($opt_g));    # -g <gzip binary>.
    $tar_bin           = $opt_t if (defined($opt_t));    # -t <tar binary>.
    $conf_file         = $opt_i if (defined($opt_i));    # -i <configuration file>.   
    $attempts          = $opt_a if (defined($opt_a));    # -a <attempts>.

  # Make sure we have the 'which' command.
    die("Working 'which' binary not found (path used: $path).\n\nExiting")
      if (system("which which >/dev/null 2>&1"));

  # Check for wget.
    die("wget binary not found, try a different path/filename with the -w argument.\n\nExiting")
      if (system("which \"$wget_bin\" >/dev/null 2>&1"));

  # Check for tar.
    die("tar binary not found, try a different path/filename with the -t argument.\n\nExiting")
      if (system("which \"$tar_bin\" >/dev/null 2>&1"));

  # Check for gzip.
    die("gzip binary not found, try a different path/filename with the -g argument.\n\nExiting")
      if (system("which \"$gzip_bin\" >/dev/null 2>&1"));

  # Make sure that the config file exists.
    unless (-f "$conf_file") {
        print STDERR "The file \"$conf_file\" does not exist. Please specify correct path/filename with -i <configuration file>.\n";
        print STDERR "Just create an empty file If you don't want to disable any rules/files at all.\n";
        print STDERR "Rename your \"rules.ignore\" to \"$conf_file\" if you just upgraded to Oinkmaster 0.3.\n";
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
    die("The directory \"$out_dir\" doesn't exist or isn't writable by you.\n\nExiting")
      if (! -d "$out_dir" || ! -w "$out_dir");

    $out_dir    =~ s/\/$//;			# Remove possible trailing slash (just for cosmetic reasons).
    $backup_dir =~ s/\/$//;

  # Make sure the backup directory exists and is writable if running with -b.
    die("The backup directory \"$backup_dir\" doesn't exist or isn't writable by you.\n\nExiting")
      if ($backup_dir && (! -d "$backup_dir" || ! -w "$backup_dir"));

  # Can't use both -q and -v.
    die("Both quiet mode and verbose mode at the same time doesn't make sense.\n\nExiting")
      if ($quiet && $verbose); 

  # Make sure number of download attempts looks ok.
    if (defined($opt_a)) { 
        die("\"$attempts\" is not a valid number of download attempts (should be 1-9).\n\nExiting")
	  if ($attempts !~ /^\d$/ || $attempts < 1);
    }
}



# Display usage information and exit.
sub usage
{
    select(STDERR);

    print "$version\n";
    print "Usage:\n";
    print "$0 -o <output directory> [options]\n\n";
    print "-o <output directory> Where to put the new rules files. This should be the\n";
    print "                      directory where you store your snort.org rules.\n";
    print "                      The new rules files will be compared to the ones in here.\n";
    print "                      Note that your current rules files will then be overwritten\n";
    print "                      by the new ones if they had been modified.\n";
    print "\nOptions:\n";
    print "-v                    Verbose mode - gives some more output.\n";
    print "-c                    Careful mode - don't update any rules, just download the new\n";
    print "                      rules and check for differences.\n";
    print "-r                    Check for rules files that exist in the output directory\n";
    print "                      but not in the downloaded rules archive (i.e. files that may\n";
    print "                      have been removed from the archive).\n";
    print "-a <attempts>         Maximum number of download attempts before giving up.\n";
    print "                      Must be a number between 1 and 9. Default is $attempts.\n";
    print "-b <directory>        If any rules file had changed, backup the old ones (from\n";
    print "                      <output directory>) to <directory> before updating them.\n";
    print "-i <config file>      AKA the \"ignore file\", the file containing information about\n";
    print "                      the rules/files that should be disabled/ignored.\n";
    print "                      Default is $conf_file.\n";
    print "-u <URL>              Get rules archive from this URL (http:// or ftp://) instead of\n";
    print "                      the default, $url.\n";
    print "                      This file must be in .tar.gz format and have the rules\n";
    print "                      files in a directory called \"rules/\" in it.\n";
    print "-w <wget>             Where to find the wget binary if its in a special location\n";
    print "                      (e.g. \"-w /opt/local/bin/wget\").\n";
    print "-g <gzip>             Same but for gzip.\n";
    print "-t <tar>              Same but for tar.\n";
    print "-q                    Quiet mode. No output unless something had changed.\n";
    print "                      Warnings and errors will still be printed.\n";
    print "\nOther:\n";
    print "-V                    Show version and exit.\n";
    print "-h                    Show help and exit.\n";

    select(STDOUT);
    exit(1);
}



# Open each new rules file, #comment rules listed in the config file, and write rules file back to disk. 
sub fix_comments
{
    my($rulefile, @rules, $line, $sid, $num);

    $num = 0;						# Keep track of number of disabled rules.

    print STDERR "Fixing rules to be disabled...\n" unless ($quiet);

    foreach $rulefile (@new_rules_files) {

      # Make sure it's a regular file.    
	die("$rulefile isn't a regular file.\n\nExiting") 
	  unless (-f "$tmpdir/rules/$rulefile" && ! -l "$tmpdir/rules/$rulefile");  

	open(RULES_IN, "$tmpdir/rules/$rulefile") or die("Could not open $tmpdir/rules/$rulefile: $!\nExiting");
	@rules = <RULES_IN>;
	close(RULES_IN);  

	open(RULES_OUT, ">$tmpdir/rules/$rulefile") 	# Write back to the same file.
          or die("Could not open $tmpdir/rules/$rulefile for writing: $!\nExiting");

	LINELOOP:foreach $line (@rules) {
	    unless ($line =~ /$snortrule_regexp/) {	# Only care about Snort rule lines, other
	        print RULES_OUT $line;			# lines will just be put right back into the file.
	        next LINELOOP;
	    }

	    ($msg, $sid) = ($1, $2);			# Grab msg string and the sid from the rule.

	    if (exists($sid_disable_list{$sid})) {   	# Should this sid be disabled?
	        if ($verbose) {				
		    $_ = $rulefile;
		    $_ =~ s/.+\///;			# Remove path, just keep the filename.
		    $_ = sprintf("Disabling sid %-5s in file %-20s (%s)\n", $sid, $_, $msg);
		    print STDERR "$_";
	        }
	        $line = "#$line" unless ($line =~ /^\s*#/); # Comment this rule, unless already done by default.
		$num++;
	    }
 	    else {			 # Sid was not listed in the config file.
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
# It's extremely slow, but who cares.
sub find_line
{
    my $line = shift;	# Line to look for.
    my @arr  = @_;	# Array to look in.

    return 1 unless ($line =~ /\S/);                       # Skip blank lines (always consider them as found).
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

    unless (exists($printed{$type})) {			       # Filename info already added?
	$changes{$type} = "   -> In file \"$filename\":\n";    # Nope, add it.
	$printed{$type}++;				       # So we know it has now been added.
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

  # Run integrity check (gzip -t) on the gzip file.
    die("Integrity check on gzip file failed (file transfer failed or file in URL not in gzip format?)\n\nExiting")
      if (system("$gzip_bin","-t","$archive")); 

  # Unpack it.
    system("$gzip_bin","-d","$archive") and die("Unable to unpack $archive.\n\nExiting");

  # Suffix has now changed from .tar.gz to .tar.
    $archive =~ s/\.gz$//;

  # Run integrity check on the tar file (by doing a "tar tf" on it and checking the return value).
    die("Integrity check on tar file failed (file transfer failed or file in URL not a compressed tar file?)\n\nExiting")
      if (system("tar tf \"$archive\" >/dev/null"));

  # Look for uncool stuff in the archive.
    if (open(TAR,"-|")) {
        @tar = <TAR>;				# Read output of the "tar vtf" command into @tar.
    }
    else {
        exec("$tar_bin","vtf","$archive")
          or die("Unable to execute untar/unpack command: $!\nExiting");
    }

    foreach $_ (@tar) {
      # We don't want to have any weird characters in the tar file.
	die("Forbidden characters in tar archive: refuse to unpack file.\nOffending file/line:\n$_\nExiting")
	  if (/[^$ok]/);
      # We don't want to unpack any "../../" junk.
	die("Error: file in tar archive contains \"..\" in filename: refuse to unpack file.\nOffending file/line:\n$_\nExiting")
	  if (/\.\./);
      # Links in the tar archive are not allowed (should be detected because of illegal chars above though).
	die("Error: file in tar archive contains link: refuse to unpack file.\nOffending file/line:\n$_\nExiting")
 	  if (/->/ || /=>/ || /==/);
    }

  # Looks good. Now we can untar it.
    print STDERR "Rules successfully downloaded, unpacking...\n" unless ($quiet); 

    die("Failed to untar $archive, broken download?\n\nExiting")
      if system("$tar_bin","xf","$archive");

    die("No \"rules/\" directory found in tar file.\n\nExiting")
      unless (-d "rules");
}



# Backup old files into -b <directory>.
sub backup_rules
{
    my ($date, $tmpbackupdir, @files, $old_dir);

    print STDERR "Backing up old rules...\n" unless ($quiet);

    $date         = strftime("%Y%m%d-%H%M", localtime);
    $tmpbackupdir = "$tmpdir/rules-backup-$date";

    mkdir("$tmpbackupdir", 0700) or die("Could not create directory $tmpbackupdir: $!\nExiting");

  # Copy old interesting files in $out_dir into our temporary directory.
    opendir(OLDFILES, "$out_dir") or die("Could not open directory $out_dir: $!\nExiting");
    @_ = readdir(OLDFILES);
    closedir(OLDFILES);

    foreach $_ (@_) {
	copy("$out_dir/$_", "$tmpbackupdir/") or print STDERR "Warning: error copying $out_dir/$_ to $tmpbackupdir: $!"
	  if (/$interesting_files/);
    }

  # Change directory to $tmpdir (so we'll be right below the directory where we have our rules to be backed up).
    $old_dir = getcwd or die("Could not get current directory: $!\nExiting"); 	# So we can change back.
    chdir("$tmpdir") or die("Could not change directory to $tmpdir: $!\nExiting"); 

  # Execute tar command. 
  # This will archive "rules-backup-$date/" into the file rules-backup-$date.tar, placed in $tmpdir.
    print STDERR "Warning: tar command did not exit with status 0 when archiving backup files.\n"
      if (system("$tar_bin","cf","rules-backup-$date.tar","rules-backup-$date"));

  # Compress it.
    print STDERR "Warning: gzip command did not exit with status 0 when compressing backup file.\n"
      if (system("$gzip_bin","rules-backup-$date.tar"));

  # Change back to old directory (so it will work with -b <directory> as either an absolute or a relative path.
    chdir("$old_dir") or die("Could not change directory to $old_dir: $!\nExiting"); 

  # Move the archive to the backup directory.
    move("$tmpdir/rules-backup-$date.tar.gz", "$backup_dir/")
      or print STDERR "Warning: unable to move $tmpdir/rules-backup-$date.tar.gz to $backup_dir/: $!\n";

    print STDERR "Saved backup as $backup_dir/rules-backup-$date.tar.gz.\n" unless ($quiet);
}



# Open new files and read the rules/other lines into the hashes %new_rules/%new_other.
# Also open old files and read the rules/other lines into the hashes %old_rules/%old_other.
# Rule hashes will be built like %new_rules{%filename}{sid} = rule
# *_other hashes will be built like %new_other{%filename} = @lines
# (we must keep track of the filenames since a rule may be moved from one file to another, and we
# might have the latter disabled in snort.conf, so we want to be notified of such changes)

sub setup_rule_hashes
{
    my ($file, $line, @old_ruleset, @new_ruleset);

    foreach $file (@new_rules_files) {
	open(NEW, "$tmpdir/rules/$file") or die("Could not open $tmpdir/rules/$file: $!\nExiting");
	@new_ruleset = <NEW>;
	close(NEW);

        foreach $line (@new_ruleset) {
	    if ($line =~ /$snortrule_regexp/) {
	        $new_rules{$file}{$2} = $line;			   # Rule line, add to %new_rules.
	    }
	    else {
		push(@{$new_other{$file}}, $line);		   # Non-rule line, add to %new_other.

	    }
        }

      # Also read in old file if it exists 
      # (i.e. if a file with that filename also exists in our output directory).
	if (-f "$out_dir/$file") {
	    open(OLD, "$out_dir/$file") or die("Could not open $out_dir/$file: $!\nExiting"); 
	    @old_ruleset = <OLD>;
	    close(OLD);
	
	    foreach $line (@old_ruleset) {    
		if ($line =~ /$snortrule_regexp/) { 	
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
