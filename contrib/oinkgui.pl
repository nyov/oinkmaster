#!/usr/bin/perl -w

# $Id$ #

use strict;
use File::Spec;
use Tk;
use Tk::NoteBook;
use Tk::ROText;
use Tk::Balloon;
use Tk::BrowseEntry;


sub test_config();
sub show_version();
sub show_help();
sub update_rules();
sub clear_messages();
sub create_cmdline($);
sub fileDialog($ $);
sub load_config();
sub save_config();
sub update_file_label_color($ $ $);
sub create_fileSelectFrame($ $ $ $);
sub create_checkbutton($ $ $);
sub create_radiobutton($ $ $);
sub create_actionbutton($ $ $);
sub logmsg($ $);


my $version     = 'Oinkmaster GUI v0.1';

my %config;

my @oinkmaster_conf = qw(./oinkmaster.conf
                         /etc/oinkmaster.conf
                         /usr/local/etc/oinkmaster.conf
                        );


# List of URLs that will show up in the URL BrowseEntry.
my @urls = qw(http://www.snort.org/dl/rules/snortrules-stable.tar.gz
              http://www.snort.org/dl/rules/snortrules-current.tar.gz
             );

my $bgcolor        = 'Bisque3';
my $butcolor       = 'Bisque2';
my $actbutcolor    = 'Bisque2';
my $labelcolor     = 'Bisque1';


$config{careful}       = 0;
$config{enable_all}    = 0;
$config{check_removed} = 0;

$config{mode} = 'normal';

my $animate = 0;

$config{oinkmaster}      = "";
$config{oinkmaster_conf} = "";
$config{outdir}          = "";
$config{url}             = "";
$config{varfile}         = "";
$config{backupdir}       = "";

my $config_file     = "";


my %help = (

  # File locations.
    oinkscript   => 'Location of the executable oinkmaster script.',
    oinkconf     => 'The oinkmaster configuration file to use.',
    outdir       => 'Where to put the new rules. This shoudl be the directory where you '.
                    'store your existing rules.',

    url          => 'Alternate location of rules archive. '.
                    'If empty, the location in oinkmaster.conf is used.',
    varfile      => 'Variables that exist in downloaded snort.conf but not in '.
                    'this file will be added to it. Leave empty to skip.',
    backupdir    => 'Directory to put tarball of old rules before overwriting them. '.
                    'Leave empty to skip backup.',

  # Checkbuttons.
    careful      => 'In careful mode, Oinkmaster will just check for changes '.
                    'and not update anything.',
    enable       => 'Some rules may be commented out by default. '.
                    'This option will make Oinkmaster enable those rules.',
    removed      => 'Check for rules files that exist in the output directory but not '.
                    'in the downloaded rules archive.',

  # Action buttons.
    clear        => 'Clear current output messages.',
    exit         => 'Exit the GUI.',
    update       => 'Execute Oinkmaster to update the rules.',
    test         => 'Test current oinkmaster configuration. ' .
                    'If there are no fatal errors, you are ready to update the rules.',
    help         => 'Execute oinkmaster -h.',
    version      => 'Request version information from Oinkmaster.',
);



#### MAIN ####

select STDERR;
$| = 1;
select STDOUT;
$| = 1;


# Find out which oinkmaster config file to use.
foreach my $file (@oinkmaster_conf) {
    if (-e "$file") {
        $config{oinkmaster_conf} = $file;
        last;
    }
}

# Find out which oinkmaster.pl file to use.
foreach my $dir (File::Spec->path()) {
    my $file = "$dir/oinkmaster";
    if (-f "$file" && -x "$file") {
        $config{oinkmaster} = $file;
        last;
    } elsif (-f "$file.pl" && -x "$file.pl") {
        $config{oinkmaster} = "$file.pl";
        last;
    } 
}


# Find out where the GUI config file is (it's not required).
$config_file = "$ENV{HOME}/.oinkguirc" if ($ENV{HOME});


# Create main window.
my $main = MainWindow->new(
  -background => "$bgcolor",
  -title      => "$version"
);


my $out_frame = $main->Scrolled('ROText',
  -setgrid    => 'true',
  -scrollbars => 'e',
  -background => 'black',
  -foreground => 'white',
);

my $help_label = $main->Label(
    -relief     => 'groove',
    -background => "$labelcolor"
);

my $balloon = $main->Balloon(
    -statusbar => $help_label,
);


# Create notebook.
my $notebook = $main->NoteBook(
  -ipadx      => 6,
  -ipady      => 6,
  -background => 'Bisque2'
);


# Create tab with required files/dirs.
my $req_tab = $notebook->add("required",
  -label     => "Required files and directories",
  -underline => 0,
);


# Create frame with oinkmaster.pl location.
my ($oinkscript_frame, $oinkscript_label, $oinkscript_entry, $oinkscript_but) = 
  create_fileSelectFrame($req_tab, "Oinkmaster.pl", 'EXECFILE', \$config{oinkmaster});

$balloon->attach($oinkscript_frame, -statusmsg => $help{oinkscript});


# Create frame with oinkmaster.conf location.
my ($oinkconf_frame, $oinkconf_label, $oinkconf_entry, $oinkconf_but) = 
  create_fileSelectFrame($req_tab, "Oinkmaster.conf", 'ROFILE', \$config{oinkmaster_conf});

$balloon->attach($oinkconf_frame, -statusmsg => $help{oinkconf});


# Create frame with output directory. XXX must be able to select dir only.
my ($outdir_frame, $outdir_label, $outdir_entry, $outdir_but) = 
  create_fileSelectFrame($req_tab, "Output directory", 'WRDIR', \$config{outdir});

$balloon->attach($outdir_frame, -statusmsg => $help{outdir});



# Create tab with optional files/dirs.
my $opt_tab = $notebook->add("optional",
  -label     => "Optional files and directories",
  -underline => 0,
);


# Create frame with alternate URL location. XXX choice between stable/current/local.
my ($url_frame, $url_label, $url_entry, $url_but) = 
  create_fileSelectFrame($opt_tab, "Alternate URL", 'URL', \$config{url});

$balloon->attach($url_frame, -statusmsg => $help{url});


# Create frame with variable file.
my ($varfile_frame, $varfile_label, $varfile_entry, $varfile_but) = 
  create_fileSelectFrame($opt_tab, "Variable file", 'WRFILE', \$config{varfile});

$balloon->attach($varfile_frame, -statusmsg => $help{varfile});


# Create frame with backup dir location. XXX must be able to select dir only.
my ($backupdir_frame, $backupdir_label, $backupdir_entry, $backupdir_but) = 
  create_fileSelectFrame($opt_tab, "Backup directory", 'WRDIR', \$config{backupdir});

$balloon->attach($backupdir_frame, -statusmsg => $help{backupdir});


$notebook->pack(
  -expand => 'no',
  -fill   => 'x',
  -padx   => 5,
  -pady   => 5,
  -side   => 'top'
);


# Create the frame to the left.
my $left_frame = $main->Frame(
  -background => "$labelcolor", 
  -border     => '2'
)->pack(
  -side       => 'left',
  -fill       => 'y'
);


# Create "GUI settings" label.
$left_frame->Label(
  -text       => "GUI settings:",
  -background => "$labelcolor"
)->pack(
  -side       => 'top',
  -fill       => 'x'
);


create_actionbutton($left_frame, "Load saved settings",   \&load_config);
create_actionbutton($left_frame, "Save current settings", \&save_config);


# Create "options" label at the top of the left frame.
$left_frame->Label(
  -text       => "Options:", 
  -background => "$labelcolor"
)->pack(side  => 'top',
        fill  => 'x'
);


# Create checkbuttons in the left frame.
$balloon->attach(
  create_checkbutton($left_frame, "Careful mode", \$config{careful}),
  -statusmsg => $help{careful}
);

$balloon->attach(
  create_checkbutton($left_frame, "Enable all", \$config{enable_all}),
  -statusmsg => $help{enable}
);

$balloon->attach(
  create_checkbutton($left_frame, "Check for removed files", \$config{check_removed}),
  -statusmsg => $help{removed}
);


# Create "mode" label.
$left_frame->Label(
  -text       => "Mode:", 
  -background => "$labelcolor"
)->pack(side  => 'top',
        fill  => 'x'
);

# Create mode radiobuttons in the left frame.
create_radiobutton($left_frame, "�ber-quiet", \$config{mode});
create_radiobutton($left_frame, "quiet",      \$config{mode});
create_radiobutton($left_frame, "normal",     \$config{mode});
create_radiobutton($left_frame, "verbose",    \$config{mode});



# Create "activity messages" label.
$main->Label(
  -text       => "Output messages:", 
  -width      => '100', 
  -background => "$labelcolor"
)->pack(
  -side       => 'top',
  -fill       => 'x'
);



# Pack output frame.
$out_frame->pack(
  -expand     => 'yes',
  -fill       => 'both'
);


# Pack help label below output window.
$help_label->pack(
    -fill       => 'x',
);


# Create "actions" label.
$left_frame->Label(
  -text       => "Actions:",
  -background => "$labelcolor"
)->pack(
  -side       => 'top',
  -fill       => 'x'
);


# Create action buttons.

$balloon->attach(
  create_actionbutton($left_frame, "Show version", \&show_version), 
  -statusmsg => $help{version}
);

$balloon->attach(
  create_actionbutton($left_frame, "Show help", \&show_help),
  -statusmsg => $help{help}
);

$balloon->attach(
  create_actionbutton($left_frame, "Test configuration", \&test_config),
  -statusmsg => $help{test}
);

$balloon->attach(
  create_actionbutton($left_frame, "Update rules!", \&update_rules),
  -statusmsg => $help{update}
);

$balloon->attach(
  create_actionbutton($left_frame, "Clear messages", \&clear_messages),
  -statusmsg => $help{clear}
);

$balloon->attach(
  create_actionbutton($left_frame, "Exit", \&exit),
  -statusmsg => $help{exit}
);



# Now the fun begins.
if ($animate) {
    foreach (split(//, "Welcome to $version")) {
        logmsg("$_", 'MISC');
        $out_frame->after(5);
    }
} else {
    logmsg("Welcome to $version", 'MISC');
}

logmsg("\n\n", 'MISC');

# Load gui settings into %config.
load_config();


# Warn if any required file/directory is not set.
logmsg("No oinkmaster.pl set, please select one above!\n", 'ERROR')
  if ($config{oinkmaster} !~ /\S/);

logmsg("No configuration file set, please select one above!\n", 'ERROR')
  if ($config{oinkmaster_conf} !~ /\S/);

logmsg("Output directory is not set, please select one above!\n", 'ERROR')
if ($config{outdir} !~ /\S/);


logmsg("\n", 'MISC');
 
MainLoop;



#### END ####



sub fileDialog($ $)
{
    my $var_ref = shift;
    my $title   = shift;

    my $filename = $main->getOpenFile(-title => $title);
    $$var_ref = $filename if ($filename);
}



sub update_file_label_color($ $ $)
{
    my $label    = shift;
    my $filename = shift;
    my $type     = shift;

    $filename =~ s/^\s+//;
    $filename =~ s/\s+$//;

    unless ($filename) {
        $label->configure(-background => 'red');
        return (1);
    }

    if ($type eq "URL") {
        if ($filename =~ /^(?:http|ftp):\/\/.+\.tar\.gz$/) {
            $label->configure(-background => "#00e000");
        } elsif ($filename =~ /^(?:file:\/\/)*(.+\.tar\.gz)$/) {
            my $file = $1;
            if (-f "$file" && -r "$file") {
                $label->configure(-background => "#00e000");
            } else {
                $label->configure(-background => 'red');
            }
        } else {
            $label->configure(-background => 'red');
        }
    } elsif ($type eq "ROFILE") {
        if (-f "$filename" && -r "$filename") {
            $label->configure(-background => "#00e000");
        } else {
            $label->configure(-background => 'red');
        }
    } elsif ($type eq "EXECFILE") {
        if (-f "$filename" && -x "$filename") {
            $label->configure(-background => "#00e000");
        } else {
            $label->configure(-background => 'red');
        }
    } elsif ($type eq "WRFILE") {
        if (-f "$filename" && -w "$filename") {
            $label->configure(-background => "#00e000");
        } else {
            $label->configure(-background => 'red');
        }
    } elsif ($type eq "RODIR") {
        if (-d "$filename" && -r "$filename") {
            $label->configure(-background => "#00e000");
        } else {
            $label->configure(-background => 'red');
        }
    } elsif ($type eq "WRDIR") {
        if (-d "$filename" && -w "$filename") {
            $label->configure(-background => "#00e000");
        } else {
            $label->configure(-background => 'red');
        }
    } else {
       print STDERR "incorrect type ($type)\n";
       exit;
    }

    return (1);
}



sub create_checkbutton($ $ $)
{
    my $frame   = shift;
    my $name    = shift;
    my $var_ref = shift;
 
    my $button = $frame->Checkbutton(
      -text       => $name,
      -background => $butcolor,
      -variable   => $var_ref,
      -relief     => 'raise',
      -anchor     => 'w',
    )->pack(
      -fill       => 'x',
      -side       => 'top',
      -pady       => '1',
    );

    return ($button);
}



sub create_actionbutton($ $ $)
{
    my $frame    = shift;
    my $name     = shift;
    my $func_ref = shift;

    my $button = $frame->Button(
      -text       => "$name",
      -command    => sub { &$func_ref }, 
      -background => "$actbutcolor",
    )->pack(
      -fill       => 'x',
    );

    return ($button);
}



sub create_radiobutton($ $ $)
{
    my $frame    = shift;
    my $name     = shift;
    my $mode_ref = shift;
 
    my $button = $frame->Radiobutton(
      -text       => "$name",
      -background => "$butcolor",
      -variable   =>  $mode_ref,
      -relief     => 'raised',
      -anchor     => 'w',
      -value      => "$name",
    )->pack(
      -side       => 'top',
      -pady       => '1',
      -fill       => 'x',
    );

    return ($button);
}



# Create <label><entry><browsebutton> in given frame.
sub create_fileSelectFrame($ $ $ $) 
{
    my $win     = shift;
    my $name    = shift;
    my $type    = shift;  # FILE|DIR|URL
    my $var_ref = shift;

  # Create frame.
    my $frame = $win->Frame->pack(
      -padx => '2',
      -pady => '2',
      -fill => 'x'
    );

  # Create label.
    my $label = $frame->Label(
      -text       => $name,
      -width      => '16',
      -relief     => 'raised',
      -background => 'red'
    )->pack(
      -side       => 'left'
    );

my $entry;

if ($type eq 'URL') {
    $entry = $frame->BrowseEntry(
      -textvariable    => $var_ref,
      -background      => 'white',
      -width           => '80',
      -choices         => \@urls,
      -validate        => 'key',
      -validatecommand => sub { update_file_label_color($label, $_[0], $type) },
    )->pack(
      -side            => 'left',
      -expand          => 'yes',
      -fill            => 'x'
   );
} else {
    $entry = $frame->Entry(
      -textvariable    => $var_ref,
      -background      => 'white',
      -width           => '80',
      -validate        => 'key',
      -validatecommand => sub { update_file_label_color($label, $_[0], $type) },
    )->pack(
      -side            => 'left',
      -expand          => 'yes',
      -fill            => 'x'
   );

}



  # Create browse-button.
    my $but = $frame->Button(
      -text       => "browse ...",
      -background => "$actbutcolor",
      -command    => sub {
                            fileDialog($var_ref, $name);
                         }
    )->pack(
      -side       => 'left',
    );



    return ($frame, $label, $entry, $but);
}



sub logmsg($ $)
{
    my $text = shift;
    my $type = shift;

    return unless (defined($text));

    $out_frame->tag(qw(configure OUTPUT -foreground grey));
    $out_frame->tag(qw(configure ERROR  -foreground red));
    $out_frame->tag(qw(configure MISC   -foreground white));
    $out_frame->tag(qw(configure EXEC   -foreground bisque2));

    $out_frame->insert('end', "$text", "$type");
    $out_frame->see('end'); 
    $out_frame->update;
}



sub show_version()
{
    $config{oinkmaster} =~ s/^\s+//;
    $config{oinkmaster} =~ s/\s+$//;

    unless ($config{oinkmaster} && -x "$config{oinkmaster}") {
        logmsg("Location to oinkmaster.pl is not set correctly!\n\n", 'ERROR');
        return;
    }

    my $cmd = File::Spec->rel2abs($config{oinkmaster}) . " -V";
    logmsg("$cmd:\n", 'EXEC');
    my $output = `$cmd 2>&1` || "Could not execute $config{oinkmaster}: $!\n";
    logmsg("$output", 'OUTPUT');
    logmsg("$version by Andreas �stling <andreaso\@it.su.se>\n\n", 'OUTPUT');
}



sub show_help()
{
    $config{oinkmaster} =~ s/^\s+//;
    $config{oinkmaster} =~ s/\s+$//;

    unless ($config{oinkmaster} && -x "$config{oinkmaster}") {
        logmsg("Location to oinkmaster.pl is not set correctly!\n\n", 'ERROR');
        return;
    }

    my $cmd = File::Spec->rel2abs($config{oinkmaster}) . " -h";
    logmsg("$cmd:\n", 'EXEC');
    my $output = `$cmd 2>&1` || "Could not execute $config{oinkmaster}: $!\n";
    logmsg("$output\n", 'OUTPUT');
}



sub test_config()
{
    my @cmd;

    create_cmdline(\@cmd) || return;
    push(@cmd, "-T");
    logmsg("@cmd:\n", 'EXEC');

    if (open(OINK,"-|")) {
        while (<OINK>) {
            logmsg($_, 'OUTPUT');
        }
    } else {
        open(STDERR, '>&', 'STDOUT');
        exec(@cmd);
    }
    close(OINK);

    logmsg("\n", 'MISC');
}



sub clear_messages()
{
    $out_frame->delete('1.0','end');
    $out_frame->update;
}



sub update_rules()
{
    my @cmd;

    create_cmdline(\@cmd) || return;
    clear_messages();
    logmsg("@cmd:\n", 'EXEC');

    $main->Busy(-recurse => 1);

    if (open(OINK,"-|")) {
        while (<OINK>) {
            logmsg($_, 'OUTPUT');
            $main->update;
        }
    } else {
        open(STDERR, '>&', 'STDOUT');
        exec(@cmd);
    }
    close(OINK);
 
    logmsg("Done.\n\n", 'EXEC');
    $main->Unbusy;
}



sub create_cmdline($)
{
    my $cmd_ref = shift;

  # Clean leading/trailing whitespaces from all filenames.
    my @filename_vars = qw(
      oinkmaster oinkmaster_conf outdir varfile url backupdir
    );

    foreach my $var (@filename_vars) {
        next unless (exists($config{$var}));
        $config{$var} =~ s/^\s+//;
        $config{$var} =~ s/\s+$//;
    }
 
    unless ($config{oinkmaster} && -x "$config{oinkmaster}") {
        logmsg("Location to oinkmaster.pl is not set correctly!\n\n", 'ERROR');
        return (0);
    }

    unless ($config{oinkmaster_conf}) {
        logmsg("Location to configuration file is not set correctly!\n\n", 'ERROR');
        return (0);
    }

    unless ($config{outdir}) {
        logmsg("Output directory is not set!\n\n", 'ERROR');
        return (0);
    }

    push(@$cmd_ref, 
      File::Spec->rel2abs($config{oinkmaster}), 
      "-C", "$config{oinkmaster_conf}", 
      "-o", "$config{outdir}");

    push(@$cmd_ref, "-c")                       if ($config{careful});
    push(@$cmd_ref, "-e")                       if ($config{enable_all});
    push(@$cmd_ref, "-r")                       if ($config{check_removed});
    push(@$cmd_ref, "-q")                       if ($config{mode} eq "quiet");
    push(@$cmd_ref, "-Q")                       if ($config{mode} eq "�ber-quiet");
    push(@$cmd_ref, "-v")                       if ($config{mode} eq "verbose");
    push(@$cmd_ref, "-U", "$config{varfile}")   if ($config{varfile});
    push(@$cmd_ref, "-b", "$config{backupdir}") if ($config{backupdir});


  # Assume file:// if url prefix is missing.
    if ($config{url}) {
        my $url = $config{url};
        $url = "file://$url" unless ($url =~ /(?:http|ftp|file):\/\//);
        push(@$cmd_ref, "-u", "$url");
    }

    return (1);
}



# Load $config file into %config hash.
sub load_config()
{
    unless (defined($config_file) && $config_file) {
        logmsg("Unable to determine config file location, is your \$HOME set?\n\n", 'ERROR');
        return;
    }

    unless (-e "$config_file") {
        logmsg("$config_file does not exist, keeping current/default settings\n\n", 'MISC');
        return;
    }

    logmsg("Loading GUI settings from $config_file\n\n", 'MISC');

    unless (open(RC, "<$config_file")) {
        logmsg("Could not open $config_file for reading: $!\n", 'ERROR');
        return;
    }

    while (<RC>) {
        next unless (/^(\S+)=(.*)/);
        $config{$1} = $2;
    }

    close(RC);
}



# Save %config into file $config.
sub save_config()
{
    unless (defined($config_file) && $config_file) {
        logmsg("Unable to determine config file location, is your \$HOME set?\n\n", 'ERROR');
        return;
    }

    logmsg("Saving current GUI settings to $config_file\n\n", 'MISC');

    unless (open(RC, ">$config_file")) {
        logmsg("Could not open $config_file for writing: $!\n", 'ERROR');
        return;
    }

    foreach my $option (sort(keys(%config))) {
        print RC "$option=$config{$option}\n";
    }

    close(RC);
}
