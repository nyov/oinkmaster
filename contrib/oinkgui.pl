#!/usr/bin/perl -w

# $Id$ #

use strict;
use File::Spec;
use Tk;
use Tk::Balloon;
use Tk::BrowseEntry;
use Tk::FileSelect;
use Tk::NoteBook;
use Tk::ROText;


sub test_config();
sub show_version();
sub show_help();
sub update_rules();
sub clear_messages();
sub create_cmdline($);
sub fileDialog($ $ $ $);
sub load_config();
sub save_config();
sub update_file_label_color($ $ $);
sub create_fileSelectFrame($ $ $ $ $ $);
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

# Graphical editors to look for.
my @editors = qw (kwrite kate kedit gedit xemacs xedit notepad wordpad);

# List of URLs that will show up in the URL BrowseEntry.
my @urls = qw(http://www.snort.org/dl/rules/snortrules-stable.tar.gz
              http://www.snort.org/dl/rules/snortrules-current.tar.gz
             );


my %color = (
    background        => 'Bisque3',
    button            => 'Bisque2',
    label             => 'Bisque1',
    notebook          => 'Bisque2',
    file_label_ok     => '#00e000',
    file_label_not_ok => 'red',
    out_frame_fg      => 'white',
    out_frame_bg      => 'black',
);



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

my $gui_config_file     = "";
my $editor = "";


my %help = (

  # File locations.
    oinkscript   => 'Location of the executable Oinkmaster script (oinkmaster.pl).',
    oinkconf     => 'The Oinkmaster configuration file to use.',
    outdir       => 'Where to put the new rules. This should be the directory where you '.
                    'store your rules.',

    url          => 'Alternate location of rules archive to download/copy. '.
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
    test         => 'Test current Oinkmaster configuration. ' .
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
    if (-f "$file" && (-x "$file" || $^O eq 'MSWin32')) {
        $config{oinkmaster} = $file;
        last;
    } elsif (-f "$file.pl" && (-x "$file" || $^O eq 'MSWin32')) {
        $config{oinkmaster} = "$file.pl";
        last;
    } 
}

# Find out which editor to use.
EDITOR:foreach my $ed (@editors) {
    foreach my $dir (File::Spec->path()) {
        my $file = "$dir/$ed";
        if (-f "$file" && -x "$file") {
            $editor = $file;
            last EDITOR;
        } elsif (-f "$file.exe" && -x "$file.exe") {
            $editor = $file;
            last EDITOR;
        }
    } 
}


# Find out where the GUI config file is (it's not required).
if ($ENV{HOME}) {
    $gui_config_file = "$ENV{HOME}/.oinkguirc"
} elsif ($ENV{HOMEDRIVE} && $ENV{HOMEPATH}) {
   $gui_config_file = "$ENV{HOMEDRIVE}$ENV{HOMEPATH}\\.oinkguirc";
}


# Create main window.
my $main = MainWindow->new(
  -background => "$color{background}",
  -title      => "$version"
);


my $out_frame = $main->Scrolled('ROText',
  -setgrid    => 'true',
  -scrollbars => 'e',
  -background => $color{out_frame_bg},
  -foreground => $color{out_frame_fg},
);

my $help_label = $main->Label(
    -relief     => 'groove',
    -background => "$color{label}"
);

my $balloon = $main->Balloon(
    -statusbar => $help_label,
);


# Create notebook.
my $notebook = $main->NoteBook(
  -ipadx      => 6,
  -ipady      => 6,
  -background => $color{notebook},
);


# Create tab with required files/dirs.
my $req_tab = $notebook->add("required",
  -label     => "Required files and directories",
  -underline => 0,
);


# Create frame with oinkmaster.pl location.
my $types = [
  ['Oinkmaster script', 'oinkmaster.pl'],
  ['All files',         '*'            ]
];
my $oinkscript_frame = 
  create_fileSelectFrame($req_tab, "oinkmaster.pl", 'EXECFILE', \$config{oinkmaster}, 'NOEDIT', $types);

$balloon->attach($oinkscript_frame, -statusmsg => $help{oinkscript});


# Create frame with oinkmaster.conf location.
$types = [
  ['configuration files', '.conf'],
  ['All files',           '*'    ]
];
my $oinkconf_frame = 
  create_fileSelectFrame($req_tab, "oinkmaster.conf", 'ROFILE', \$config{oinkmaster_conf}, 'EDIT', $types);

$balloon->attach($oinkconf_frame, -statusmsg => $help{oinkconf});


# Create frame with output directory.
my $outdir_frame =
  create_fileSelectFrame($req_tab, "output directory", 'WRDIR', \$config{outdir}, 'NOEDIT', undef);

$balloon->attach($outdir_frame, -statusmsg => $help{outdir});



# Create tab with optional files/dirs.
my $opt_tab = $notebook->add("optional",
  -label     => "Optional files and directories",
  -underline => 0,
);


# Create frame with alternate URL location.
$types = [
  ['compressed tar files', '.tar.gz']
];
my $url_frame =
  create_fileSelectFrame($opt_tab, "Alternate URL", 'URL', \$config{url}, 'NOEDIT', $types);

$balloon->attach($url_frame, -statusmsg => $help{url});


# Create frame with variable file.
$types = [
  ['Snort files', ['.conf', '.config', '.rules']],
  ['All files',    '*'                           ]
];
my $varfile_frame =
  create_fileSelectFrame($opt_tab, "Variable file", 'WRFILE', \$config{varfile}, 'EDIT', $types);

$balloon->attach($varfile_frame, -statusmsg => $help{varfile});


# Create frame with backup dir location.
my $backupdir_frame =
  create_fileSelectFrame($opt_tab, "Backup directory", 'WRDIR', \$config{backupdir}, 'NOEDIT', undef);

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
  -background => "$color{label}", 
  -border     => '2'
)->pack(
  -side       => 'left',
  -fill       => 'y'
);


# Create "GUI settings" label.
$left_frame->Label(
  -text       => "GUI settings:",
  -background => "$color{label}"
)->pack(
  -side       => 'top',
  -fill       => 'x'
);


create_actionbutton($left_frame, "Load saved settings",   \&load_config);
create_actionbutton($left_frame, "Save current settings", \&save_config);


# Create "options" label at the top of the left frame.
$left_frame->Label(
  -text       => "Options:", 
  -background => "$color{label}"
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
  -background => "$color{label}"
)->pack(side  => 'top',
        fill  => 'x'
);

# Create mode radiobuttons in the left frame.
create_radiobutton($left_frame, "über-quiet", \$config{mode});
create_radiobutton($left_frame, "quiet",      \$config{mode});
create_radiobutton($left_frame, "normal",     \$config{mode});
create_radiobutton($left_frame, "verbose",    \$config{mode});



# Create "activity messages" label.
$main->Label(
  -text       => "Output messages:", 
  -width      => '100', 
  -background => "$color{label}"
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
  -background => "$color{label}"
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

logmsg("No oinkmaster configuration file set, please select one above!\n", 'ERROR')
  if ($config{oinkmaster_conf} !~ /\S/);

logmsg("Output directory is not set, please select one above!\n", 'ERROR')
if ($config{outdir} !~ /\S/);


logmsg("\n", 'MISC');
 
MainLoop;



#### END ####



sub fileDialog($ $ $ $)
{
    my $var_ref   = shift;
    my $title     = shift;
    my $type      = shift;
    my $filetypes = shift;

    if ($type eq 'WRDIR') {
        my $fs = $main->FileSelect();
        $fs->configure(-verify => ['-d', '-w'], -title => $title);
        my $dirname = $fs->Show;
        $$var_ref = $dirname if ($dirname);
    } else {
        my $filename = $main->getOpenFile(-title => $title, -filetypes => $filetypes);
        $$var_ref = $filename if ($filename);
    }
}



sub update_file_label_color($ $ $)
{
    my $label    = shift;
    my $filename = shift;
    my $type     = shift;

    $filename =~ s/^\s+//;
    $filename =~ s/\s+$//;

    unless ($filename) {
        $label->configure(-background => $color{file_label_not_ok});
        return (1);
    }

    if ($type eq "URL") {
        if ($filename =~ /^(?:http|ftp):\/\/.+\.tar\.gz$/) {
            $label->configure(-background => $color{file_label_ok});
        } elsif ($filename =~ /^(?:file:\/\/)*(.+\.tar\.gz)$/) {
            my $file = $1;
            if (-f "$file" && -r "$file") {
                $label->configure(-background => $color{file_label_ok});
            } else {
                $label->configure(-background => $color{file_label_not_ok});
            }
        } else {
            $label->configure(-background => $color{file_label_not_ok});
        }
    } elsif ($type eq "ROFILE") {
        if (-f "$filename" && -r "$filename") {
            $label->configure(-background => $color{file_label_ok});
        } else {
            $label->configure(-background => $color{file_label_not_ok});
        }
    } elsif ($type eq "EXECFILE") {
        if (-f "$filename" && (-x "$filename" || $^O eq 'MSWin32')) {
            $label->configure(-background => $color{file_label_ok});
        } else {
            $label->configure(-background => $color{file_label_not_ok});
        }
    } elsif ($type eq "WRFILE") {
        if (-f "$filename" && -w "$filename") {
            $label->configure(-background => $color{file_label_ok});
        } else {
            $label->configure(-background => $color{file_label_not_ok});
        }
    } elsif ($type eq "WRDIR") {
        if (-d "$filename" && -w "$filename") {
            $label->configure(-background => $color{file_label_ok});
        } else {
            $label->configure(-background => $color{file_label_not_ok});
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
      -background => $color{button},
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
      -background => "$color{button}",
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
      -background => "$color{button}",
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
sub create_fileSelectFrame($ $ $ $ $ $) 
{
    my $win       = shift;
    my $name      = shift;
    my $type      = shift;  # FILE|DIR|URL
    my $var_ref   = shift;
    my $edtype    = shift;  # EDIT|NOEDIT
    my $filetypes = shift;

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

  # Create edit-button if file is ediable.
    if ($edtype eq 'EDIT') {
        my $edit_but = $frame->Button(
          -text       => "Edit",
          -background => "$color{button}",
          -command    => sub {
                                 unless (-e "$$var_ref") {
                                     logmsg("Select an existing file first!.\n\n", 'ERROR');
                                     return;
                                 }

                                 if ($editor) {
                                     $main->Busy(-recurse => 1);
                                     logmsg("Launching $editor. Close it to continue the GUI.\n\n", 'MISC');
                                     sleep(2);
                                     system($editor, $$var_ref);  # yes, MainLoop will be put on hold...
                                     $main->Unbusy;
                                 } else {
                                     logmsg("No suitable editor found.\n\n", 'ERROR');
                                 }
                             }
        )->pack(
          -side       => 'left',
        );
    }

  # Create browse-button.
    my $but = $frame->Button(
      -text       => "browse ...",
      -background => "$color{button}",
      -command    => sub {
                            fileDialog($var_ref, $name, $type, $filetypes);
                         }
    )->pack(
      -side       => 'left',
    );

    return ($frame);
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

    unless ($config{oinkmaster} && (-x "$config{oinkmaster}" || $^O eq 'MSWin32')) {
        logmsg("Location to oinkmaster.pl is not set correctly!\n\n", 'ERROR');
        return;
    }

    my $cmd = File::Spec->rel2abs($config{oinkmaster}) . " -V";
    logmsg("$cmd:\n", 'EXEC');
    my $output = `$cmd 2>&1` || "Could not execute $config{oinkmaster}: $!\n";
    logmsg("$output", 'OUTPUT');
    logmsg("$version by Andreas Östling <andreaso\@it.su.se>\n\n", 'OUTPUT');
}



sub show_help()
{
    $config{oinkmaster} =~ s/^\s+//;
    $config{oinkmaster} =~ s/\s+$//;

    unless ($config{oinkmaster} && (-x "$config{oinkmaster}" || $^O eq 'MSWin32')) {
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

    if ($^O eq 'MSWin32') {
        open(OINK, "@cmd 2>&1|");
        while (<OINK>) {
            logmsg($_, 'OUTPUT');
        }
        close(OINK);
    } else {
        if (open(OINK,"-|")) {
            while (<OINK>) {
                logmsg($_, 'OUTPUT');
            }
        } else {
            open(STDERR, '>&', 'STDOUT');
            exec(@cmd);
        }
        close(OINK);
    }

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

    clear_messages();
    $main->Busy(-recurse => 1);

    create_cmdline(\@cmd) || return;
    logmsg("@cmd:\n", 'EXEC');

    if ($^O eq 'MSWin32') {
        open(OINK, "@cmd 2>&1|");
        while (<OINK>) {
            logmsg($_, 'OUTPUT');
        }
        close(OINK);
    } else {
        if (open(OINK,"-|")) {
            while (<OINK>) {
                logmsg($_, 'OUTPUT');
            }
        } else {
            open(STDERR, '>&', 'STDOUT');
            exec(@cmd);
        }
        close(OINK);
    }

    logmsg("Done.\n\n", 'EXEC');
    $main->Unbusy;
}



sub create_cmdline($)
{
    my $cmd_ref = shift;

    my $oinkmaster      = File::Spec->rel2abs($config{oinkmaster});
    my $oinkmaster_conf = $config{oinkmaster_conf};
    my $outdir          = $config{outdir};
    my $varfile         = $config{varfile};
    my $url             = $config{url};
    my $backupdir       = $config{backupdir};

  # Assume file:// if url prefix is missing.
    if ($url) {
        $url = "file://$url" unless ($url =~ /(?:http|ftp|file):\/\//);
    }

    foreach my $var_ref (\$oinkmaster, \$oinkmaster_conf, \$outdir, 
                         \$varfile, \$url, \$backupdir) {
        $$var_ref =~ s/^\s+//;
        $$var_ref =~ s/\s+$//;
        if ($^O eq 'MSWin32' && $$var_ref) {
            $$var_ref = "\"$$var_ref\"";
        }
    }

    unless ($oinkmaster && (-x "$oinkmaster" || $^O eq 'MSWin32')) {
        logmsg("Location to oinkmaster.pl is not set correctly!\n\n", 'ERROR');
        return (0);
    }

    unless ($oinkmaster_conf) {
        logmsg("Location to configuration file is not set correctly!\n\n", 'ERROR');
        return (0);
    }

    unless ($outdir) {
        logmsg("Output directory is not set!\n\n", 'ERROR');
        return (0);
    }

    push(@$cmd_ref, 
      $oinkmaster, 
      "-C", "$oinkmaster_conf", 
      "-o", "$outdir");

    push(@$cmd_ref, "-c")               if ($config{careful});
    push(@$cmd_ref, "-e")               if ($config{enable_all});
    push(@$cmd_ref, "-r")               if ($config{check_removed});
    push(@$cmd_ref, "-q")               if ($config{mode} eq "quiet");
    push(@$cmd_ref, "-Q")               if ($config{mode} eq "über-quiet");
    push(@$cmd_ref, "-v")               if ($config{mode} eq "verbose");
    push(@$cmd_ref, "-U", "$varfile")   if ($varfile);
    push(@$cmd_ref, "-b", "$backupdir") if ($backupdir);

    push(@$cmd_ref, "-u", "$url")
      if ($url);

    return (1);
}



# Load $config file into %config hash.
sub load_config()
{
    unless (defined($gui_config_file) && $gui_config_file) {
        logmsg("Unable to determine config file location, is your \$HOME set?\n\n", 'ERROR');
        return;
    }

    unless (-e "$gui_config_file") {
        logmsg("$gui_config_file does not exist, keeping current/default settings\n\n", 'MISC');
        return;
    }

    unless (open(RC, "<$gui_config_file")) {
        logmsg("Could not open $gui_config_file for reading: $!\n", 'ERROR');
        return;
    }

    while (<RC>) {
        next unless (/^(\S+)=(.*)/);
        $config{$1} = $2;
    }

    close(RC);
    logmsg("Successfully loaded GUI settings from $gui_config_file\n\n", 'MISC');
}



# Save %config into file $config.
sub save_config()
{
    unless (defined($gui_config_file) && $gui_config_file) {
        logmsg("Unable to determine config file location, is your \$HOME set?\n\n", 'ERROR');
        return;
    }

    unless (open(RC, ">$gui_config_file")) {
        logmsg("Could not open $gui_config_file for writing: $!\n", 'ERROR');
        return;
    }

    foreach my $option (sort(keys(%config))) {
        print RC "$option=$config{$option}\n";
    }

    close(RC);
    logmsg("Successfully saved current GUI settings to $gui_config_file\n\n", 'MISC');
}
