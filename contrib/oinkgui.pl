#!/usr/bin/perl -w

# $Id$ #

use strict;
use Tk;
use Tk::NoteBook;


sub test_config();
sub show_version();
sub show_help();
sub update_rules();
sub clear_messages();
sub create_cmdline($);
sub fileDialog($ $);
sub load_config();
sub save_config();
sub update_file_label_color($ $);
sub create_fileSelectFrame($ $);
sub create_checkbutton($ $ $);
sub create_radiobutton($ $ $);
sub create_actionbutton($ $ $);
sub logmsg($ $);


my $version     = 'Oinkmaster GUI v0.1';

my %gui_config;


my @oinkmaster_pl   = qw(./oinkmaster.pl
                         /etc/oinkmaster.pl 
                         /usr/local/bin/oinkmaster.pl
                        );

my @oinkmaster_conf = qw(./oinkmaster.conf
                         /etc/oinkmaster.conf
                         /usr/local/etc/oinkmaster.conf
                        );



my $bgcolor        = 'Bisque3';
my $butcolor       = 'Bisque2';
my $actbutcolor    = 'Bisque2';
my $labelcolor     = 'Bisque1';


$gui_config{careful}       = 0;
$gui_config{enable_all}    = 1;
$gui_config{check_removed} = 0;

$gui_config{mode} = 'normal';



$gui_config{oinkmaster}             = "";
$gui_config{oinkmaster_config_file} = "";
$gui_config{outdir}                 = "";
$gui_config{url}                    = "";
$gui_config{varfile}                = "";
$gui_config{backupdir}              = "";

my $gui_config_file     = "";


#### MAIN ####

select STDERR;
$| = 1;
select STDOUT;
$| = 1;


# Find out which oinkmaster config file to use.
foreach my $file (@oinkmaster_conf) {
    if (-e "$file") {
        $gui_config{oinkmaster_config_file} = $file;
        last;
    }
}

# Find out which oinkmaster.pl file to use.
foreach my $file (@oinkmaster_pl) {
    if (-e "$file") {
        $gui_config{oinkmaster} = $file;
        last;
    }
}

# Find out where the GUI config file is (it's not required).
$gui_config_file = "$ENV{HOME}/.oinkguirc" if ($ENV{HOME});


# Create main window.
my $main = MainWindow->new(
  -background => "$bgcolor",
  -title      => "$version"
);


my $out_frame = $main->Scrolled('Text',
  -setgrid    => 'true',
  -scrollbars => 'e',
  -background => 'black',
  -foreground => 'white',
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
  create_fileSelectFrame($req_tab, "Oinkmaster.pl");

# Create frame with oinkmaster.pl location.
my ($oinkconf_frame, $oinkconf_label, $oinkconf_entry, $oinkconf_but) = 
  create_fileSelectFrame($req_tab, "Oinkmaster.conf");

# Create frame with output directory. XXX must be able to select dir only.
my ($outdir_frame, $outdir_label, $outdir_entry, $outdir_but) = 
  create_fileSelectFrame($req_tab, "Output directory");



# Create tab with optional files/dirs.
my $opt_tab = $notebook->add("optional",
  -label     => "Optional files and directories",
  -underline => 0,
);


# Create frame with alternate URL location. XXX choice between stable/current/local.
my ($url_frame, $url_label, $url_entry, $url_but) = 
  create_fileSelectFrame($opt_tab, "Alternate URL");

# Create frame with variable file.
my ($varfile_frame, $varfile_label, $varfile_entry, $varfile_but) = 
  create_fileSelectFrame($opt_tab, "Variable file");

# Create frame with backup dir location. XXX must be able to select dir only.
my ($backupdir_frame, $backupdir_label, $backupdir_entry, $backupdir_but) = 
  create_fileSelectFrame($opt_tab, "Backup directory");


$notebook->pack(
  -expand => 'no',
  -fill   => 'x',
  -padx   => 5,
  -pady   => 5,
  -side   => 'top'
);

#$req_tab->pack();
#$opt_tab->pack();



# Create the option frame to the left.
my $opt_frame = $main->Frame(
  -background => "#202020", 
  -border     => '2'
)->pack(
  -side       => 'left',
  -fill       => 'y'
);


# Create "GUI settings" label.
$opt_frame->Label(
  -text       => "GUI settings:",
  -background => "$labelcolor"
)->pack(
  -side       => 'top',
  -fill       => 'x'
);


create_actionbutton($opt_frame, "Load saved settings",   \&load_config);
create_actionbutton($opt_frame, "Save current settings", \&save_config);


# Create "options" label at the top of the option frame.
$opt_frame->Label(
  -text       => "Options:", 
  -background => "$labelcolor"
)->pack(side  => 'top',
        fill  => 'x'
);


# Create checkbuttons in the option frame.
create_checkbutton($opt_frame, "Careful mode                 ",    \$gui_config{careful});
create_checkbutton($opt_frame, "Enable all                      ", \$gui_config{enable_all});
create_checkbutton($opt_frame, "Check for removed files",          \$gui_config{check_removed});


# Create "mode" label.
$opt_frame->Label(
  -text       => "Mode:", 
  -background => "$labelcolor"
)->pack(side  => 'top',
        fill  => 'x'
);

# Create mode radiobuttons in the option frame.
create_radiobutton($opt_frame, "über-quiet", \$gui_config{mode});
create_radiobutton($opt_frame, "quiet",      \$gui_config{mode});
create_radiobutton($opt_frame, "normal",     \$gui_config{mode});
create_radiobutton($opt_frame, "verbose",    \$gui_config{mode});



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



# Create "actions" label.
$opt_frame->Label(
  -text       => "Actions:",
  -background => "$labelcolor"
)->pack(
  -side       => 'top',
  -fill       => 'x'
);


# Create actions button.
create_actionbutton($opt_frame, "Show version",       \&show_version);
create_actionbutton($opt_frame, "Show help",          \&show_help);
create_actionbutton($opt_frame, "Test configuration", \&test_config);
create_actionbutton($opt_frame, "Update rules!",      \&update_rules);
create_actionbutton($opt_frame, "Clear messages",     \&clear_messages);
create_actionbutton($opt_frame, "Exit",               \&exit);



# Now the fun begins.
logmsg("Welcome to $version by Andreas Östling <andreaso\@it.su.se>\n\n", 'MISC');

# Load gui settings into %config. Will overwrite the defaults if it exists.
load_config();


# Fill in values in the graphical entries if files were found in default locations.
if ($gui_config{oinkmaster_config_file} !~ /\S/) {
    logmsg("No configuration file found, please choose one above!\n", 'ERROR');
} else {
    $oinkconf_entry->delete(0.0, 'end');
    $oinkconf_entry->insert(0.0, "$gui_config{oinkmaster_config_file}");
    update_file_label_color($oinkconf_label, $oinkconf_entry->get);    
}

if ($gui_config{oinkmaster} !~ /\S/) {
    logmsg("No oinkmaster.pl found, please select one above!\n", 'ERROR');
} else {
    $oinkscript_entry->delete(0.0, 'end');
    $oinkscript_entry->insert(0.0, "$gui_config{oinkmaster}");
    update_file_label_color($oinkscript_label, $oinkscript_entry->get);    
}

if ($gui_config{outdir} !~ /\S/) {
    logmsg("Please select an output directory above before continuing!\n", 'ERROR');
} else {
    $outdir_entry->delete(0.0, 'end');
    $outdir_entry->insert(0.0, "$gui_config{outdir}");
    update_file_label_color($outdir_label, $outdir_entry->get);    
}



logmsg("\n", 'MISC');


 
MainLoop;



#### END ####



sub fileDialog($ $)
{
    my $entry   = shift;
    my $title   = shift;

    my $filename = $main->getOpenFile(-title => $title);

    if ($filename) {
        $entry->delete('0.0', 'end');
        $entry->insert('0.0', $filename);
        logmsg("$filename selected\n\n", 'white');
    }
}



sub update_file_label_color($ $)
{
    my $label    = shift;
    my $filename = shift;

    if ($filename && -e "$filename") {
        $label->configure(-background => "#00e000");
    } else {
        $label->configure(-background => 'red');
    }
}



sub create_checkbutton($ $ $)
{
    my $frame   = shift;
    my $name    = shift;
    my $var_ref = shift;
 
    $frame->Checkbutton(
      -text       => $name,
      -background => $butcolor,
      -variable   => $var_ref,
      -relief     => 'raise'
    )->pack(
      -fill       => 'x',
      -side       => 'top',
      -pady       => '1',
      -anchor     => 'w'
    );
}



sub create_actionbutton($ $ $)
{
    my $frame    = shift;
    my $name     = shift;
    my $func_ref = shift;

    $frame->Button(
      -text       => $name,
      -command    => sub { &$func_ref }, 
      -background => "$actbutcolor",
    )->pack(
      -fill       => 'x'
    );
}



sub create_radiobutton($ $ $)
{
    my $frame    = shift;
    my $name     = shift;
    my $mode_ref = shift;
 
    $frame->Radiobutton(
      -text       => "$name",
      -background => "$butcolor",
      -variable   =>  $mode_ref,
      -relief     => 'raised',
      -value      => "$name",
    )->pack(
      -side       => 'top',
      -pady       => '1',
      -fill       => 'x',
      -anchor     => 'w'
    );
}



# Create <label><entry><browsebutton> in given frame.
sub create_fileSelectFrame($ $)
{
    my $win  = shift;
    my $name = shift;

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

  # Create entry.
    my $entry = $frame->Entry(
      -background => 'white',
      -width      => '80',
    )->pack(
      -side       => 'left',
      -expand     => 'yes',
      -fill       => 'x'
   );


  # Create browse-button.
    my $but = $frame->Button(
      -text       => "browse ...",
      -background => "$actbutcolor",
      -command    => sub {
                            fileDialog($entry, $name);
                            update_file_label_color($label, $entry->get);
                          }
    )->pack(
      -side       => 'left'
    );

    return ($frame, $label, $entry, $but);
}



sub logmsg($ $)
{
    my $text = shift;
    my $type = shift;

    die("too early to use logmsg(), msg=$text\n")
      unless (defined($out_frame));

    return unless (defined($text));

    $out_frame->tag(qw(configure OUTPUT -foreground grey));
    $out_frame->tag(qw(configure ERROR  -foreground red));
    $out_frame->tag(qw(configure MISC   -foreground white));
    $out_frame->tag(qw(configure EXEC   -foreground bisque2));

    $out_frame->insert('insert', "$text", "$type");
    $out_frame->see('end'); 
    $out_frame->update;
}



sub show_version()
{
    my $oinkmaster = $oinkscript_entry->get;

    unless ($oinkmaster && -x "$oinkmaster") {
        logmsg("Location to oinkmaster.pl is not set correctly!\n\n", 'ERROR');
        return;
    }

    my $cmd = "$oinkmaster -V";
    logmsg("$cmd:\n", 'EXEC');
    my $output = `$cmd 2>&1`;
    logmsg("$output\n", 'OUTPUT');
}



sub show_help()
{
    my $oinkmaster = $oinkscript_entry->get;

    unless ($oinkmaster && -x "$oinkmaster") {
        logmsg("Location to oinkmaster.pl is not set correctly!\n\n", 'ERROR');
        return;
    }

    my $cmd = "$oinkmaster -h";
    logmsg("$cmd:\n", 'EXEC');
    my $output = `$cmd 2>&1`;
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
        open(STDERR, '>&', 'STDOUT') or die("could not redirect STDERR\n");
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

    if (open(OINK,"-|")) {
        while (<OINK>) {
            logmsg($_, 'OUTPUT');
            $main->update;
        }
    } else {
        open(STDERR, '>&', 'STDOUT') or die("could not redirect STDERR\n");
        exec(@cmd);
    }
    close(OINK);
 
    logmsg("Done.\n\n", 'EXEC');
}



sub create_cmdline($)
{
    my $cmd_ref = shift;

    my $oinkmaster  = $oinkscript_entry->get;
    my $config_file = $oinkconf_entry->get;
    my $outdir      = $outdir_entry->get;
    my $varfile     = $varfile_entry->get;
    my $url         = $url_entry->get;
    my $backupdir   = $backupdir_entry->get;

    unless ($oinkmaster && -x "$oinkmaster") {
        logmsg("Location to oinkmaster.pl is not set correctly!\n\n", 'ERROR');
        return (0);
    }

    unless ($config_file) {
        logmsg("Location to configuration file is not set correctly!\n\n", 'ERROR');
        return (0);
    }

    unless ($outdir) {
        logmsg("Output directory is not set!\n\n", 'ERROR');
        return (0);
    }

    push(@$cmd_ref, $oinkmaster, "-C", "$config_file", "-o", "$outdir");

    push(@$cmd_ref, "-c")               if ($gui_config{careful});
    push(@$cmd_ref, "-e")               if ($gui_config{enable_all});
    push(@$cmd_ref, "-r")               if ($gui_config{check_removed});
    push(@$cmd_ref, "-q")               if ($gui_config{mode} eq "quiet");
    push(@$cmd_ref, "-Q")               if ($gui_config{mode} eq "über-quiet");
    push(@$cmd_ref, "-v")               if ($gui_config{mode} eq "verbose");
    push(@$cmd_ref, "-u", "$url")       if ($url);
    push(@$cmd_ref, "-U", "$varfile")   if ($varfile);
    push(@$cmd_ref, "-b", "$backupdir") if ($backupdir);

    return (1);
}



# Load $gui_config file into %gui_config hash.
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

    logmsg("Loading GUI settings from $gui_config_file\n\n", 'MISC');

    unless (open(RC, "<$gui_config_file")) {
        logmsg("Could not open $gui_config_file for reading: $!\n", 'ERROR');
        return;
    }

    while (<RC>) {
        next unless (/^(\S+) = (\S+.*)/);
        $gui_config{$1} = $2;
    }

    close(RC);

  # Update entries.

    $oinkscript_entry->delete(0.0, 'end');
    $oinkscript_entry->insert(0.0, "$gui_config{oinkmaster}");
    update_file_label_color($oinkscript_label, $oinkscript_entry->get);    

    $oinkconf_entry->delete(0.0, 'end');
    $oinkconf_entry->insert(0.0, "$gui_config{oinkmaster_config_file}");
    update_file_label_color($oinkconf_label, $oinkconf_entry->get);    

    $outdir_entry->delete(0.0, 'end');
    $outdir_entry->insert(0.0, "$gui_config{outdir}");
    update_file_label_color($outdir_label, $outdir_entry->get);    

    $url_entry->delete(0.0, 'end');
    $url_entry->insert(0.0, "$gui_config{url}");
    update_file_label_color($url_label, $url_entry->get);    

    $varfile_entry->delete(0.0, 'end');
    $varfile_entry->insert(0.0, "$gui_config{varfile}");
    update_file_label_color($varfile_label, $varfile_entry->get);    

    $backupdir_entry->delete(0.0, 'end');
    $backupdir_entry->insert(0.0, "$gui_config{backupdir}");
    update_file_label_color($backupdir_label, $backupdir_entry->get);    
}



# Save %gui_config into file $gui_config.
sub save_config()
{
    unless (defined($gui_config_file) && $gui_config_file) {
        logmsg("Unable to determine config file location, is your \$HOME set?\n\n", 'ERROR');
        return;
    }

    logmsg("Saving current GUI settings to $gui_config_file\n\n", 'MISC');

    $gui_config{oinkmaster_config_file} =  $oinkconf_entry->get;    
    $gui_config{oinkmaster}             =  $oinkscript_entry->get;
    $gui_config{outdir}                 =  $outdir_entry->get;

    $gui_config{url}                    =  $url_entry->get;
    $gui_config{varfile}                =  $varfile_entry->get;
    $gui_config{backupdir}              =  $backupdir_entry->get;

    unless (open(RC, ">$gui_config_file")) {
        logmsg("Could not open $gui_config_file for writing: $!\n", 'ERROR');
        return;
    }

    foreach my $option (sort(keys(%gui_config))) {
        print STDERR "$option = $gui_config{$option}\n";
        print RC "$option = $gui_config{$option}\n";
    }

    close(RC);
}
