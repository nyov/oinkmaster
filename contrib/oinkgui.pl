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
sub update_file_label_color($ $);
sub create_fileSelectFrame($ $);
sub create_checkbutton($ $ $);
sub create_radiobutton($ $ $);
sub create_actionbutton($ $ $);
sub logmsg($ $);


my $version     = 'Oinkmaster GUI v0.1 by Andreas Östling <andreaso@it.su.se>';
my $outdir      = "";

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

my $careful        = 0;
my $enable_all     = 0;
my $check_removed  = 0;
my $mode           = 'normal';

my $config_file    = "";
my $oinkmaster     = "";



#### MAIN ####

select STDERR;
$| = 1;
select STDOUT;
$| = 1;


# Find out which config file to use.
foreach my $file (@oinkmaster_conf) {
    if (-e "$file") {
        $config_file = $file;
        last;
    }
}

# Find out which oinkmaster.pl file to use.
foreach my $file (@oinkmaster_pl) {
    if (-e "$file") {
        $oinkmaster = $file;
        last;
    }
}


# Create main window.
my $main = MainWindow->new(
  -background => "$bgcolor",
  -title      => "$version"
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


# Create frame with alternate URL location.
my ($url_frame, $url, $url_entry, $url_but) = 
  create_fileSelectFrame($opt_tab, "Alternate URL");

# Create frame with variable file. XXX must be able to select dir only.
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


# Create "options" label at the top of the option frame.
$opt_frame->Label(
  -text       => "Options:", 
  -background => "$labelcolor"
)->pack(side  => 'top',
        fill  => 'x'
);


# Create checkbuttons in the option frame.
create_checkbutton($opt_frame, "Careful mode                 ",    \$careful);
create_checkbutton($opt_frame, "Enable all                      ", \$enable_all);
create_checkbutton($opt_frame, "Check for removed files",          \$check_removed);


# Create "mode" label.
$opt_frame->Label(
  -text       => "Mode:", 
  -background => "$labelcolor"
)->pack(side  => 'top',
        fill  => 'x'
);

# Create mode radiobuttons in the option frame.
create_radiobutton($opt_frame, "über-quiet                     ", \$mode);
create_radiobutton($opt_frame, "quiet                             ", \$mode);
create_radiobutton($opt_frame, "normal                          ", \$mode);
create_radiobutton($opt_frame, "verbose                        ", \$mode);


# Create "activity messages" label.
$main->Label(
  -text       => "Output messages:", 
  -width      => '100', 
  -background => "$labelcolor"
)->pack(
  -side       => 'top',
  -fill       => 'x'
);


# Create output frame.
my $out_frame = $main->Scrolled('Text',
  -setgrid    => 'true',
  -scrollbars => 'e',
  -background => 'black',
  -foreground => 'white',
)->pack(
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



logmsg("Welcome to $version\n\n", 'MISC');


# Fill in values in the entries if files were found in default locations.
if ($config_file eq "") {
    logmsg("No configuration file found, please choose one above!\n", 'ERROR');
} else {
    logmsg("Found configuration file: $config_file\n", 'MISC');
    $oinkconf_entry->insert(0.0, "$config_file");
    update_file_label_color($oinkconf_label, $oinkconf_entry->get);    
}

if ($oinkmaster eq "") {
    logmsg("No oinkmaster.pl found, please select one above!\n", 'ERROR');
} else {
    logmsg("Found oinkmaster.pl: $oinkmaster\n", 'MISC');
    $oinkscript_entry->insert(0.0, "$oinkmaster");
    update_file_label_color($oinkscript_label, $oinkscript_entry->get);    
}

logmsg("Please set the output directory before continuing\n", 'ERROR');

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
      -command    => sub { &$func_ref() }, 
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

    die("too early to use logmsg()\n")
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

    push(@$cmd_ref, "-c")               if ($careful);
    push(@$cmd_ref, "-e")               if ($enable_all);
    push(@$cmd_ref, "-r")               if ($check_removed);
    push(@$cmd_ref, "-q")               if ($mode =~ /^quiet/);
    push(@$cmd_ref, "-Q")               if ($mode =~ /^über-quiet/);
    push(@$cmd_ref, "-v")               if ($mode =~ /^verbose/);
    push(@$cmd_ref, "-u", "$url")       if ($url);
    push(@$cmd_ref, "-U", "$varfile")   if ($varfile);
    push(@$cmd_ref, "-b", "$backupdir") if ($backupdir);

    return (1);
}
