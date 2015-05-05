################################################################################
# cgSpamAssassin.pl - SpamAssassin spamc interface for CommuniGate Pro
################################################################################
# 2015-05-04 0.0.4  Initial release
# 2015-05-05 0.0.5  Spamc error kills helper so spam doesn't leak through

# Get configuration
use strict;
use warnings;
use POSIX ":sys_wait_h";
use Cwd qw(cwd abs_path);
use File::Basename;
use Time::HiRes qw(time);
$| = 1;

my $ver = '0.0.5';

our %config;
$config{cfgFile}=abs_path(dirname(__FILE__))."/cgSpamAssassin.conf";
$config{cgpBase}=cwd();

print "* cgSpamAssassin v$ver starting\n";

open CFGH, $config{cfgFile} or die "Couldn't open configuration file: $!"; 
while (<CFGH>) {
    chomp;                  # no newline
    s/#.*//;                # no comments
    s/^\s+//;               # no leading white
    s/\s+$//;               # no trailing white
    next unless length;     # anything left?
    my ($var, $value) = split(/\s*=\s*/, $_, 2);
    $config{$var} = $value;
} 
close CFGH;

my $cfgkey;
foreach $cfgkey (keys %config) {
	print "* cgSpamAssassin $cfgkey = $config{$cfgkey}\n";
}

#print "* cgSpamAssassin cgBase = ".$config{cgpBase}."\n";
#print "* cgSpamAssassin saSpamc = $config{saSpamc}\n";
#print "* cgSpamAssassin saSpamd = $config{saSpamd}\n";
#print "* cgSpamAssassin tempdir = $config{tempdir}\n";

if ( ! -e "$config{tempdir}" ) {
	print "* cgSpamAssassin ***ERROR*** tempdir does not exist, terminating\n";
	exit;
}

#-------------------------------------------------------------------------------
# Main Processing Loop
my %pids;
my $pid;
my $parentpid=$$;
$SIG{INT} = sub { die "SpamAssassin Error" };

while (<>)
 {
 	my @line = split(/ /, $_);
 	$line[0] =~ s/[\r\n]//g;

 	print "$line[0] OK\n"      and next if ($line[1] =~ /^quit$/i);
 	print "$line[0] INTF 3\n"  and next if ($line[1] =~ /^intf$/i);
 	print "$line[0] OK\n"      and next if ($line[1] =~ /^key$/i);
 	print "$line[0] FAILURE\n" and next if ($line[1] !~ /^file$/i);

	$line[2] =~ s|\\|/|g; # Getting the filepath
 	$line[2] =~ s/[\r\n]//g;
	
	# Start a separate process to handle the request so we don't have to wait for it
	$pid=0;
	rand(); 
	$pid = fork();
	
	# This is all the child process does: process the message and exit
	if ($pid == 0) {
		processMessage($line[0],$line[2]);
		exit();
	}
	
	# Record the existence of our new child process
	$pids{$pid}=1;
	
	# Clean up any complete child processes
	foreach $pid (keys %pids)
	{
		if (waitpid($pid, &WNOHANG) == -1) {
			# child $pid has terminated
			delete $pids{$pid};
		}
	}
}

# Clean up child processes
foreach $pid (keys %pids)
{
	waitpid($pid, 0); # blocking wait
    delete $pids{$pid};
}


sub processMessage {
	my ($reqid,$msgfile)=@_;
	my $stime=time;
 	if (!open(MSG, $msgfile))
 	{
 		close(MSG);
 		print "* $reqid File Not Found $msgfile\n$reqid OK\n";
 		return;
 	}

	# Get the sender from CGP message info
	my $sender='<>';
 	while (<MSG>) 
 	{
 		s/[\r\n]//g;
 		last if($_ eq '');
 		if(/^(\w) (\w).+<(.+)>/)
 		{
			$sender = $3 if	($1 eq 'P');
 		}
 	}
	
	# Call spamc to scan the message
	#my $WTR = gensym();  # get a reference to a typeglob
	#my $RDR = gensym();  # and another one

	#my $pid = open2(\*RDR, \*WTR, $config{saSpamc}, '--headers');
	#my $pid = open2(\*RDR, \*WTR, "cmd.exe", '/cdir');
	#open(WTR,"| $config{saSpamc} --headers >$config{tempdir}\\msg-$reqid.eml");
	my $tempfile="$config{tempdir}\\msg-$reqid-in.eml";
	open WTR, ">", $tempfile;
	# Here we send the message to spamc
	my $retpath="Return-Path: $sender\n";
	#print "-------------------------------------------------------------------------------\n";
	#print $retpath;
	print WTR $retpath;
	my $firsthdr='';
	while (<MSG>) {
		#print $_;
		print WTR $_;
		$firsthdr=$_ if ($firsthdr eq '');
	}
	close(MSG);
	close(WTR);

	my $pid=open(RDR,"\"$config{saSpamc}\" --headers -x<$tempfile |");

	
	#print "-------------------------------------------------------------------------------\n";
	# Here we process the results of spamc
	my @saheaders=();
	my $sagethdr=1;
	while (<RDR>) {
		#print $_;
		if ($_ eq $firsthdr) {
			$sagethdr=0;
		}
		if ($sagethdr && ($_ ne $retpath)) {
			#s/^\s+|\s+$//g; use this to remove white space. For now, we'll just add the line to the end
			chomp;
			s/\t/\\t/g;
			push @saheaders, $_;
		}
	}
	
	close(RDR);
	my $xcode=$?; #Get spamc exit code
	unlink $tempfile;
	
	#print "-------------------------------------------------------------------------------\n";
	#print "SpamAssassin Headers:\n";
	#print "-------------------------------------------------------------------------------\n";
	#print $saheaders;
	#print "-------------------------------------------------------------------------------\n";
	
#	$saheaders =~ s/\n/\e/g;
#	$saheaders =~ s/\e\e/\e/g; # remove any double \e's
#	$saheaders =~ s/\e\t/ /g; # combine folded headers
#	my $l = length $saheaders;
#	my $e = substr $saheaders, $l-1;
#	if ($e eq "\e"){
#		$saheaders = substr $saheaders, 0, $l-1;
#	}
	
	# Clean up the spamc process
	waitpid($pid, &WNOHANG);
	my $isspam=$xcode==0 ? "not spam" : "spam";
	my $etime=time;
	my $dtime=$etime - $stime;
	if ($xcode gt 1) { # spamassassin error just die so messages don't skate by unscanned
		my $errmsg = sprintf("SpamAssassin error in %.1f seconds, exit code $?", $dtime);
		print "* $reqid $errmsg\n";
		kill KILL => $parentpid;
		die "$errmsg";
	}
	printf "* $reqid identified $isspam in %.1f seconds, exit code $?\n", $dtime;
	my $saheadertxt=join "\\e", @saheaders;

	print "$reqid ADDHEADER \"$saheadertxt\"\n";
	
	# Clean up the spamc process
	waitpid($pid, &WNOHANG);

}