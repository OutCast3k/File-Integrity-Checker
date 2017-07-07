#!/usr/bin/perl

## FIC 0.2 - file integrity checker, By OutCast3k
## settings start

my $host = "https://coinb.in";
my $sha1sum = "https://raw.githubusercontent.com/OutCast3k/coinbin/master/sha1sum";

my $smtpserver = 'smtp.gmail.com';
my $smtpport = 465;
my $smtpuser   = '';
my $smtppassword = '';

## settings end

use strict;
use warnings;

use Digest::SHA1;

use Email::Sender::Simple qw(sendmail);
use Email::Sender::Transport::SMTPS;
use Email::Simple ();
use Email::Simple::Creator ();

sub fileDownload {
	my $filename = fileName($_[0]);
	print "Downloading File: ".$_[0]." to ".$filename."\r\n";
	system("curl -s ".$_[0]." > ".$filename);
}

sub fileName {
	$_[0] =~ /\/?([a-z0-9\.\\\-]+)$/i;
	return $1;
}

sub fileDelete {
	print "Deleting File: ".$_[0]."\r\n";
	unlink($_[0]);
}

sub fileRead {
	open(my $fh, '<:encoding(UTF-8)', $_[0]) or die "Could not open file '$_[0]' $!";
	my @result = (''); 
	while (my $row = <$fh>) {
		chomp $row;
		push @result,$row;
	}
	return @result;
}

sub sha1sum {
	my $fh;
	unless (open $fh, $_[0]) {
	        warn "$0: open $_[0]: $!";
	        next;
	}

	my $sha1 = Digest::SHA1->new;
	$sha1->addfile($fh);
	close $fh;
	return $sha1->hexdigest;
}

sub sendnotification {
	my $transport = Email::Sender::Transport::SMTPS->new({
		host => $smtpserver,
		port => $smtpport,
		ssl  => 'ssl',
		sasl_username => $smtpuser,
		sasl_password => $smtppassword,
	});

	my $email = Email::Simple->create(
		header => [
    		To      => $smtpuser,
		From    => $smtpuser,
		Subject => '['.$host.'] WARNING FILE CHECKSUM MISSMATCH!!!'],
		body => $_[0]);

	print "Sending email to: ".$smtpuser."\n";

	sendmail($email, { transport => $transport });
}

sub begin {
	print "BEGIN\n";
	my $emailBody = "";
	fileDelete(fileName($sha1sum));
	fileDownload($sha1sum);
	my @filelist = fileRead("sha1sum");
	foreach my $line (@filelist){
		if($line =~ /^([a-f0-9]+)\s\s\.\/([a-z0-9\/\.\-\_]+)$/i){
			my $file_local = fileName($2);

			print "Hash Expected ".$1." for file ".$file_local."\n";
			fileDownload($host."/".$2);

			my $file_local_hash = sha1sum($file_local);
			print "File Hash ".$file_local_hash."\n";

			if($1 eq $file_local_hash){
				print "OK";
			} else {
				print "WARNING!!! WARNING!!! WARNING!!! WARNING!!!";
				$emailBody .= "Expected hash ".$1." for ".$file_local.", but generated ".$file_local_hash."\n";
			}

			print "\n";

			fileDelete($file_local);
		}
	}

	if(($emailBody ne "") && $smtpuser ne ""){
		sendnotification("[".localtime()."] Please check ".$host." for unauthorized access, checksum miss match.\n\n".$emailBody);
	}

}

begin();
