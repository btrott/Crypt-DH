# $Id: test.pl,v 1.1 2001/04/10 21:26:36 btrott Exp $

my $loaded;
BEGIN { print "1..1\n" }
use Net::SSH::Perl;
$loaded++;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded }
