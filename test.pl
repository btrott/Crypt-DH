# $Id: test.pl,v 1.2 2001/04/24 08:22:22 btrott Exp $

my $loaded;
BEGIN { print "1..1\n" }
use Crypt::DH;
$loaded++;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded }
