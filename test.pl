# $Id: test.pl,v 1.3 2002/01/20 22:46:25 btrott Exp $

my $i   = 1;
my $loaded;
BEGIN { print "1..0\n" }
use Crypt::DH;
$loaded++;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded }

# Try this enough times that it doesn't randomly pass:
foreach (1 .. 10) {
    $i++;
    my $dh1 = Crypt::DH->new(g => 99, p => 101);
    $dh1->generate_keys;
    my $priv_key    = $dh1->priv_key;

    my $dh2 = Crypt::DH->new(g => 99, p => 101, priv_key => $priv_key);
    $dh2->generate_keys;
    if ($dh2->priv_key == $priv_key)    { print "ok $i\n" }
    else                                { print "not ok $i\n" }
}

