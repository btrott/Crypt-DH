# $Id: DH.pm,v 1.9 2001/04/24 22:18:50 btrott Exp $

package Crypt::DH;
use strict;

use Crypt::Random qw( makerandom );
use Math::Pari qw( PARI floor pari2num Mod lift pari2pv );

use vars qw( $VERSION );
$VERSION = '0.02';

sub new {
    my $class = shift;
    my $dh = bless {}, $class;
    $dh->init(@_);
    $dh;
}

BEGIN {
    no strict 'refs';
    for my $meth (qw( p g pub_key priv_key )) {
        *$meth = sub {
            my($key, $value) = @_;
            if (ref $value eq 'Math::Pari') {
                $key->{$meth} = pari2pv($value);
            }
            elsif ($value && !(ref $value)) {
                if ($value =~ /^0x/) {
                    $key->{$meth} = pari2pv(Math::Pari::_hex_cvt($value));
                }
                else {
                    $key->{$meth} = $value;
                }
            }
            my $ret = $key->{$meth} || "";
            $ret = PARI("$ret") if $ret =~ /^\d+$/;
            $ret;
        };
    }
}

sub init {
    my $dh = shift;
    my %param = @_;
    for my $w (qw( p g )) {
        $dh->$w($param{$w});
    }
}

sub generate_keys {
    my $dh = shift;
    my $i = bitsize($dh->{p}) - 1;
    $dh->{priv_key} = makerandom(Size => $i, Strength => 0);
    $dh->{pub_key} = mod_exp($dh->{g}, $dh->{priv_key}, $dh->{p});
}

sub size {
    my $dh = shift;
    bitsize($dh->{p}) / 8;
}

sub compute_key {
    my $dh = shift;
    my $pub_key = shift;
    mod_exp($pub_key, $dh->{priv_key}, $dh->{p});
}

sub bitsize {
    return pari2num(floor(Math::Pari::log($_[0])/Math::Pari::log(2)) + 1);
}

sub mp2bin {
    my $p = shift;
    my $base = PARI(256);
    my $res = '';
    {
        my $r = $p % $base;
        my $d = PARI($p-$r) / $base;
        $res = chr($r) . $res;
        if ($d >= $base) {
            $p = $d;
            redo;
        }
        elsif ($d != 0) {
            $res = chr($d) . $res;
        }
    }
    $res;
}

sub mod_exp {
    my($a, $exp, $n) = @_;
    my $m = Mod($a, $n);
    lift($m ** $exp);
}

1;
__END__

=head1 NAME

Crypt::DH - Diffie-Hellman key exchange system

=head1 SYNOPSIS

    use Crypt::DH;
    my $dh = Crypt::DH->new;
    $dh->g($g);
    $dh->p($p);

    ## Generate public and private keys.
    $dh->generate_keys;

    ## Send public key to "other" party, and receive "other"
    ## public key in return.

    ## Now compute shared secret from "other" public key.
    my $shared_secret = $dh->compute_key( $other_pub_key );

=head1 DESCRIPTION

I<Crypt::DH> is a Perl implementation of the Diffie-Hellman key
exchange system. Diffie-Hellman is an algorithm by which two
parties can agree on a shared secret key, known only to them.
The secret is negotiated over an insecure network without the
two parties ever passing the actual shared secret, or their
private keys, between them.

=head1 THE ALGORITHM

The algorithm generally works as follows: Party A and Party B
choose a property I<p> and a property I<g>; these properties are
shared by both parties. Each party then computes a random private
key integer I<priv_key>, where the length of I<priv_key> is at
most (number of bits in I<p>) - 1. Each party then computes a
public key based on I<g>, I<priv_key>, and I<p>; the exact value
is

    g ^ priv_key mod p

The parties exchange these public keys.

The shared secret key is generated based on the exchanged public
key, the private key, and I<p>. If the public key of Party B is
denoted I<pub_key_B>, then the shared secret is equal to

    pub_key_B ^ priv_key mod p

The mathematical principles involved insure that both parties will
generate the same shared secret key.

More information can be found in PKCS #3 (Diffie-Hellman Key
Agreement Standard):

    http://www.rsasecurity.com/rsalabs/pkcs/pkcs-3/

=head1 USAGE

I<Crypt::DH> implements the core routines needed to use
Diffie-Hellman key exchange. To actually use the algorithm,
you'll need to start with values for I<p> and I<g>; I<p> is a
large prime, and I<g> is a base which must be larger than 0
and less than I<p>.

I<Crypt::DH> uses I<Math::Pari> internally for big-integer
calculations. All accessor methods (I<p>, I<g>, I<priv_key>, and
I<pub_key>) thus return I<Math::Pari> objects, as does the
I<compute_key> method.

=head2 $dh = Crypt::DH->new

Constructs a new I<Crypt::DH> object and returns the object.

=head2 $dh->p([ $p ])

Given an argument I<$p>, sets the I<p> parameter (large prime)
for this I<Crypt::DH> object.

Returns the current value of I<p>.

=head2 $dh->g([ $g ])

Given an argument I<$g>, sets the I<g> parameter (base) for
this I<Crypt::DH> object.

Returns the current value of I<g>.

=head2 $dh->generate_keys

Generates the public and private key portions of the I<Crypt::DH>
object, assuming that you've already filled I<p> and I<g> with
appropriate values.

=head2 $dh->compute_key( $public_key )

Given the public key I<$public_key> of Party B (the party with which
you're performing key negotiation and exchange), computes the shared
secret key, based on that public key, your own private key, and your
own large prime value (I<p>).

Returns the shared secret.

=head2 $dh->priv_key

Returns the private key.

=head2 $dh->pub_key

Returns the public key.

=head1 AUTHOR & COPYRIGHT

Benjamin Trott, ben@rhumba.pair.com

Except where otherwise noted, Crypt::DH is Copyright 2001
Benjamin Trott. All rights reserved. Crypt::DH is free
software; you may redistribute it and/or modify it under
the same terms as Perl itself.

=cut
