# $Id: Makefile.PL,v 1.1 2001/04/10 21:26:36 btrott Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME => 'Crypt::DH',
    DISTNAME => 'Crypt-DH',
    VERSION_FROM => 'lib/Crypt/DH.pm',
    AUTHOR => 'Benjamin Trott <ben@rhumba.pair.com>',
    ABSTRACT => 'Diffie-Hellman key exchange system',
    PREREQ_PM => {
        'Math::Pari' => '2.001804',
        'Crypt::Random' => '0.33',
    },
);
