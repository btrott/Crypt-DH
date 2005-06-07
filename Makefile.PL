# $Id: Makefile.PL 1854 2005-06-07 00:54:36Z btrott $

use inc::Module::Install;

name('Crypt-DH');
abstract('Diffie-Hellman key exchange system');
author('Benjamin Trott <ben+cpan@stupidfool.org>');
version_from('lib/Crypt/DH.pm'),
license('perl');
no_index(directory => 't');
sign(1);

include('ExtUtils::AutoInstall');

requires('Math::BigInt' => '1.60');

auto_include();
auto_install();

&WriteAll;
