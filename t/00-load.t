#!perl -T
use 5.006;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'X509Factory' ) || print "Bail out!\n";
}

diag( "Testing X509Factory $X509Factory::VERSION, Perl $], $^X" );
