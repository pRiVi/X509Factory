use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'X509::Factory',
    AUTHOR           => q{Markus Schraeder <privi@cpan.org>},
    VERSION_FROM     => 'lib/X509/Factory.pm',
    ABSTRACT_FROM    => 'lib/X509/Factory.pm',
    LICENSE          => 'Artistic_2_0',
    OBJECT           => ['openssl.o', 'apps.o', 'app_rand.o', 'opt.o', 'cm_helper.o', 'cm_x509.o', 'cm_req.o', 'cm_pkcs12.o', 'cm_openssl.o'],
    INC              => '-I. -Iinc/',
    LIBS		         => ['-ldl -lssl -lcrypto'],
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        'Test::More' => 0,
        'Net::SSLeay'   => '1.65',
        'XSLoader'      => 0,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'X509::Factory-*' },
);
