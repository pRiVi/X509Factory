package X509::OpenSSL;

use strict;
use Net::SSLeay;
use Fcntl qw(SEEK_END);
use Digest::SHA qw(sha512);
use X509::Factory;

use vars qw($VERSION @ISA);
$VERSION = '0.01';

BEGIN {
   eval {
      require Net::SSLeay;
      Net::SSLeay->import( 1.65 );
   };
   Net::SSLeay::load_error_strings();
   Net::SSLeay::SSLeay_add_ssl_algorithms();
   Net::SSLeay::randomize();
}

sub new {
   my $type = shift;
   my $params = {@_};
   my $self = bless({}, $type);
   $self->{debug}++;
   return $self;
}

sub pkcs12 {
   my $self = shift;
   my $passin = shift;
   my $passout = shift;
   my $certsfile = shift;
   my $keyfile = shift;
   my $macalg = shift;
   return X509::Factory::X509_OpenSSL_pkcs12($passin, $passout, $certsfile, $keyfile, $macalg);
}

sub x509 {
   my $self = shift;
   my $ca = shift;
   my $cakey = shift;
   my $cakeypass = shift;
   my $req = shift;
   my $serial = shift;
   my $hashing = shift;
   my $days = shift;
   my $extensions = shift;
   return X509::Factory::X509_OpenSSL_sign($ca, $cakey, $cakeypass, $req, $serial, $hashing, $days, $extensions, $req ? undef : $self->{reqbin} ? $self->{reqbin} : undef);
}

sub req {
   my $self = shift;
   my $config = shift;
   my $serial = shift;
   my $hashing = shift;
   my $privatekeytype = shift;
   my $days = shift;
   my $privatekey = shift;
   my $spkac = shift;
   if ($self->{reqbin}) {
      #print "FREEING ".$self->{reqbin}."\n";
      $self->freereq($self->{reqbin});
      delete $self->{reqbin};
   }
   my $return = X509::Factory::X509_OpenSSL_req($config, $serial, $hashing, $privatekeytype, $days, $privatekey, $spkac);
   if ($return->[3]) {
      $self->{reqbin} = $return->[3];
      $return->[3] = undef;
   }
   return $return;
}

sub freereq {
   my $self = shift;
   my $req = shift;
   return X509::Factory::X509_OpenSSL_freereq($req);
}

sub getreq {
   my $self = shift;
   return $self->{reqbin};
}


sub DESTROY {
   my $self = shift;
   #print "DESTROYING ".$self->{reqbin}."\n";
   if ($self->{reqbin}) {
      $self->freereq($self->{reqbin});
      delete $self->{reqbin};
   }
}

1;

__END__

=head1 NAME

X509::OpenSSL

=head1 VERSION

Version 0.01

=over 2

=back

=head1 DESCRIPTION

-

=over 2

=back

=head1 SYNOPSIS

-

=head2 A

   use X509::OpenSSL;
   ...

=head1 FUNCTIONS

=over 2

=item new

Returns a new I<ELF::sign> object. It ignores any options.

=item req

-

=item x509

-

=back

=head2 Internal functions

=over 2

=item doreq()

=back

=head1 Commercial support

Commercial support can be gained at <elfsignsupport at cryptomagic.eu>.

Used in our products, you can find on L<https://www.cryptomagic.eu/>

=head1 COPYRIGHT & LICENSE

Copyright 2010-2018 Markus Schraeder, CryptoMagic GmbH, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of X509::OpenSSL
