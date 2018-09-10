﻿package X509Factory;
use strict;
use ELF::sign;

BEGIN {
   use Exporter;
   our @ISA = qw(Exporter);
   our @EXPORT = qw//;
   our @EXPORT_OK = qw(
      $ISCA $TYPEOBJ $TYPEMAIL $TYPSERVER $TYPCLIENT $TYPECAOBJ $TYPECAEMAIL
      $TYPECASSL $TYPERESERVED  $KEYUSESIG  $KEYUSENONREDU $KEYUSEKEYENC
      $KEYUSEDATAENC $KEYUSEKEYAGR  $KEYUSECERTSIGN $KEYUSECRLSIG $KEYUSEONLYENC
      $KEYUSEONLYDEC $EXTCLIENTAUTH $EXTSERVERAUTH $EXTOBJSIGN $EXTEMAIL
      $EXTTIMESTAMP  $EXTMSINSIGN $EXTMSCOMSIGN  $EXTMSCTLSIGN $EXTMSSGC
      $EXTMSEFS $EXTNSSGC);
}

my $i = 1;
my $opensslpath = 'openssl';

our $VERSION = 0.01;

### CA
our $ISCA           = 2**$i++;

### Types
our $TYPEOBJ        = 2**$i++;
our $TYPEMAIL       = 2**$i++;
our $TYPSERVER      = 2**$i++;
our $TYPCLIENT      = 2**$i++;
our $TYPECAOBJ      = 2**$i++;
our $TYPECAEMAIL    = 2**$i++;
our $TYPECASSL      = 2**$i++;
our $TYPERESERVED   = 2**$i++;

### Keyusage
our $KEYUSESIG      = 2**$i++;
our $KEYUSENONREDU  = 2**$i++;
our $KEYUSEKEYENC   = 2**$i++;
our $KEYUSEDATAENC  = 2**$i++;
our $KEYUSEKEYAGR   = 2**$i++;
our $KEYUSECERTSIGN = 2**$i++;
our $KEYUSECRLSIG   = 2**$i++;
our $KEYUSEONLYENC  = 2**$i++;
our $KEYUSEONLYDEC  = 2**$i++;

### Extensions
our $EXTCLIENTAUTH  = 2**$i++;
our $EXTSERVERAUTH  = 2**$i++;
our $EXTOBJSIGN     = 2**$i++;
our $EXTEMAIL       = 2**$i++;
our $EXTTIMESTAMP   = 2**$i++;
# Microsoft
our $EXTMSINSIGN    = 2**$i++;
our $EXTMSCOMSIGN   = 2**$i++;
our $EXTMSCTLSIGN   = 2**$i++;
our $EXTMSSGC       = 2**$i++;
our $EXTMSEFS       = 2**$i++;
# Netscape 
our $EXTNSSGC       = 2**$i++;

sub createCertificate {
   my $cconfig = shift;
   foreach my $key (keys %$cconfig) {
      if (($key eq "ca")  ||
          ($key eq "key") ||
          ($key eq "certconf")) {
         $cconfig->{$key} =~ s,[^a-zA-Z0-9\ \:\-\+\=\/\,\n],,g;
      } elsif($key eq "days") {
         $cconfig->{$key} =~ s,[^0-9],,g;
      } elsif($key eq "serial") {
         $cconfig->{$key} =~ s,[^a-zA-Z0-9],,g;
      } elsif((ref($cconfig->{$key}) eq "ARRAY") && ($key eq "commonaltnames")) {
         foreach my $val (@{$cconfig->{$key}}) {
            $val =~ s,[^a-zA-Z0-9\ \:\-\+\=\_\/\,\~\.\;\<\>\@],,g;
         }
      } else {
         $cconfig->{$key} =~ s,[^a-zA-Z0-9\ \:\-\_\+\=\/\,\~\.\;\<\>\@],,g;
      }
   }
   return { err => "No ca!" }
      if (!$cconfig->{ca} &&
          !$cconfig->{selfsign} &&
          !$cconfig->{onlycsr});
   return { err => "No key!" }
      if ($cconfig->{ca} &&
         !$cconfig->{key});
   my $return = {};
   my $out = undef;
  my $i = 1;
  my $j = 1;
  my $reqconf =
     "[ req ]"."\n".
  "prompt = no"."\n".
  "distinguished_name = req_distinguished_name"."\n".($cconfig->{commonaltnames} ?
  "req_extensions = v3_req"."\n" : "").
  "[ req_distinguished_name ]"."\n".
  "C=".$cconfig->{country}."\n".
  "ST=".$cconfig->{state}."\n".
  "L=".$cconfig->{location}."\n".
  "OU=".$cconfig->{organisation}."\n".
  "CN=".$cconfig->{commonname}."\n".($cconfig->{commonaltnames} ?
  "[ v3_req ]"."\n".
  #"basicConstraints = CA:FALSE"."\n".
  #"keyUsage = nonRepudiation, digitalSignature, keyEncipherment"."\n".
  'subjectAltName = @alt_names'."\n".
  "[alt_names]"."\n".
  join("\n", map { (/^[\d\.]+$/ ? "IP.".$i++ : "DNS.".$j++)." = ".$_ } @{$cconfig->{commonaltnames}}) : "");
  my $x = ELF::sign->new();
  my $result = $x->req($reqconf, undef, 'sha256', "rsa:2048", 31, undef, $cconfig->{SPKAC} || "");
  $return->{csr} = $result->[1];
  $return->{key} = $result->[0];
  #print "REQUEST:".$result->[3]."\n";
  return $return
     if (!$return->{csr} || $cconfig->{onlycsr});
  my $crswriteer = WriteForkFd($return->{csr});
  my $types = join(", ", map { $_->[0] } grep {
     print STDERR $_->[0].":".$cconfig->{flags}.' & '.$_->[1]." = ".(int($cconfig->{flags}) & int($_->[1]))."\n"
        if $cconfig->{debug};
     ($cconfig->{flags} & $_->[1])
  } (
     ["client",           $TYPCLIENT],
     ["server",           $TYPSERVER],
     ["email",            $TYPEMAIL],
     ["objsign",          $TYPEOBJ],
     ["reserved",         $TYPERESERVED],
     ["objCA",            $TYPECAOBJ],
     ["emailCA",          $TYPECAEMAIL],
     ["sslCA",            $TYPECASSL],
  ));
  my $keyusage = join(", ", map { $_->[0] } grep {
     print STDERR $_->[0].":".$cconfig->{flags}.' & '.$_->[1]." = ".(int($cconfig->{flags}) & int($_->[1]))."\n"
        if $cconfig->{debug};
     ($cconfig->{flags} & $_->[1])
  } (
     ["digitalSignature", $KEYUSESIG],
     ["nonRepudiation",   $KEYUSENONREDU],
     ["keyEncipherment",  $KEYUSEKEYENC],
     ["dataEncipherment", $KEYUSEDATAENC],
     ["keyAgreement",     $KEYUSEKEYAGR],
     ["keyCertSign",      $KEYUSECERTSIGN],
     ["cRLSign",          $KEYUSECRLSIG],
     ["encipherOnly",     $KEYUSEONLYENC],
     ["decipherOnly",     $KEYUSEONLYDEC],
  ));
  my $extkeyusage = join(", ", map { $_->[0] } grep {
     print STDERR $_->[0].":".$cconfig->{flags}.' & '.$_->[1]." = ".(int($cconfig->{flags}) & int($_->[1]))."\n"
        if $cconfig->{debug};
     ($cconfig->{flags} & $_->[1])
  } (
     ["clientAuth",       $EXTCLIENTAUTH],
     ["serverAuth",       $EXTSERVERAUTH],
     ["codeSigning",      $EXTOBJSIGN],
     ["emailProtection",  $EXTEMAIL],
     ["timeStamping",     $EXTTIMESTAMP],
     ["msCodeInd",        $EXTMSINSIGN],
     ["msCodeCom",        $EXTMSCOMSIGN],
     ["msCTLSign",        $EXTMSCTLSIGN],
     ["msSGC",            $EXTMSSGC],
     ["msEFS",            $EXTMSEFS],
     ["nsSGC",            $EXTNSSGC],
  ));
  my $comment = $cconfig->{comment};
  my $extstr =
     "basicConstraints = CA:".(($cconfig->{flags} & $ISCA) ? "TRUE" : "FALSE")."\n".
  join("", map {
     $_->[1]." = ".$_->[0]."\n"
  } grep { $_->[0] } (
     [$types,              "nsCertType"],
     [$keyusage,           "keyUsage"],
     [$extkeyusage,        "extendedKeyUsage"],
     [$cconfig->{comment}, "nsComment"],
  ));
  $result = $x->signx($cconfig->{ca}, $cconfig->{key}, $cconfig->{pass},
     #$return->{csr},
     undef,
     $cconfig->{serial} || int(rand(int(2**63)+(int(2**63)-1))), $cconfig->{hash} || 'sha256', $cconfig->{days}, $extstr, $x->getreq());
   print STDERR "CA:".$cconfig->{ca}."\nKEY:".(length($cconfig->{key})||"-")."\nSELFSIGNKEY=".(length($return->{key}) || "-")."\nPASS:".$cconfig->{pass}."\n"
      if $cconfig->{debug};
   $return->{crt} = $result->[0];
   if ($cconfig->{SPKAC}) {
      print "SENDING:".$return->{crt}.":\n";
      $return->{out} = $return->{crt};
      return $return;
   }
   print STDERR "RESULT2:".$result->[1]."\n";
   my $crtwriter = WriteForkFd($return->{crt});
   my $keywriter = WriteForkFd($return->{key});
   $out = ReadFork(sub {
      my $outfd = shift;
      my @cmd = (
         $opensslpath,
         "pkcs12", "-export",
         "-in",    '/dev/fd/'.fileno($crtwriter),
         "-inkey", '/dev/fd/'.fileno($keywriter),
         "-out",   '/dev/fd/'.fileno($outfd),
         "-passin", "pass:''", "-passout", "pass:".($cconfig->{pkcs12pass}||""));
      exec(@cmd);
   });
   while (<$out>) {
      $return->{out} .= $_;
   }
   return $return;
}

sub doPipe {
   my $CLIENT = undef;
   my $SERVER = undef;
   $^F = 1024; # TODO:XXX:FIXME: Wir machen beim Forken gar keine Sockets mehr zu.... Sollten wir das so machen?
   pipe($CLIENT, $SERVER);
   return [$CLIENT, $SERVER];
}

sub WriteForkFd {
   my $data = shift;
   my ($CLIENT, $SERVER) = @{doPipe()};
   if (my $pid = fork) {
      close($SERVER);
      return $CLIENT;
   } else {
      my $id = fileno($CLIENT);
      close($CLIENT);
      my $real = syswrite($SERVER, $data);
      #print STDERR $id." WROTE ".$real." of ".length($data)." Bytes\n"; # .$data."\n";
      close($SERVER);
      exit(0);
   }
}

sub ReadFork {
   my $func = shift;
   my ($CLIENT, $SERVER) = @{doPipe()};
   if (my $pid = fork) {
      close($SERVER);
      return $CLIENT;
   } else {
      close($CLIENT);
      &$func($SERVER);
      exit(0);
   }
}

sub ReadForkFd {
   my $name = shift;
   my ($CLIENT, $SERVER) = @{doPipe()};
   if (my $pid = fork) {
      close($SERVER);
      return $CLIENT;
   } else {
      close($CLIENT);
      my $buf = '';
      while(<$SERVER>) {
         print $SERVER $_;
      }
      close($SERVER);
      exit(0);
   }
}

=head1 NAME

X509Factory - Create X509 Certificate requests and signed requests easy

=head1 VERSION

Version 0.01

=head1 DESCRIPTION

Create X509 Certificate requests and signed requests easy

=cut

1;