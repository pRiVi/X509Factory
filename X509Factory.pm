package x509factory::X509Factory;
use strict;

# TODO:XXX:FIXME:
# - Im POE::Filter:SSL überprüfen obs wirklich ein Clientzertifikat ist.

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
my $debug = 0;

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
            $val =~ s,[^a-zA-Z0-9\ \:\-\+\=\/\,\~\.\;\<\>\@],,g;
         }
      } else {
         $cconfig->{$key} =~ s,[^a-zA-Z0-9\ \:\-\+\=\/\,\~\.\;\<\>\@],,g;
      }
   }
   return { err => "No ca!" }
      if (!$cconfig->{ca} &&
          !$cconfig->{onlycsr});
   return { err => "No key!" }
      if ($cconfig->{ca} &&
         !$cconfig->{key});
   my $return = {};
   my $out = undef;
   if ($cconfig->{SPKAC}) {
      $cconfig->{SPKAC} =~ s,[^a-zA-Z0-9\ \:\-\+\=\/],,g;
      my $pass   = WriteForkFd($cconfig->{pass});
      my $cacrt  = WriteForkFd($cconfig->{ca});
      my $cakey  = WriteForkFd($cconfig->{key});
      my $serial = WriteForkFd($cconfig->{serial});
      my $serial2 = WriteForkFd($cconfig->{serial});
      unlink "/tmp/serial";
      symlink("/dev/fd/".fileno($serial2), "/tmp/serial");
      unlink "/tmp/serial.new";
      symlink("/dev/fd/".fileno($serial2), "/tmp/serial.new");
      unlink "/tmp/null";
      symlink("/dev/fd/".fileno($serial), "/tmp/null");
      symlink("/dev/null", "/tmp/null.attr");
      my $days   = $cconfig->{days};
      my $config =
         "[ ca ]"."\n".
         "default_ca      = CA_default"."\n".
         "[ CA_default ]"."\n".
         #"dir             = ."."\n".
         "certs           = /tmp/"."\n".
         #"crl_dir         = ./crl"."\n".
         "database        = /tmp/null"."\n".
         "new_certs_dir   = /tmp/"."\n".
         "certificate     = /dev/fd/".fileno($cacrt)."\n".
         "serial          = /tmp/serial"."\n".
         #"crl             = ./crl.pem"."\n".
         "private_key     = /dev/fd/".fileno($cakey)."\n".
         #"RANDFILE        = ./private/.rand"."\n".
         "x509_extensions = usr_cert"."\n".
         "default_md      = default"."\n".
         "policy          = policy_match"."\n".
         "[ policy_match ]"."\n".
         "countryName             = optional"."\n".
         "stateOrProvinceName     = optional"."\n".
         "organizationName        = optional"."\n".
         "organizationalUnitName  = optional"."\n".
         "commonName              = supplied"."\n".
         "emailAddress            = optional"."\n".
         "[ usr_cert ]"."\n".
         "basicConstraints=CA:FALSE"."\n".
         'nsComment               = "OpenSSL Generated Certificate"'."\n".
         "subjectKeyIdentifier    = hash"."\n".
         "authorityKeyIdentifier  = keyid,issuer"."\n";
      #print $config."\n";
      my $configwriter = WriteForkFd($config);
      my $req =
      # TODO:XXX:FIXME: Params filtern!
         "SPKAC=".              $cconfig->{SPKAC}."\n".
         "CN=".                 $cconfig->{commonname}."\n".
         "emailAddress=".       $cconfig->{email}."\n".
         "organizationName=".   $cconfig->{organisation}."\n".
         "countryName=".        $cconfig->{country}."\n".
         "stateOrProvinceName=".$cconfig->{state}."\n".
         "localityName=".       $cconfig->{location};
      print $req."\n"
         if $debug;
      my $spkacwriter  = WriteForkFd($req);
      my $days = $cconfig->{days};
      $out = ReadFork(sub {
         my $outfd = shift;
         my @cmd = (
            $opensslpath,
            'ca',
            ($days ? ('-days', $days) : ()),
            "-notext",
            "-batch",
            "-config", '/dev/fd/'.fileno($configwriter),
            '-passin', 'fd:'.fileno($pass),
            "-spkac",  '/dev/fd/'.fileno($spkacwriter),
            '-out',    '/dev/fd/'.fileno($outfd),
         );
         print "Running '".join(" ", @cmd)."'\n"
            if $debug;
         exec(@cmd);
      });
   } else {
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
      my $certconfig = WriteForkFd($reqconf);
      my $key = ReadForkFd('KEY');
      my $csr = ReadFork(sub {
         my $outfd = shift;
         my @cmd = (
            $opensslpath,
            'req',
            '-passin', 'pass:',
            '-passout', 'pass:',
            '-new',
            '-newkey',
            'rsa:2048',
            '-sha256',
            '-nodes',
            '-keyout', '/dev/fd/'.fileno($key),
            '-config', '/dev/fd/'.fileno($certconfig),
            '-out',    '/dev/fd/'.fileno($outfd)
         );
         print "Running '".join(" ", @cmd)."'\n"
            if $debug;
         exec(@cmd);
      });
      foreach my $curdef (["csr", $csr],
                          ["key", $key]) {
         my $fd = $curdef->[1];
         while (<$fd>) {
            $return->{$curdef->[0]} .= $_;
         }
      }
      return $return
         if (!$return->{csr} || $cconfig->{onlycsr});
      my $crswriteer = WriteForkFd($return->{csr});
      my $types = join(", ", map { $_->[0] } grep {
         print $_->[0].":".$cconfig->{flags}.' & '.$_->[1]." = ".(int($cconfig->{flags}) & int($_->[1]))."\n"
            if $debug;
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
         print $_->[0].":".$cconfig->{flags}.' & '.$_->[1]." = ".(int($cconfig->{flags}) & int($_->[1]))."\n"
            if $debug;
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
         print $_->[0].":".$cconfig->{flags}.' & '.$_->[1]." = ".(int($cconfig->{flags}) & int($_->[1]))."\n"
            if $debug;
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
      my $extensions = WriteForkFd(
         "basicConstraints = CA:".(($cconfig->{flags} & $ISCA) ? "TRUE" : "FALSE")."\n".
         join("", map {
            $_->[1]." = ".$_->[0]."\n"
         } grep { $_->[0] } (
            [$types,              "nsCertType"],
            [$keyusage,           "keyUsage"],
            [$extkeyusage,        "extendedKeyUsage"],
            [$cconfig->{comment}, "nsComment"],
         ))
      );
      my $pass   = WriteForkFd($cconfig->{pass});
      my $cacrt  = WriteForkFd($cconfig->{ca});
      my $cakey  = WriteForkFd($cconfig->{key});
      my $serial = WriteForkFd($cconfig->{serial});
      my $days   = $cconfig->{days};
      print "CA:".$cconfig->{ca}."\nKEY:".$cconfig->{key}."\nPASS:".$cconfig->{pass}."\n"
         if $debug;
      my $crt = ReadFork(sub {
         my $outfd = shift;
         my @cmd = (
            $opensslpath,
            'x509',
            '-sha256',
            '-req',
            '-CAcreateserial',
            ($days ? ('-days', $days) : ()),
            '-passin',        'fd:'.fileno($pass),
            '-CA',       '/dev/fd/'.fileno($cacrt),
            '-in',       '/dev/fd/'.fileno($crswriteer),
            '-CAkey',    '/dev/fd/'.fileno($cakey),
            '-CAserial', '/dev/fd/'.fileno($serial),
            '-extfile',  '/dev/fd/'.fileno($extensions),
            '-out',      '/dev/fd/'.fileno($outfd)
         );
         #print "Running '".join(" ", @cmd)."'\n";
         exec(@cmd);
      });
      while (<$crt>) {
         $return->{crt} .= $_;
      }
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
   }
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
      #print $id." WROTE ".$real." of ".length($data)." Bytes\n"; # .$data."\n";
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
