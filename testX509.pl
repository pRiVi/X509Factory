use strict;

use x509factory::X509Factory qw(
   $TYPCLIENT
   $KEYUSESIG
   $KEYUSEKEYENC
   $EXTCLIENTAUTH
);

my $config = {
   country      => "DE",
   state        => "Germany",
   location     => "Augsburg",
   organisation => "CryptoMagic GmbH",
   commonname   => 'markus.schraeder@cryptomagic.eu',
   serial       => "00", # Das naechsthoere wird genommen!
   days         => 1095,
   pass         => "1234",
   comment      => "CryptoMagic CryptoApp Tunnel Client",
   flags        => 
      $TYPCLIENT    |
      $KEYUSESIG    |
      $KEYUSEKEYENC |
      $EXTCLIENTAUTH,
};

foreach my $curdef (["ca",  "cacrt.sign.crt", ],
                    ["key", "cacrt.sign.key", ]) {
   open(my $fd, "<", $curdef->[1]);
   while (<$fd>) {
      $config->{$curdef->[0]} .= $_;
   }
}

my $result = x509factory::X509Factory::createCertificate($config);
if ($result->{crt}) {
   print $result->{crt};
} else {
   print STDERR "Fehler bei".($result->{crs} ? " der Zertifikatsanfrage" : "m Signieren").".\n";
}
