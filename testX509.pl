use strict;

use x509factory::X509Factory qw(
   $TYPCLIENT
   $KEYUSESIG
   $KEYUSEKEYENC
   $EXTCLIENTAUTH
);

my $config = {
   debug        => 1,
   country      => "DE",
   state        => "Germany",
   location     => "Augsburg",
   organisation => "CryptoMagic GmbH",
   commonname   => 'markus.schraeder@cryptomagic.eu',
   serial       => "00", # Das naechsthoere wird genommen!
   days         => 1095,
   pass         => "1234",
   hash         => "sha512",
   rsasize      => "4096",
   comment      => "CryptoMagic CryptoApp Tunnel Client",
   flags        =>
      $TYPCLIENT    |
      $KEYUSESIG    |
      $KEYUSEKEYENC |
      $EXTCLIENTAUTH,
};

foreach my $curdef (["key", "cacrt.sign.key", ],
                    ["ca",  "cacrt.sign.crt", ]) {
   if (-s $curdef->[1]) {
      open(my $fd, "<", $curdef->[1]);
      while (<$fd>) {
         $config->{$curdef->[0]} .= $_;
      }
   } else {
      print STDERR "No ca and/or no key, doing selfsigned.\n";
      $config->{selfsign}++;
      last;
   }
}

my $result = x509factory::X509Factory::createCertificate($config);
if ($result->{crt}) {
   print $result->{crt};
} else {
   print STDERR "Fehler bei".($result->{crs} ? " der Zertifikatsanfrage" : "m Signieren").".\n";
}
