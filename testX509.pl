use strict;

use x509factory::X509Factory qw(
   $ISCA
   $TYPECASSL
   $KEYUSECERTSIGN
   $KEYUSECRLSIG
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
   selfsign     => 1,
   comment      => "CryptoMagic Client",
   flags        =>
      $TYPCLIENT     |
      $KEYUSESIG     |
      $KEYUSEKEYENC  |
      $EXTCLIENTAUTH,
};

foreach my $curdef (["key", "cacrt.sign.key", ],
                    ["ca",  "cacrt.sign.crt", ]) {
   unless (-s $curdef->[1]) {
      print STDERR "No ca and/or no key, doing selfsigned.\n";
      $config->{selfsign}++;
      $config->{comment} = "CryptoMagic CA";
      $config->{flags} =  {
         $ISCA           |
         $TYPECASSL      |
         $KEYUSECERTSIGN |
         $KEYUSECRLSIG,
      };
      last;
   }
   open(my $fd, "<", $curdef->[1]);
   while (<$fd>) {
      $config->{$curdef->[0]} .= $_;
   }
}

my $result = x509factory::X509Factory::createCertificate($config);
if ($result->{crt}) {
   print $result->{key};
   print $result->{crt};
} else {
   print STDERR "Fehler bei".($result->{crs} ? " der Zertifikatsanfrage" : "m Signieren").".\n";
}
