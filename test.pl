use strict;
use X509::OpenSSL;
my $ca = X509::OpenSSL->new();

my $result = $ca->req('[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
C=DE
ST=LgoodALA
L=LOCAgoodTION
OU=ORGANIgoodSATION
CN=COMMONgoodNAME
[ v3_req ]
basicConstraints = CA:TRUE', "4712", "sha384", "rsa:4096", 31, "");

my $CAKEY = $result->[0];
my $CAREQ = $result->[1];
my $CAREQTXT = $result->[2];
#my $REQBIN = $result->[3];
#print "BIN".ref($REQBIN)."\n";
print "CAREQ\n=====\n".length($CAREQTXT)." Bytes\n\n";

$result = $ca->x509(undef, $CAKEY, "1234",
#$REQ,
undef,
"39999", "SHA384", 2, undef, "basicConstraints = CA:TRUE\n");

my $CA = $result->[0];
my $CATXT = $result->[1];

print "CA\n===\n".$CATXT."\n";
print "KEY\n===\n".length($CAKEY)." Bytes\n\n";

$ca = undef;

my $x = X509::OpenSSL->new();

my $result = $x->req('[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
C=DE
ST=LgoodALA
L=LOCAgoodTION
OU=ORGANIgoodSATION
CN=COMMONgoodNAME
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
IP.1 =1.2.3.4
DNS.1 =findme', "4712", "sha384", "rsa:4096", 31, ""); my $a = (
"-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAuApEFc5TtCuOYKi6hzRHHWzl8d1tNiPFCj8Usq6TW4gclP1D
9dQ5Sd5dH+gMzOpJBo0soBA9cwZtIj6NOPTa0Y7+GaQQFghZ30YVp4PEiIB3DUFf
DW/IwkFTT5qQYi8F4bG21BWyeEQ4b6bUwrTzndrjZ5Px9BTLs25VlD33Dvp1E7cn
w+HA7/ATfBU9a6jpERYasvuEz7niA1BgpVXV48BL//Co0LsM82L6K3Z7QBc5s+XF
cPKlK0fHNHtHRUN2FRuR2Xul9pXJ5QOON9T5BAZynAw7neYFi5uJXGEzKcEhp0PL
myTIYl0mF7dtsqsj8B3AkPUgbKpx2mjVwFW1uwIDAQABAoIBAQCLFi8Yb8Mwoc5L
XJkDf03Tfi5V2OslhGjwcnX5CBiTj01SiAlpascU/XlRmLS71L/1tJGqMjvOh2fI
/o8KIXqR70g4JpaFoDATnkrVO683HidbHDFy3S1TKb2FpqFBopoGVKGArRkg7SXd
s66Nq+WFQhykddnghirgYx1IGIBzjyqOsvEriFrXkafN9T1IqTyupqY1QKcjIyS8
/vzV87d+Y8obusAMSKaxX13hnTasfQ5Itqt7JrcPYDLVYnhQfrpNCEnp3Ys8aHzQ
JOJf5CWBY6xr9lFXNx+aHohW2jfJsm8RUY+j6xINm08xCvgNjwQG2hnkLb097hT2
54cRfcJxAoGBAOSmKM81xuTPU/bgQWM+DCprdXj4K/vKqg7KDP/nN7keda6dUOo8
TDO+BUcySuEBTNIF2McsFkQDZgJiDPG10zsAa6/rjQBFqsdKt2McpUdxoXFUOho3
IR5ve2DmNs6uYTz2rOmFPfK6g4x1/FIEOd88WhBNPXtN+B3STMUC3zU5AoGBAM4O
D9pvxwrflx3rGsvjI51dypOOxN1zjn1YXqoOPrWBP9c1uW3HC95CFfoheas90K5T
o+msNTEnWSN9Gs35titb4KTsLs4+r6158ByBfMr9Gzu4OcQryW52CMXExfd8LLGJ
XGehtLVzg+Dir1qiIVosco1Ba1EZct4c/7nBkVaTAoGBALAAkyNFYu9YBGrhnpOU
/Gpew1M1vS2ZiCPQNgd55PPTVYTuxY04kvO1TnzKYscmaAq2w3I1JoJ+FzS4Yvxg
GNOu9DW7XJMcDWRQyC87qqH+/uWsjvkE/LJf4Bnru76GjoUN4HX0wYWpOn+RhoNf
i2iiHTW1LyFOGDJkYgG4vzZJAoGAGVAq7Ge86P4Mv3UpZpCxyFxETZpFXvsaLxXT
E0sKsxt8r0B/VhgUwioWLxM7sii24SOPSF6Kbk5qKezthQ4/LdZso3YMTfPvev02
3RmfLgSn+s8n8Yx7g2FmtHz24O9VQj4gpu57l6roMZFHf3fZZw18yROXTnA050pi
s/wukZcCgYEAnxhHvG4H0egyIoKUxsnlanNOieqx0Lvtc21VI3nG6RSLEyfmCHAj
A+WiXAbskwiEFvYqy6+RIqJ+csYVHudT2hvG6PCkKEE3S/y5sNoNaUkPxjYFDMjL
8+qs13UhoK+o6JriPRGdCmBXuRndon4DTK3DhSlsG1KhM0rhzBTASzA=
-----END RSA PRIVATE KEY-----");

my $KEY = $result->[0];
my $REQ = $result->[1];
my $REQTXT = $result->[2];
#my $REQBIN = $result->[3];
#print "BIN".ref($REQBIN)."\n";
print "REQ\n===\n".$REQTXT."\n";

$result = $x->x509($CA, $CAKEY, "1234",
#$REQ,
undef,
"39999", "SHA384", 2, "basicConstraints = CA:FALSE\n");

my $CRT = $result->[0];
my $CRTTXT = $result->[1];

print "CRT\n===\n".$CRTTXT."\n";
print "KEY\n===\n".length($KEY)." Bytes\n\n";

print "PKCS12\n======\n\n";

my $pkcs12 = $x->pkcs12("1234", "4321", $CRT, $KEY,  "sha1");
print "PKCS12:".length($pkcs12)." Bytes\n";
open(OUT, ">", "/tmp/test.p12") || die $!;
syswrite(OUT, $pkcs12);
close OUT;
system("openssl pkcs12 -in /tmp/test.p12 -info -clcerts -password pass:4321 -passout pass:4321");
