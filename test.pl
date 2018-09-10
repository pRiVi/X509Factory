use strict;
use X509::OpenSSL;
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
basicConstraints = CA:TRUE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
IP.1 =1.2.3.4
DNS.1 =findme', "4712", "sha384", "rsa:4096", 31, #""); my $a = (
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
print "REQ\n===\n".$REQ."\n";

$result = $x->x509('-----BEGIN CERTIFICATE-----
MIIDaDCCAlCgAwIBAgIJAPFYhBfnlwcEMA0GCSqGSIb3DQEBCwUAMGExCzAJBgNV
BAYTAkRFMRAwDgYDVQQIEwdHZXJtYW55MREwDwYDVQQHEwhBdWdzYnVyZzEZMBcG
A1UEChMQQ3J5cHRvTWFnaWMgR21iSDESMBAGA1UECxMJQ3J5cHRvQXBwMB4XDTE4
MDkwNjE5MDkyOVoXDTQzMTExNDE5MDkyOVowYTELMAkGA1UEBhMCREUxEDAOBgNV
BAgTB0dlcm1hbnkxETAPBgNVBAcTCEF1Z3NidXJnMRkwFwYDVQQKExBDcnlwdG9N
YWdpYyBHbWJIMRIwEAYDVQQLEwlDcnlwdG9BcHAwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQC4V9wwEEp4N3SpBWkc09vAorMgLbH83dX1mtpTkIqt7BTs
wP07SvhdqV4F9w6xXBu4Ag79UTkGbY3vNOiEZ7JugTxsx2JD0S4DryyUW7zr0Q+M
o97rpWTxGlkYk1xFhNmSh219oVfpSepJNDKib37OfKk6wkPmk6gOb2wxxoRSgGzA
7we+EjLuIlzUj260E27n6aqKO6LLJcF2YiKZIuvk53kszlGLxRJw1PGCetl0802m
jvGFi395/2rE0PFMpzFDBG+uCV1S3TqxBWilSKUaVm5RVgRyE+ftTL4fQm06++0R
VGDj3bFqgwIlSC/dC3LQn5/6ra8OB0xHo7xDCZEVAgMBAAGjIzAhMBIGA1UdEwEB
/wQIMAYBAf8CAQEwCwYDVR0PBAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQA7aoRJ
32+ua7Y5YUhftfaX2oeeObbsYJLHqxmb/PTouCp1SLPu6pJM+qzzJXpPTf48uWac
7+f3T+bQCKhtvacZXu6OkyEBl5ajiB6p5vkpGkDHXQ35D9th/MfrjCSVsFqBN3bB
UkchkjOmGsWt5ILw7eNGE62OTVzkdCASly3qw9peMIvk0Q2OZZInl3yTqiAG+CbD
KRJ85pUP+bigvPdD3dJCLZbutnJbb8LxWJUJw7x8LTToXIyhEZwO2sqcUs7f1xr3
piEZxPEhB+Qqs08QOylSGJ9ONb8eUXr9LYXdudbTL0ypWJWVBK/kM8HMivosXfwK
vev7a9LpNXVX2V+L
-----END CERTIFICATE-----', '-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,5D44B5054BB7DC4F

JzX5TZ2tfDjaRI3gG0cskLIXhmlys1G9/ij/CfSh33y27i2uo4A3Br1bsH77bGsr
Y7azSlfMNHDGZQCPYyn6ld7zzx5ahq8t9gxXkzKKqLNOvN+Zv91Ckr4zhxtFw5EK
Prwdc2xd0NtorJjNN5BA5HLRVv51Pd5KvsKMFXiNuROtZKHUXKjj6xvnv+J3NzZx
KtXpdwqgFKk96bxf2jAzSlkXIBwbjGIFMd13zsr5v/p6JfIvKy7R2fDsSJt7HOW+
U+SAHQ7rgLkNzmJhLLmhhhfzdEtzSWBW9pSsbNlo205Y+juct5L2R8hFqClDEpem
zrK62Gbv9r5KQPzcFQWayR+TjeOnvQzTlbzdY8W23SIpo+lw78Thb2j4Ji0WS4As
zgLRY5x0eJhK1HJC2sm6ink4rTRoLm5X20tjNY4ucBSrYazW7jzbNCDYYjEQYJp3
9c/9vryeoEvTEtWQuqxyZ69wFuHAgAPYbnCt4ZxN8ws7vBXsbkBe/BiY46Bns79e
Z2BSbV48XsUG4Qb5r95v+fKIX6Ghhz16K94k5CAta8Vm/YFZQXhq7oHcL21a2rGC
sKLo/fICep96FCiyvLx4WcEFP95JRvkX08i52fL8WzdjrY5/frBWNt/c6LWMUDeT
KAZTeil4dVek5eqkqSUqr2BBLh28DmvTQKhBoMM3XSWCFCOUzmRjvw/7r/WxiJGv
fAw8Wt7/9FXp6kr4YTGIlwJVf16EDDuCZKkfvSqW86BX+gkHHpoJu1MtDuWowpPu
/qqXh62Vzyr8pSZ7gORj7QBQOghZhLuJC4KW1DJEqJlCkesfObjrkMLqX+iRCs2Y
WOf8aVboc6aMVxQaSIVo2CDiOhiQcfULU3MJnDdAjszATsBYRnYIm39qvGP5OFyr
o/xa2fSyFrCCXWctlDPWCWxs7oNslewgN3ILipiMn0PaFwm/AvAs/Am7ysBUxUIV
pKuKDM3WdBKMr56QnT2WMIa9fGapF+nh6ochI4ZqvELNjdLe2vqX6bmz3QKnmtYc
Mimi4E4nF986njaxEqu/Ov7qGig9tOqUxegLy1GRaHz4UI/x6Xxxc9tWTKbrSQpz
Pcyk1Zz9JbJBKVhQNr0Y4gOZ58BSqbQqKRL5OYs+RnXgKsrN2dn+HfJ3D5yFxyG9
t9gKbrDXQ+Ij1LKgLn3ksYWocNQjjD1VftY/yU4HhYkKJyUSY48kQ5EVXRJEOMzX
u4ik0AOXgPIqDEekf4CUgBD7nQWztFfU57wQ0vhHwwO87lkta8Evyr/D8mtWloAB
DWD0PZMolaigqL57QWAEub/MKMZL2lICwacKqtkVJqe/AdunxeorA1SXZEO+XDgx
FXM0jkF7tkxC7HedQ0JMA69fIM+Y5+Kg7kh4UoomfZzOsdLDpyp8t0b4D3XERj51
Tyo7yUPFlOq+kQl9eD1A+ZU/uhCvNqWJz4CyWrqFrIQQ2A2aD7VrU+NK9Per4y4s
DEPVL8zgCU14X2iMKFN/ukP+1vNiUx2EfWgnfj48SOs+HwCdipI9GmHn2UfR7qpl
iVTp6zBF3DUpPSy7uGS13NE04j2wGklhhwCgNtFUFZal7BSNUgMGCQ==
-----END RSA PRIVATE KEY-----', "1234", #$REQ,
undef,
 "39999", "SHA384", 2, # undef,
"basicConstraints = CA:FALSE\n"#, $x->getreq()
);
my $CRT = $result->[0];
my $CRTTXT = $result->[1];

print "CRT\n===\n".$CRTTXT."\n";
print "KEY\n===\n".$KEY."\n";

my $pkcs12 = $x->pkcs12("1234", "4321", $CRT, $KEY,  "sha1");
print "PKCS12:".length($pkcs12)."\n";
open(OUT, ">", "/tmp/test.p12") || die $!;
syswrite(OUT, $pkcs12);
close OUT;
system("openssl pkcs12 -in /tmp/test.p12 -info -clcerts -password pass:4321 -passout pass:4321");
