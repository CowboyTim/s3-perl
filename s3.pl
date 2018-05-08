#!/usr/bin/perl

use strict; use warnings;

use Data::Dumper;
use Pod::Usage;
use POSIX qw(strftime);
use Time::Local qw(timegm);
use File::Basename qw(dirname);

use MIME::Base64 qw(encode_base64);
use Digest::SHA qw(hmac_sha1 hmac_sha256 hmac_sha256_hex);
use Getopt::Long qw(:config no_ignore_case bundling);
use XML::Simple;
use AnyEvent::HTTP;
use AnyEvent::TLS;
use AE;
use AnyEvent::Log;

my ($id, $key);
if(open(my $fh, "<".glob("~/.passwd-s3fs"))){
    local $/;
    ($id, $key) = split m/:/, scalar(<$fh>);
    chop($key);
    close($fh);
}

GetOptions(
    my $opts = {
        key     => $key,
        id      => $id,
        method  => 'list',
        region  => 'us-east-1',
        url     => "s3.amazonaws.com",
        verbose => 0,
    },
    "bucket|b=s",
    "method|m=s",
    "key|k=s",
    "id=s",
    "acl|a=s",
    "url|u=s",
    "insecure!",
    "signv4!",
    "region=s",
    "verbose|v+",
    "l!"
) or pod2usage(1);
pod2usage(-message => "Please specify --bucket <bucketname>\n",
          -exitval => 2) unless defined $opts->{bucket};
pod2usage(-message => "Please specify --key <key> --id <id>\n",
          -exitval => 2) unless defined $opts->{key} and defined $opts->{id};

$AnyEvent::Log::FILTER->level($opts->{verbose}==1?'info':$opts->{verbose}==2?'debug':'note');

my $headers = {
    (defined $opts->{'acl'}         ?('x-amz-acl'    => $opts->{'acl'})         :()),
    (defined $opts->{'content-type'}?('content-type' => $opts->{'content-type'}):()),
};

{
    no warnings 'once';
    *{ls} = *{dir} = \&list;
    *{rm} = *{del} = \&delete;
    *{mv} = \&replace;
}

if(grep {$_ eq $opts->{method}} qw(ls dir list rm del delete mv replace put cat)){
    no strict 'refs';
    &{$opts->{method}}($ARGV[0]);
} else {
    pod2usage(-message => "Please specify a valid method with -m <method>\n",
              -exitval => 2);
}

sub sign {
    my ($h, $method, $resource, $all_headers, $md5, $contenttype) = @_;
    my @gmt_now = gmtime();
    $resource = "/$opts->{bucket}/".($resource//'');
    $method = uc($method);
    $md5 //= '';
    $contenttype //= '';
    my $headerstr = '';
    my $date = strftime('%a, %d %b %Y %H:%M:%S +0000', @gmt_now);
    if($opts->{signv4}){
        my $isodate = strftime('%Y%m%dT%H%M%SZ', @gmt_now);
        my $dt   = strftime('%Y%m%d', @gmt_now);
        my $dk   = hmac_sha256("AWS4$opts->{key}$dt");
        my $drk  = hmac_sha256($dk  , $opts->{region});
        my $drsk = hmac_sha256($drk , 's3');
        my $sk   = hmac_sha256($drsk, 'aws4_request');

        $h->{'x-amz-date'}  = $isodate;
        my $sh  = join(';', map {lc $_} sort 'x-amz-date', keys %{$all_headers//{}});

        my $str = "$method\n$md5\n$contenttype\n$date\n$headerstr$resource";
        my $signature = hmac_sha256_hex($sk, $str);
        $h->{Authorization} = "AWS4-HMAC-SHA256\nCredential=$opts->{id}/$dt/$opts->{region}/s3/aws4_request,\nSignedHeaders=$sh,\nSignature=$signature";

        return
    }
    $all_headers->{'x-amz-security-token'} = $ENV{AWS_SESSION_TOKEN} if $ENV{AWS_SESSION_TOKEN};
    if (keys %{$all_headers}){
        $headerstr = join("\n", map {lc($_).":$all_headers->{$_}"} sort keys %{$all_headers})."\n";
    }
    my $str = "$method\n$md5\n$contenttype\n$date\n$headerstr$resource";
    $h->{Authorization} = "AWS $opts->{id}:".encode_base64(hmac_sha1($str, $opts->{key}), '');
    $h->{Date}          = $date;
    return;
}

sub put {
    my ($file) = @_;
    my $from = $ARGV[1] // '&STDIN';
    die "Need a correct arguments for put <remote filename> [<local filename>]\n"
        unless defined $file;
    sign($headers, 'put', $file);
    my $body = do {
        local $/;
        my $fh;
        open($fh, "<$from") or die "Error opening file $from: $!\n";
        <$fh>
    };
    return w_do('put', $file, $headers, $body);
}

sub cat {
    my ($file) = @_;
    print get($file);
    return;
}

sub get {
    my ($file) = @_;
    sign($headers, 'get', $file);
    return w_do('get', $file, $headers);
}

sub delete {
    my ($file) = @_;
    sign($headers, 'delete', $file);
    w_do('delete', $file, $headers);
    return;
}

sub replace {
    my ($file) = @_; 
    my $to = $ARGV[1];
    die "Need a second argument\n" unless defined $to;
    my $copy_h = {
        'x-amz-meta-mtime'         => time(),
        'x-amz-copy-source'        => "/$opts->{bucket}/$file",
        'x-amz-metadata-directive' => 'REPLACE',
    };
    sign($headers, 'put', $to, $copy_h);
    w_do('put', $to, {%{$headers}, %{$copy_h}});
    return;
}

sub list {
    my ($file) = @_; 
    my $result = get('');
    return unless defined $result;
    my $parser = XML::Simple->new(ForceArray => [qw(Contents CommonPrefixes Prefix)]);
    $result = $parser->XMLin($result);
    my $long = '';
    for my $ent (grep {($file//'') eq $_->{Key} or !$file} @{$result->{Contents}//[]}){
        if ($opts->{l}){
            $long = sprintf('%s %10d  %s ',
                $ent->{Owner}{DisplayName}, 
                $ent->{Size}, 
                strftime('%a %d %b %Y %H:%M:%S', parse_date($ent->{LastModified}))
            );
        }
        print "$long$ent->{Key}\n";
    }
    return $result;
}

sub w_do {
    my ($what, $url, $all_headers, $body) = @_;
    my $result;
    my $cv = AE::cv();
    http_request(
        uc($what) => "https://$opts->{bucket}.$opts->{url}/$url",
        headers   => {%{$all_headers}, "User-Agent" => 's3.pl'},
        tls_ctx   => AnyEvent::TLS->new(verify => !$opts->{insecure}, verify_peername => 'https'),
        timeout   => 30,
        (defined $body?(body => $body):()),
        sub {
            (my $body, $result) = @_;
            AE::log(debug => sub {Dumper($result)});
            $result->{content} = $body;
            $cv->send();
        }
    );
    $cv->recv();
    AE::log(debug => sub{Dumper($result)});
    if($result->{Status} !~ m/^(200)$/){
        AE::log(error => sub{$result->{Reason}.($result->{content}?"\n$result->{content}\n":'')});
        return;
    }
    return $result->{content};
}

sub parse_date {
    my ($ts) = @_;
    my @a = reverse($ts =~ m/^(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)\.\d+Z$/);
    $a[5] -= 1900;
    $a[4]--;
    return @a;
}
