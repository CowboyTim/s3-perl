#!/usr/bin/perl

use strict; use warnings;

use Data::Dumper;
use Pod::Usage;
use POSIX qw(strftime);
use Time::Local qw(timegm);
use File::Basename qw(dirname);

use MIME::Base64 qw(encode_base64);
use Digest::HMAC_SHA1 qw(hmac_sha1);
use Getopt::Long;
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
        key    => $key,
        id     => $id,
        method => 'list',
        url    => "s3.amazonaws.com",
    },
    "bucket|b=s",
    "method|m=s",
    "key|k=s",
    "acl|a=s",
    "url|u=s",
    "l!"
) or pod2usage(1);
push @ARGV, '' unless @ARGV;

AnyEvent::Log::ctx->level("debug");


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

{
    no strict 'refs';
    &{$opts->{method}}($ARGV[0]);
}

sub sign {
    my ($h, $method, $resource, $headers, $md5, $contenttype) = @_;
    $resource = "/$opts->{bucket}/$resource";
    $method = uc($method);
    $md5 //= '';
    $contenttype //= '';
    my $headerstr = '';
    if (keys %{$headers}){
        $headerstr = join("\n", map {"$_:$headers->{$_}"} sort keys %{$headers})."\n";
    }
    my $date = strftime('%a, %d %b %Y %H:%M:%S +0000', gmtime());
    my $str = "$method\n$md5\n$contenttype\n$date\n$headerstr$resource";
    $h->{Authorization} = "AWS $opts->{id}:".encode_base64(hmac_sha1($str, $opts->{key}), '');
    $h->{Date}          = $date;
}

sub put {
    my ($file) = @_;
    sign($headers, 'put', $file);
    my $from = $ARGV[1];
    die "Need a second argument\n" unless defined $from and -e $from;
    my $body = do {
        local $/;
        my $fh;
        open($fh, '<', $from) or die "Error opening file $from: $!\n";
        <$fh>
    };
    return w_do('put', $file, $headers, $body);
}

sub cat {
    my ($file) = @_;
    print get($file);
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
}

sub list {
    my ($file) = @_; 
    my $result = get('');
    my $parser = XML::Simple->new(ForceArray => [qw(Contents CommonPrefixes Prefix)]);
    $result = $parser->XMLin($result);
    my $long = '';
    for my $ent (grep {$file eq $_->{Key} or !$file} @{$result->{Contents}//[]}){
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
    my ($what, $url, $headers, $body) = @_;
    my $result;
    my $cv = AE::cv();
    http_request(
        uc($what) => "https://$opts->{bucket}.$opts->{url}/$url",
        headers   => {%{$headers}, "User-Agent" => 's3.pl'},
        tls_ctx   => AnyEvent::TLS->new(verify => 0),
        timeout   => 30,
        (defined $body?(body => $body):()),
        sub {
            (my $body, $result) = @_;
            print STDERR Dumper($result);
            $result->{content} = $body;
            $cv->send();
        }
    );
    $cv->recv();
    AE::log(debug => Dumper($result));
    return $result->{content};
}

sub parse_date {
    my ($ts) = @_;
    my @a = reverse($ts =~ m/^(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)\.\d+Z$/);
    $a[5] -= 1900;
    $a[4]--;
    return @a;
}
