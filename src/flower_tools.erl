%% Copyright 2010-2012, Travelping GmbH <info@travelping.com>

%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:

%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.

%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

-module(flower_tools).

-include("flower_flow.hrl").

-export([ip_to_tuple/1, tuple_to_ip/1]).
-export([format_ip/1, format_mac/1]).
-export([format_flow/1]).
-export([hexdump/1]).
-export([socket_family/1, socket_type/1, socket_protocol/1]).

flat_format(Format, Data) ->
    lists:flatten(io_lib:format(Format, Data)).

ip_to_tuple(<<A:8, B:8, C:8, D:8>>) ->
    {A, B, C, D};
ip_to_tuple(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.

tuple_to_ip({A, B, C, D}) ->
    <<A:8, B:8, C:8, D:8>>;
tuple_to_ip({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

format_mac(<<A:8, B:8, C:8, D:8, E:8, F:8>>) ->
    flat_format("~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B",
                [A, B, C, D, E, F]);
format_mac(MAC) ->
    flat_format("~w", MAC).

format_ip(undefined) ->
    "undefined";
format_ip(<<A:8, B:8, C:8, D:8>>) ->
    flat_format("~B.~B.~B.~B", [A, B, C, D]);
format_ip(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    flat_format("~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B:~.16B",
                [A, B, C, D, E, F, G, H]);
format_ip(IP) ->
    flat_format("~w", IP).


format_flow(#flow{tun_id = TunId, nw_src = NwSrc, nw_dst = NwDst,
                  in_port = InPort, vlan_tci = VlanTci,
                  dl_type = DlType, dl_src = DlSrc, dl_dst = DlDst,
                  nw_proto = NwProto, arp_sha = ArpSha, arp_tha = ArpTha})
  when DlType == arp ->
    flat_format("ARP Flow: tun_id = ~w, in_port = ~w, vlan_tci = ~w, "
                "dl_src = ~s, dl_dst = ~s, dl_type = ~w, nw_proto "
                "(arp op) = ~w, nw_src (sha) = ~s, nw_dst (tpa) = ~s, "
                "arp_sha = ~s, arp_tha = ~s",
                [TunId,  InPort, VlanTci, format_mac(DlSrc),
                 format_mac(DlDst), DlType, NwProto, format_ip(NwSrc),
                 format_ip(NwDst),format_mac(ArpSha), format_mac(ArpTha)]);

format_flow(#flow{tun_id = TunId, nw_src = NwSrc, nw_dst = NwDst,
                  in_port = InPort, vlan_tci = VlanTci,
                  dl_type = DlType, tp_src = TpSrc, tp_dst = TpDst,
                  dl_src = DlSrc, dl_dst = DlDst,
                  nw_proto = NwProto, nw_tos = NwTos}) ->
    flat_format("Flow: tun_id = ~w, nw_src = ~s, nw_dst = ~s, "
                "in_port = ~w, vlan_tci = ~w, dl_type = ~w, tp_src = ~w, "
                "tp_dst = ~w, dl_src = ~s, dl_dst = ~s, nw_proto = ~w, "
                "nw_tos = ~w",
                [TunId, format_ip(NwSrc), format_ip(NwDst), InPort, VlanTci,
                 DlType, TpSrc, TpDst, format_mac(DlSrc), format_mac(DlDst),
                 NwProto, NwTos]).


hexdump(Line, Part) ->
       L0 = [io_lib:format(" ~2.16.0B", [X]) || <<X:8>> <= Part],
       io_lib:format("~4.16.0B:~s~n", [Line * 16, L0]).

hexdump(_, <<>>, Out) ->
       lists:flatten(lists:reverse(Out));
hexdump(Line, <<Part:16/bytes, Rest/binary>>, Out) ->
       L1 = hexdump(Line, Part),
       hexdump(Line + 1, Rest, [L1|Out]);
hexdump(Line, <<Part/binary>>, Out) ->
       L1 = hexdump(Line, Part),
       hexdump(Line + 1, <<>>, [L1|Out]).

hexdump(List) when is_list(List) ->
       hexdump(0, list_to_binary(List), []);
hexdump(Bin) when is_binary(Bin)->
       hexdump(0, Bin, []).



%% Protocol family (aka domain)
socket_family(unspec) -> 0;
socket_family(inet) -> 2;
socket_family(ax25) -> 3;
socket_family(ipx) -> 4;
socket_family(appletalk) -> 5;
socket_family(netrom) -> 6;
socket_family(bridge) -> 7;
socket_family(atmpvc) -> 8;
socket_family(x25) -> 9;
socket_family(inet6) -> 10;
socket_family(rose) -> 11;
socket_family(decnet) -> 12;
socket_family(netbeui) -> 13;
socket_family(security) -> 14;
socket_family(key) -> 15;
socket_family(packet) -> 17;
socket_family(ash) -> 18;
socket_family(econet) -> 19;
socket_family(atmsvc) -> 20;
socket_family(rds) -> 21;
socket_family(sna) -> 22;
socket_family(irda) -> 23;
socket_family(pppox) -> 24;
socket_family(wanpipe) -> 25;
socket_family(llc) -> 26;
socket_family(can) -> 29;
socket_family(tipc) -> 30;
socket_family(bluetooth) -> 31;
socket_family(iucv) -> 32;
socket_family(rxrpc) -> 33;
socket_family(isdn) -> 34;
socket_family(phonet) -> 35;
socket_family(ieee802154) -> 36;
socket_family(Proto) when Proto == local; Proto == unix; Proto == file -> 1;
socket_family(Proto) when Proto == netlink; Proto == route -> 16;

socket_family(0) -> unspec;
socket_family(1) -> unix;
socket_family(2) -> inet;
socket_family(3) -> ax25;
socket_family(4) -> ipx;
socket_family(5) -> appletalk;
socket_family(6) -> netrom;
socket_family(7) -> bridge;
socket_family(8) -> atmpvc;
socket_family(9) -> x25;
socket_family(10) -> inet6;
socket_family(11) -> rose;
socket_family(12) -> decnet;
socket_family(13) -> netbeui;
socket_family(14) -> security;
socket_family(15) -> key;
socket_family(17) -> packet;
socket_family(18) -> ash;
socket_family(19) -> econet;
socket_family(20) -> atmsvc;
socket_family(21) -> rds;
socket_family(22) -> sna;
socket_family(23) -> irda;
socket_family(24) -> pppox;
socket_family(25) -> wanpipe;
socket_family(26) -> llc;
socket_family(29) -> can;
socket_family(30) -> tipc;
socket_family(31) -> bluetooth;
socket_family(32) -> iucv;
socket_family(33) -> rxrpc;
socket_family(34) -> isdn;
socket_family(35) -> phonet;
socket_family(36) -> ieee802154.

%% Socket type
socket_type(stream) -> 1;
socket_type(dgram) -> 2;
socket_type(raw) -> 3;

socket_type(1) -> stream;
socket_type(2) -> dgram;
socket_type(3) -> raw.


% Select a protocol within the family (0 means use the default
% protocol in the family)
socket_protocol(ip) -> 0;
socket_protocol(icmp) -> 1;
socket_protocol(igmp) -> 2;
socket_protocol(ipip) -> 4;
socket_protocol(tcp) -> 6;
socket_protocol(egp) -> 8;
socket_protocol(pup) -> 12;
socket_protocol(udp) -> 17;
socket_protocol(idp) -> 22;
socket_protocol(tp) -> 29;
socket_protocol(dccp) -> 33;
socket_protocol(ipv6) -> 41;
socket_protocol(routing) -> 43;
socket_protocol(fragment) -> 44;
socket_protocol(rsvp) -> 46;
socket_protocol(gre) -> 47;
socket_protocol(esp) -> 50;
socket_protocol(ah) -> 51;
socket_protocol(icmpv6) -> 58;
socket_protocol(none) -> 59;
socket_protocol(dstopts) -> 60;
socket_protocol(mtp) -> 92;
socket_protocol(encap) -> 98;
socket_protocol(pim) -> 103;
socket_protocol(comp) -> 108;
socket_protocol(sctp) -> 132;
socket_protocol(udplite) -> 136;
socket_protocol(raw) -> 255;

socket_protocol(0) -> ip;
socket_protocol(1) -> icmp;
socket_protocol(2) -> igmp;
socket_protocol(4) -> ipip;
socket_protocol(6) -> tcp;
socket_protocol(8) -> egp;
socket_protocol(12) -> pup;
socket_protocol(17) -> udp;
socket_protocol(22) -> idp;
socket_protocol(29) -> tp;
socket_protocol(33) -> dccp;
socket_protocol(41) -> ipv6;
socket_protocol(43) -> routing;
socket_protocol(44) -> fragment;
socket_protocol(46) -> rsvp;
socket_protocol(47) -> gre;
socket_protocol(50) -> esp;
socket_protocol(51) -> ah;
socket_protocol(58) -> icmpv6;
socket_protocol(59) -> none;
socket_protocol(60) -> dstopts;
socket_protocol(92) -> mtp;
socket_protocol(98) -> encap;
socket_protocol(103) -> pim;
socket_protocol(108) -> comp;
socket_protocol(132) -> sctp;
socket_protocol(136) -> udplite;
socket_protocol(255) -> raw;
socket_protocol(X) -> X.
