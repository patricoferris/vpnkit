module Policy(Files: Sig.FILES): Sig.DNS_POLICY
(** Global DNS configuration *)

module Config: sig
  type t = [
    | `Upstream of Dns_forward.Config.t (** use upstream servers *)
    | `Host (** use the host's resolver *)
  ]
  val to_string: t -> string
  val compare: t -> t -> int
end

module Make
    (Ip: Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t)
    (Udp: Tcpip.Udp.S with type ipaddr = Ipaddr.V4.t)
    (Tcp: Tcpip.Tcp.S with type ipaddr = Ipaddr.V4.t)
    (Socket: Sig.SOCKETS)
    (Dns_resolver: Sig.DNS)
    (Recorder: Sig.RECORDER) :
sig

  type t
  (** A DNS proxy instance with a fixed configuration *)

  type 'a env = <
    net : Eio.Net.t;             (** To connect to the servers *)
    mono : Eio.Time.Mono.t;
    clock : Eio.Time.clock;      (** Needed for timeouts *)
    ..
  > as 'a

  val create:
    sw: Eio.Switch.t ->
    local_address:Dns_forward.Config.Address.t ->
    builtin_names:(Dns.Name.t * Ipaddr.t) list ->
    _ env ->
    Config.t -> t
  (** Create a DNS forwarding instance based on the given
      configuration, either [`Upstream config]: send DNS requests to
      the given upstream servers [`Host]: use the Host's resolver.
      The parameter [~local_address] will be used in any .pcap trace
      as the source address of DNS requests sent from this host. *)

  val set_recorder: Recorder.t -> unit

  val handle_udp:
    t:t -> udp:Udp.t -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int ->
    Cstruct.t -> unit

  val handle_tcp:
    t:t -> (int -> (<Eio.Flow.two_way; Eio.Flow.close; Tcp.dst> -> unit) option)

  val destroy: t -> unit
end
