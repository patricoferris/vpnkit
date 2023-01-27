type pcap = (string * int64 option) option
(** Packet capture configuration. None means don't capture; Some (file, limit)
    means write pcap-formatted data to file. If the limit is None then the
    file will grow without bound; otherwise the file will be closed when it is
    bigger than the given limit. *)

module Make
    (Vmnet: Sig.VMNET)
    (Dns_policy: Sig.DNS_POLICY)
    (Vnet : Vnetif.BACKEND with type macaddr = Macaddr.t) :
sig

  type stack
  (** A TCP/IP stack which may talk to multiple ethernet clients *)

  val create_static:
    sw:Eio.Switch.t ->
    fs:Eio.Fs.dir Eio.Path.t ->
    < clock : Eio.Time.clock; mono : Eio.Time.Mono.t; net : Eio.Net.t; .. > ->
    Vnet.t -> Configuration.t -> stack
  (** Initialise a TCP/IP stack, with a static configuration *)

  type connection
  (** An ethernet connection to a stack *)

  val connect:
    sw:Eio.Switch.t ->
    net:Eio.Net.t ->
    mono:Eio.Time.Mono.t ->
    clock:Eio.Time.clock ->
    random:Eio.Flow.source -> stack -> Vmnet.fd -> connection
  (** Read and write ethernet frames on the given fd, connected to the
      specified Vnetif backend *)

  val after_disconnect: connection -> unit Eio.Promise.t
  (** Waits until the stack has been disconnected *)

  val filesystem: connection -> Vfs.Dir.t
  (** A virtual filesystem which exposes internal state for debugging *)

  val diagnostics: connection -> <Iflow.rw; Eio.Flow.two_way; Eio.Flow.close> -> unit
  (** Output diagnostics in .tar format over a local Unix socket or named pipe *)

  val pcap: connection -> <Iflow.rw; Eio.Flow.two_way; Eio.Flow.close> -> unit
  (** Output all traffic in pcap format over a local Unix socket or named pipe *)

  val http_intercept_api_handler: <Iflow.rw; Eio.Flow.two_way; Eio.Flow.close> -> unit
  (** Handle HTTP proxy reconfigurations via an HTTP API *)

  module Debug: sig
    module Nat : sig
      type address = Ipaddr.t * int

      type flow = {
        inside: address;
        outside: address;
        last_use_time_ns: int64;
      }

      val get_table: connection -> flow list
      (** Return an instantaneous snapshot of the NAT table *)

      val get_max_active_flows: connection -> int
    end

    val update_dns: ?local_ip:Ipaddr.t -> ?builtin_names:(Dns.Name.t * Ipaddr.t) list ->
      sw:Eio.Switch.t ->
      < clock : Eio.Time.clock; mono : Eio.Time.Mono.t; net : Eio.Net.t; .. > -> unit
    (** Update the DNS forwarder following a configuration change *)

    val update_http: ?http:string -> ?https:string -> ?exclude:string
      -> ?transparent_http_ports:int list -> ?transparent_https_ports:int list
      -> unit -> (unit, [`Msg of string]) result
    (** Update the HTTP forwarder following a configuration change *)

    val update_http_json: Ezjsonm.value ->
      unit -> (unit, [`Msg of string]) result
    (** Update the HTTP forwarder using the json interface *)
  end
end

val print_pcap: pcap -> string
