open Eio
module type READ_INTO = sig
  type error

  val read_into: Flow.two_way -> Cstruct.t ->
    (unit Mirage_flow.or_eof, error) result
    (** Completely fills the given buffer with data from [fd] *)
end

module type FLOW_CLIENT = sig
  (* include Mirage_flow_combinators.SHUTDOWNABLE *)

  type error

  val pp_error : Format.formatter -> error -> unit

  type address

  val connect: sw:Eio.Switch.t -> net:Eio.Net.t -> ?read_buffer_size:int -> address ->
    (<Iflow.rw; Eio.Flow.two_way; Eio.Flow.close>, [`Msg of string]) result
    (** [connect address] creates a connection to [address] and returns
        he connected flow. *)
end

module type CONN = sig
  include Mirage_flow.S

  include READ_INTO
    with type error := error
end

module type FLOW_SERVER = sig
  type server
  (* A server bound to some address *)

  type address

  val of_bound_fd: sw:Eio.Switch.t -> ?read_buffer_size:int -> Unix.file_descr -> server
  (** Create a server from a file descriptor bound to a Unix domain socket
      by some other process and passed to us. *)

  val bind: sw:Eio.Switch.t -> Eio.Net.t -> ?description:string -> address -> server
  (** Bind a server to an address *)

  val getsockname: server -> address
  (** Query the address the server is bound to *)

  val disable_connection_tracking: server -> unit
  (** For a particular server, exempt connections from the tracking mechanism.
      This is intended for internal purposes only (e.g. extracting diagnostics
      information) *)

  (* type flow *)

  val listen: sw:Eio.Switch.t -> Eio.Net.t -> server -> (<Iflow.rw; Eio.Flow.two_way; Eio.Flow.close> -> unit) -> unit
  (** Accept connections forever, calling the callback with each one.
      Connections are closed automatically when the callback finishes. *)

  val shutdown: server -> unit
  (** Stop accepting connections on the given server *)
end

module type FLOW_CLIENT_SERVER = sig
  include FLOW_CLIENT
  include FLOW_SERVER
    with type address := address
end

module type SOCKETS = sig
  (* An OS-based BSD sockets implementation *)

  module Datagram: sig

    type address = Ipaddr.t * int

    module Udp: sig
      type address = Ipaddr.t * int

      include FLOW_CLIENT_SERVER
        with type address := address

      val recvfrom: server -> Cstruct.t -> (int * address)

      val sendto: server -> address -> ?ttl:int -> Cstruct.t -> unit
    end
  end
  module Stream: sig
    module Tcp: sig
      type address = Ipaddr.t * int

      include FLOW_CLIENT_SERVER
        with type address := address

      include READ_INTO
        with type error := error
    end

    module Unix: sig
      type address = string

      include FLOW_CLIENT_SERVER
        with type address := address

      include READ_INTO
        with type error := error

      val unsafe_get_raw_fd: <Eio.Flow.two_way; Eio.Flow.close> -> Unix.file_descr
      (** Return the underlying fd. This is intended for careful integration
          with 3rd party libraries. Don't use this fd at the same time as the
          flow. *)

    end
  end
end

module type FILES = sig
  (** An OS-based file reading implementation *)

  val read_file: #Eio.Fs.dir Eio.Path.t -> string
  (** Read a whole file into a string *)

  type watch

  val watch_file: Eio.Fs.dir Eio.Path.t -> (unit -> unit) -> (watch, [ `Msg of string ]) result
  (** [watch_file path callback] executes [callback] whenever the contents of
      [path] may have changed. This blocks until the watch has been established. *)

  val unwatch: watch -> unit
  (** [unwatch watch] stops watching the path(s) associated with [watch] *)
end

module type DNS = sig
  val resolve: Eio.Net.t -> Dns.Packet.question -> Dns.Packet.rr list
  (** Given a question, find associated resource records *)
end

module type HOST = sig
  (** The Host interface *)

  module Sockets: sig
    (** User-space socket connections *)
    include SOCKETS
  end

  module Files: sig
    include FILES
  end

  module Dns: sig
    include DNS
  end
end

module type VMNET = sig
  (** A virtual ethernet link to the VM *)

  include Mirage_net.S

  val add_listener: t -> (Cstruct.t -> unit) -> unit
  (** Add a callback which will be invoked in parallel with all received packets *)

  val after_disconnect: t -> unit Eio.Promise.t
  (** Waits until the network has disconnected *)

  type fd

  val of_fd:
    connect_client_fn:(Uuidm.t -> Ipaddr.V4.t option -> (Macaddr.t, [`Msg of string]) result) ->
    server_macaddr:Macaddr.t ->
    mtu:int ->
    fd -> (t, [`Msg of string]) result

  val start_capture: t -> ?size_limit:int64 -> string -> unit

  val stop_capture: t -> unit

  val get_client_uuid: t -> Uuidm.t

  val get_client_macaddr: t -> Macaddr.t
end

module type DNS_POLICY = sig
  (** Policy settings

      DNS configuration is taken from 4 places, lowest to highest priority:

      - 0: a built-in default of the Google public DNS servers
      - 1: a default configuration (from a command-line argument or a
           configuration file)
      - 2: the `/etc/resolv.conf` file if present
      - 3: the database key `slirp/dns`

      If configuration with a higher priority is found then it
      completely overrides lower priority configuration.  *)

  type priority = int (** higher is more important *)

  val start : sw:Eio.Switch.t -> Eio.Fs.dir Eio.Path.t -> unit

  val add: priority:priority ->
    config:[ `Upstream of Dns_forward.Config.t | `Host ] -> unit
  (** Add some configuration at the given priority level *)

  val remove: priority:priority -> unit
  (** Remove the configuration at the given priority level *)

  val config: unit -> [ `Upstream of Dns_forward.Config.t | `Host ]
  (** Return the currently active DNS configuration *)
end

module type RECORDER = sig
  (** Allow ethernet packets to be recorded *)

  type t

  val record: t -> Cstruct.t list -> unit
  (** Inject a packet and record it if it matches a rule. This is
      intended for debugging: the packet will not be transmitted to
      the underlying network. *)
end

module type Connector = sig
  (** Make connections into the VM *)

  include FLOW_CLIENT

  val connect: unit -> Flow.two_way
  (** Connect to the port multiplexing service in the VM *)

  include READ_INTO
    with type error := error
end
