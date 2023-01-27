module type READ_INTO =
  sig
    type error
    val read_into :
      Eio.Flow.two_way ->
      Cstruct.t -> (unit Mirage_flow.or_eof, error) result
  end
module type FLOW_CLIENT =
  sig
    type error
    val pp_error : Format.formatter -> error -> unit
    type address
    val connect :
      sw:Eio.Switch.t ->
      net:Eio.Net.t ->
      ?read_buffer_size:int ->
      address ->
      (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
         probe : 'a. 'a Eio.Generic.ty -> 'a option; read : Cstruct.t;
         read_into : Cstruct.t -> int; read_methods : Iflow.read_method list;
         shutdown : Iflow.shutdown_command -> unit;
         write : Cstruct.t list -> unit >,
       [ `Msg of string ])
      result
  end
module type CONN =
  sig
    type error
    val pp_error : error Fmt.t
    type nonrec write_error = private [> Mirage_flow.write_error ]
    val pp_write_error : write_error Fmt.t
    type flow
    val read : flow -> (Cstruct.t Mirage_flow.or_eof, error) result
    val write : flow -> Cstruct.t -> (unit, write_error) result
    val writev : flow -> Cstruct.t list -> (unit, write_error) result
    val close : flow -> unit
    val read_into :
      Eio.Flow.two_way ->
      Cstruct.t -> (unit Mirage_flow.or_eof, error) result
  end
module type FLOW_SERVER =
  sig
    type server
    type address
    val of_bound_fd :
      sw:Eio.Switch.t -> ?read_buffer_size:int -> Unix.file_descr -> server
    val bind :
      sw:Eio.Switch.t ->
      Eio.Net.t -> ?description:string -> address -> server
    val getsockname : server -> address
    val disable_connection_tracking : server -> unit
    val listen :
      sw:Eio.Switch.t ->
      Eio.Net.t ->
      server ->
      (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
         probe : 'a. 'a Eio.Generic.ty -> 'a option; read : Cstruct.t;
         read_into : Cstruct.t -> int; read_methods : Iflow.read_method list;
         shutdown : Iflow.shutdown_command -> unit;
         write : Cstruct.t list -> unit > ->
       unit) ->
      unit
    val shutdown : server -> unit
  end
module type FLOW_CLIENT_SERVER =
  sig
    type error
    val pp_error : Format.formatter -> error -> unit
    type address
    val connect :
      sw:Eio.Switch.t ->
      net:Eio.Net.t ->
      ?read_buffer_size:int ->
      address ->
      (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
         probe : 'a. 'a Eio.Generic.ty -> 'a option; read : Cstruct.t;
         read_into : Cstruct.t -> int; read_methods : Iflow.read_method list;
         shutdown : Iflow.shutdown_command -> unit;
         write : Cstruct.t list -> unit >,
       [ `Msg of string ])
      result
    type server
    val of_bound_fd :
      sw:Eio.Switch.t -> ?read_buffer_size:int -> Unix.file_descr -> server
    val bind :
      sw:Eio.Switch.t ->
      Eio.Net.t -> ?description:string -> address -> server
    val getsockname : server -> address
    val disable_connection_tracking : server -> unit
    val listen :
      sw:Eio.Switch.t ->
      Eio.Net.t ->
      server ->
      (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
         probe : 'a. 'a Eio.Generic.ty -> 'a option; read : Cstruct.t;
         read_into : Cstruct.t -> int; read_methods : Iflow.read_method list;
         shutdown : Iflow.shutdown_command -> unit;
         write : Cstruct.t list -> unit > ->
       unit) ->
      unit
    val shutdown : server -> unit
  end
module type SOCKETS =
  sig
    module Datagram :
      sig
        type address = Ipaddr.t * int
        module Udp :
          sig
            type address = Ipaddr.t * int
            type error
            val pp_error : Format.formatter -> error -> unit
            val connect :
              sw:Eio.Switch.t ->
              net:Eio.Net.t ->
              ?read_buffer_size:int ->
              address ->
              (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                 probe : 'a. 'a Eio.Generic.ty -> 'a option;
                 read : Cstruct.t; read_into : Cstruct.t -> int;
                 read_methods : Iflow.read_method list;
                 shutdown : Iflow.shutdown_command -> unit;
                 write : Cstruct.t list -> unit >,
               [ `Msg of string ])
              result
            type server
            val of_bound_fd :
              sw:Eio.Switch.t ->
              ?read_buffer_size:int -> Unix.file_descr -> server
            val bind :
              sw:Eio.Switch.t ->
              Eio.Net.t -> ?description:string -> address -> server
            val getsockname : server -> address
            val disable_connection_tracking : server -> unit
            val listen :
              sw:Eio.Switch.t ->
              Eio.Net.t ->
              server ->
              (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                 probe : 'a. 'a Eio.Generic.ty -> 'a option;
                 read : Cstruct.t; read_into : Cstruct.t -> int;
                 read_methods : Iflow.read_method list;
                 shutdown : Iflow.shutdown_command -> unit;
                 write : Cstruct.t list -> unit > ->
               unit) ->
              unit
            val shutdown : server -> unit
            val recvfrom : server -> Cstruct.t -> int * address
            val sendto : server -> address -> ?ttl:int -> Cstruct.t -> unit
          end
      end
    module Stream :
      sig
        module Tcp :
          sig
            type address = Ipaddr.t * int
            type error
            val pp_error : Format.formatter -> error -> unit
            val connect :
              sw:Eio.Switch.t ->
              net:Eio.Net.t ->
              ?read_buffer_size:int ->
              address ->
              (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                 probe : 'a. 'a Eio.Generic.ty -> 'a option;
                 read : Cstruct.t; read_into : Cstruct.t -> int;
                 read_methods : Iflow.read_method list;
                 shutdown : Iflow.shutdown_command -> unit;
                 write : Cstruct.t list -> unit >,
               [ `Msg of string ])
              result
            type server
            val of_bound_fd :
              sw:Eio.Switch.t ->
              ?read_buffer_size:int -> Unix.file_descr -> server
            val bind :
              sw:Eio.Switch.t ->
              Eio.Net.t -> ?description:string -> address -> server
            val getsockname : server -> address
            val disable_connection_tracking : server -> unit
            val listen :
              sw:Eio.Switch.t ->
              Eio.Net.t ->
              server ->
              (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                 probe : 'a. 'a Eio.Generic.ty -> 'a option;
                 read : Cstruct.t; read_into : Cstruct.t -> int;
                 read_methods : Iflow.read_method list;
                 shutdown : Iflow.shutdown_command -> unit;
                 write : Cstruct.t list -> unit > ->
               unit) ->
              unit
            val shutdown : server -> unit
            val read_into :
              Eio.Flow.two_way ->
              Cstruct.t -> (unit Mirage_flow.or_eof, error) result
          end
        module Unix :
          sig
            type address = string
            type error
            val pp_error : Format.formatter -> error -> unit
            val connect :
              sw:Eio.Switch.t ->
              net:Eio.Net.t ->
              ?read_buffer_size:int ->
              address ->
              (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                 probe : 'a. 'a Eio.Generic.ty -> 'a option;
                 read : Cstruct.t; read_into : Cstruct.t -> int;
                 read_methods : Iflow.read_method list;
                 shutdown : Iflow.shutdown_command -> unit;
                 write : Cstruct.t list -> unit >,
               [ `Msg of string ])
              result
            type server
            val of_bound_fd :
              sw:Eio.Switch.t ->
              ?read_buffer_size:int -> Unix.file_descr -> server
            val bind :
              sw:Eio.Switch.t ->
              Eio.Net.t -> ?description:string -> address -> server
            val getsockname : server -> address
            val disable_connection_tracking : server -> unit
            val listen :
              sw:Eio.Switch.t ->
              Eio.Net.t ->
              server ->
              (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                 probe : 'a. 'a Eio.Generic.ty -> 'a option;
                 read : Cstruct.t; read_into : Cstruct.t -> int;
                 read_methods : Iflow.read_method list;
                 shutdown : Iflow.shutdown_command -> unit;
                 write : Cstruct.t list -> unit > ->
               unit) ->
              unit
            val shutdown : server -> unit
            val read_into :
              Eio.Flow.two_way ->
              Cstruct.t -> (unit Mirage_flow.or_eof, error) result
            val unsafe_get_raw_fd :
              < close : unit; copy : 'b. (#Eio.Flow.source as 'b) -> unit;
                probe : 'a. 'a Eio.Generic.ty -> 'a option;
                read_into : Cstruct.t -> int;
                read_methods : Iflow.read_method list;
                shutdown : Eio.Flow.shutdown_command -> unit;
                write : Cstruct.t list -> unit > ->
              Unix.file_descr
          end
      end
  end
module type FILES =
  sig
    val read_file : #Eio.Fs.dir Eio.Path.t -> string
    type watch
    val watch_file :
      Eio.Fs.dir Eio.Path.t ->
      (unit -> unit) -> (watch, [ `Msg of string ]) result
    val unwatch : watch -> unit
  end
module type DNS =
  sig val resolve : Dns.Packet.question -> Dns.Packet.rr list end
module type HOST =
  sig
    module Sockets :
      sig
        module Datagram :
          sig
            type address = Ipaddr.t * int
            module Udp :
              sig
                type address = Ipaddr.t * int
                type error
                val pp_error : Format.formatter -> error -> unit
                val connect :
                  sw:Eio.Switch.t ->
                  net:Eio.Net.t ->
                  ?read_buffer_size:int ->
                  address ->
                  (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                     probe : 'a. 'a Eio.Generic.ty -> 'a option;
                     read : Cstruct.t; read_into : Cstruct.t -> int;
                     read_methods : Iflow.read_method list;
                     shutdown : Iflow.shutdown_command -> unit;
                     write : Cstruct.t list -> unit >,
                   [ `Msg of string ])
                  result
                type server
                val of_bound_fd :
                  sw:Eio.Switch.t ->
                  ?read_buffer_size:int -> Unix.file_descr -> server
                val bind :
                  sw:Eio.Switch.t ->
                  Eio.Net.t -> ?description:string -> address -> server
                val getsockname : server -> address
                val disable_connection_tracking : server -> unit
                val listen :
                  sw:Eio.Switch.t ->
                  Eio.Net.t ->
                  server ->
                  (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                     probe : 'a. 'a Eio.Generic.ty -> 'a option;
                     read : Cstruct.t; read_into : Cstruct.t -> int;
                     read_methods : Iflow.read_method list;
                     shutdown : Iflow.shutdown_command -> unit;
                     write : Cstruct.t list -> unit > ->
                   unit) ->
                  unit
                val shutdown : server -> unit
                val recvfrom : server -> Cstruct.t -> int * address
                val sendto :
                  server -> address -> ?ttl:int -> Cstruct.t -> unit
              end
          end
        module Stream :
          sig
            module Tcp :
              sig
                type address = Ipaddr.t * int
                type error
                val pp_error : Format.formatter -> error -> unit
                val connect :
                  sw:Eio.Switch.t ->
                  net:Eio.Net.t ->
                  ?read_buffer_size:int ->
                  address ->
                  (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                     probe : 'a. 'a Eio.Generic.ty -> 'a option;
                     read : Cstruct.t; read_into : Cstruct.t -> int;
                     read_methods : Iflow.read_method list;
                     shutdown : Iflow.shutdown_command -> unit;
                     write : Cstruct.t list -> unit >,
                   [ `Msg of string ])
                  result
                type server
                val of_bound_fd :
                  sw:Eio.Switch.t ->
                  ?read_buffer_size:int -> Unix.file_descr -> server
                val bind :
                  sw:Eio.Switch.t ->
                  Eio.Net.t -> ?description:string -> address -> server
                val getsockname : server -> address
                val disable_connection_tracking : server -> unit
                val listen :
                  sw:Eio.Switch.t ->
                  Eio.Net.t ->
                  server ->
                  (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                     probe : 'a. 'a Eio.Generic.ty -> 'a option;
                     read : Cstruct.t; read_into : Cstruct.t -> int;
                     read_methods : Iflow.read_method list;
                     shutdown : Iflow.shutdown_command -> unit;
                     write : Cstruct.t list -> unit > ->
                   unit) ->
                  unit
                val shutdown : server -> unit
                val read_into :
                  Eio.Flow.two_way ->
                  Cstruct.t -> (unit Mirage_flow.or_eof, error) result
              end
            module Unix :
              sig
                type address = string
                type error
                val pp_error : Format.formatter -> error -> unit
                val connect :
                  sw:Eio.Switch.t ->
                  net:Eio.Net.t ->
                  ?read_buffer_size:int ->
                  address ->
                  (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                     probe : 'a. 'a Eio.Generic.ty -> 'a option;
                     read : Cstruct.t; read_into : Cstruct.t -> int;
                     read_methods : Iflow.read_method list;
                     shutdown : Iflow.shutdown_command -> unit;
                     write : Cstruct.t list -> unit >,
                   [ `Msg of string ])
                  result
                type server
                val of_bound_fd :
                  sw:Eio.Switch.t ->
                  ?read_buffer_size:int -> Unix.file_descr -> server
                val bind :
                  sw:Eio.Switch.t ->
                  Eio.Net.t -> ?description:string -> address -> server
                val getsockname : server -> address
                val disable_connection_tracking : server -> unit
                val listen :
                  sw:Eio.Switch.t ->
                  Eio.Net.t ->
                  server ->
                  (< close : unit; copy : 'b. (#Iflow.source as 'b) -> unit;
                     probe : 'a. 'a Eio.Generic.ty -> 'a option;
                     read : Cstruct.t; read_into : Cstruct.t -> int;
                     read_methods : Iflow.read_method list;
                     shutdown : Iflow.shutdown_command -> unit;
                     write : Cstruct.t list -> unit > ->
                   unit) ->
                  unit
                val shutdown : server -> unit
                val read_into :
                  Eio.Flow.two_way ->
                  Cstruct.t -> (unit Mirage_flow.or_eof, error) result
                val unsafe_get_raw_fd :
                  < close : unit;
                    copy : 'b. (#Eio.Flow.source as 'b) -> unit;
                    probe : 'a. 'a Eio.Generic.ty -> 'a option;
                    read_into : Cstruct.t -> int;
                    read_methods : Iflow.read_method list;
                    shutdown : Eio.Flow.shutdown_command -> unit;
                    write : Cstruct.t list -> unit > ->
                  Unix.file_descr
              end
          end
      end
    module Files :
      sig
        val read_file : #Eio.Fs.dir Eio.Path.t -> string
        type watch
        val watch_file :
          Eio.Fs.dir Eio.Path.t ->
          (unit -> unit) -> (watch, [ `Msg of string ]) result
        val unwatch : watch -> unit
      end
    module Dns :
      sig val resolve : Dns.Packet.question -> Dns.Packet.rr list end
  end
module type VMNET =
  sig
    type error = private [> Mirage_net.Net.error ]
    val pp_error : error Fmt.t
    type t
    val disconnect : t -> unit
    val write : t -> size:int -> (Cstruct.t -> int) -> (unit, error) result
    val listen :
      sw:Eio.Switch.t ->
      t -> header_size:int -> (Cstruct.t -> unit) -> (unit, error) result
    val mac : t -> Macaddr.t
    val mtu : t -> int
    val get_stats_counters : t -> Mirage_net.stats
    val reset_stats_counters : t -> unit
    val add_listener : t -> (Cstruct.t -> unit) -> unit
    val after_disconnect : t -> unit Eio.Promise.t
    type fd
    val of_fd :
      connect_client_fn:(Uuidm.t ->
                         Ipaddr.V4.t option ->
                         (Macaddr.t, [ `Msg of string ]) result) ->
      server_macaddr:Macaddr.t ->
      mtu:int -> fd -> (t, [ `Msg of string ]) result
    val start_capture : t -> ?size_limit:int64 -> string -> unit
    val stop_capture : t -> unit
    val get_client_uuid : t -> Uuidm.t
    val get_client_macaddr : t -> Macaddr.t
  end
module type DNS_POLICY =
  sig
    type priority = int
    val start : sw:Eio.Switch.t -> Eio.Fs.dir Eio.Path.t -> unit
    val add :
      priority:priority ->
      config:[ `Host | `Upstream of Dns_forward.Config.t ] -> unit
    val remove : priority:priority -> unit
    val config : unit -> [ `Host | `Upstream of Dns_forward.Config.t ]
  end
module type RECORDER =
  sig type t val record : t -> Cstruct.t list -> unit end
module type Connector =
  sig
    type error
    val pp_error : Format.formatter -> error -> unit
    type address
    val connect : unit -> Eio.Flow.two_way
    val read_into :
      Eio.Flow.two_way ->
      Cstruct.t -> (unit Mirage_flow.or_eof, error) result
  end
