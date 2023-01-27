open Eio

let src =
  let src =
    Logs.Src.create "forwards" ~doc:"Forwards TCP/UDP streams to local services"
  in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Protocol = struct
  type t = [ `Tcp ]
  (* consider UDP later *)

  open Ezjsonm

  let to_json t = string (match t with `Tcp -> "tcp")

  let of_json j =
    match get_string j with
    | "tcp" -> `Tcp
    | _ -> raise (Parse_error (j, "protocol should be tcp"))
end

type forward = {
  protocol : Protocol.t;
  dst_prefix : Ipaddr.Prefix.t;
  dst_port : int;
  path : string; (* unix domain socket path *)
}

let forward_to_json t =
  let open Ezjsonm in
  dict
    [
      ("protocol", Protocol.to_json t.protocol);
      ("dst_prefix", string (Ipaddr.Prefix.to_string t.dst_prefix));
      ("dst_port", int t.dst_port);
      ("path", string t.path);
    ]

let forward_of_json j =
  let open Ezjsonm in
  let protocol = Protocol.of_json @@ find j [ "protocol" ] in
  let dst_port = get_int @@ find j [ "dst_port" ] in
  let path = get_string @@ find j [ "path" ] in
  let dst_prefix =
    match Ipaddr.Prefix.of_string @@ get_string @@ find j [ "dst_prefix" ] with
    | Error (`Msg m) ->
        raise (Parse_error (j, "dst_ip should be an IP prefix: " ^ m))
    | Ok x -> x
  in
  { protocol; dst_prefix; dst_port; path }

type t = forward list

let to_json = Ezjsonm.list forward_to_json
let of_json = Ezjsonm.get_list forward_of_json
let to_string x = Ezjsonm.to_string @@ to_json x

let of_string x =
  try Ok (of_json @@ Ezjsonm.from_string x) with
  | Ezjsonm.Parse_error (_v, msg) -> Error (`Msg msg)
  | e -> Error (`Msg (Printf.sprintf "parsing %s: %s" x (Printexc.to_string e)))

let dynamic = ref []
let static = ref []
let all = ref []

let set_static xs =
  static := xs;
  all := !static @ !dynamic;
  Log.info (fun f -> f "New Forward configuration: %s" (to_string !all))

let update xs =
  dynamic := xs;
  all := !static @ !dynamic;
  Log.info (fun f -> f "New Forward configuration: %s" (to_string !all))

(* Extend a SHUTDOWNABLE flow with a `read_some` API, as used by "channel".
   Ideally we would use channel, but we need to access the underlying flow
   without leaving data trapped in the buffer. *)

class virtual read_some = object (_ : <Iflow.rw; Flow.two_way; Flow.close; ..>)
  inherit Iflow.rw
  inherit Flow.two_way

  method virtual read_some : int -> (Cstruct.t list, [`Msg of string]) result
end

module Read_some : sig
  val read_some : #read_some -> int -> (Cstruct.t list, [`Msg of string]) result
  val of_flow : <Iflow.rw; Flow.two_way; Flow.close> -> read_some
end = struct
  (* A flow with a buffer, filled by "read_some" and then drained by "read" *)

  let read_some f = f#read_some

  let of_flow (f : <Iflow.rw; Flow.two_way; Flow.close>) = object (self)
    inherit Iflow.rw
    method read_into = f#read_into
    method shutdown = f#shutdown
    method read = f#read
    method copy = f#copy
    method close = f#close
    method read_methods = f#read_methods

    val mutable remaining = Cstruct.create 0
    method read_some t =
        let rec loop acc len =
          if Cstruct.length remaining = 0 && len > 0 then
            match Iflow.read f with
            | buf ->
              remaining <- buf;
              loop acc len
          else if Cstruct.length remaining < len then (
            let take = remaining in
            remaining <- Cstruct.create 0;
            loop (take :: acc) (len - Cstruct.length take))
          else
            let take, leave = Cstruct.split remaining len in
            remaining <- leave;
            Ok (List.rev (take :: acc))
        in
        loop [] t
  end
end

module Handshake = struct
  (* A Message is a buffer prefixed with a uint16 length field. *)
  module Message = struct

    let pp_error ppf = function
      | `Flow _ -> Fmt.string ppf "Flow error"
      | `Eof -> Fmt.string ppf "EOF while reading handshake"

    let read flow =
      match Read_some.read_some flow 2 with
      | Error e -> Error (`Flow e)
      | exception End_of_file -> Error `Eof
      | Ok bufs -> (
          let buf = Cstructs.to_cstruct bufs in
          let len = Cstruct.LE.get_uint16 buf 0 in
          match Read_some.read_some flow len with
          | Error e -> Error (`Flow e)
          | exception End_of_file -> Error `Eof
          | Ok bufs -> Ok (Cstructs.to_cstruct bufs))

    let write flow t =
      let len = Cstruct.create 2 in
      Cstruct.LE.set_uint16 len 0 (Cstruct.length t);
      Flow.write flow [ len; t ]
  end

  module Request = struct
    type t = {
      protocol : Protocol.t;
      src_ip : Ipaddr.t;
      src_port : int;
      dst_ip : Ipaddr.t;
      dst_port : int;
    }

    open Ezjsonm

    let of_json j =
      let protocol = Protocol.of_json @@ find j [ "protocol" ] in
      let src_ip =
        match Ipaddr.of_string @@ get_string @@ find j [ "src_ip" ] with
        | Error (`Msg m) ->
            raise (Parse_error (j, "src_ip should be an IP address: " ^ m))
        | Ok x -> x
      in
      let src_port = get_int @@ find j [ "src_port" ] in
      let dst_ip =
        match Ipaddr.of_string @@ get_string @@ find j [ "dst_ip" ] with
        | Error (`Msg m) ->
            raise (Parse_error (j, "dst_ip should be an IP address: " ^ m))
        | Ok x -> x
      in
      let dst_port = get_int @@ find j [ "dst_port" ] in
      { protocol; src_ip; src_port; dst_ip; dst_port }

    let to_json t =
      let open Ezjsonm in
      dict
        [
          ("protocol", Protocol.to_json t.protocol);
          ("src_ip", string (Ipaddr.to_string t.src_ip));
          ("src_port", int t.src_port);
          ("dst_ip", string (Ipaddr.to_string t.dst_ip));
          ("dst_port", int t.dst_port);
        ]

    let to_string t = Ezjsonm.to_string @@ to_json t

    let read flow =
      match Message.read flow with
      | Error (`Flow e) -> Error (`Flow e)
      | Error `Eof -> Error `Eof
      | Ok buf ->
          let j = Ezjsonm.from_string @@ Cstruct.to_string buf in
          Ok (of_json j)

    let write flow t =
      Message.write flow @@ Cstruct.of_string @@ Ezjsonm.to_string @@ to_json t
  end

  module Response = struct
    type t = { accepted : bool }

    open Ezjsonm

    let of_json j =
      let accepted = get_bool @@ find j [ "accepted" ] in
      { accepted }

    let to_json t =
      let open Ezjsonm in
      dict [ ("accepted", bool t.accepted) ]

    let read flow =
      match Message.read flow with
      | Error (`Flow e) -> Error (`Flow e)
      | Error `Eof -> Error `Eof
      | Ok buf ->
          let j = Ezjsonm.from_string @@ Cstruct.to_string buf in
          Ok (of_json j)

    let write flow t =
      Message.write flow @@ Cstruct.of_string @@ Ezjsonm.to_string @@ to_json t
  end
end

module Tcp = struct
  let any_port = 0

  let mem (dst_ip, dst_port) =
    List.exists
      (fun f ->
        f.protocol = `Tcp
        && Ipaddr.Prefix.mem dst_ip f.dst_prefix
        && (f.dst_port = any_port || f.dst_port = dst_port))
      !all

  let find (dst_ip, dst_port) =
    let f =
      List.find
        (fun f ->
          f.protocol = `Tcp
          && Ipaddr.Prefix.mem dst_ip f.dst_prefix
          && (f.dst_port = any_port || f.dst_port = dst_port))
        !all
    in
    f.path
end

module Unix = struct
  (* module FLOW = Host.Sockets.Stream.Unix *)
  module Sunix = Host.Sockets.Stream.Unix
  module Remote = Read_some
  module Handshake = Handshake

  type flow = read_some

  let connect ~sw ~net ?read_buffer_size:_ (dst_ip, dst_port) =
    let path = Tcp.find (dst_ip, dst_port) in
    let req = Fmt.str "%a, %d -> %s" Ipaddr.pp dst_ip dst_port path in
    Log.info (fun f -> f "%s: connecting" req);
    match Sunix.connect ~sw ~net path with
    | Error (`Msg m) -> Error (`Msg m)
    | Ok flow -> (
        Log.info (fun f -> f "%s: writing handshake" req);
        let remote = Remote.of_flow flow in
        match Handshake.Request.write remote
          {
            Handshake.Request.protocol = `Tcp;
            src_ip = Ipaddr.V4 Ipaddr.V4.any;
            src_port = 0;
            dst_ip;
            dst_port;
          }
        with
        | exception e ->
            Log.info (fun f ->
                f "%s: %s, returning RST" req (Printexc.to_string e));
            Flow.close remote;
              (Error
                 (`Msg
                   (Fmt.str "writing handshake: %s" (Printexc.to_string e))))
        | () -> (
            Log.info (fun f -> f "%s: reading handshake" req);
            match Handshake.Response.read remote with
            | Error e ->
                Log.info (fun f ->
                    f "%s: %a, returning RST" req Handshake.Message.pp_error e);
                Flow.close remote;
                  (Error
                     (`Msg
                       (Fmt.str "reading handshake: %a"
                          Handshake.Message.pp_error e)))
            | Ok { Handshake.Response.accepted = false } ->
                Log.info (fun f -> f "%s: request rejected" req);
                Flow.close remote;
                Error (`Msg "ECONNREFUSED")
            | Ok { Handshake.Response.accepted = true } ->
                Log.info (fun f -> f "%s: forwarding connection" req);
                Ok remote))
end

module Stream = struct
  module Tcp = struct
    type address = Ipaddr.t * int

    module Direct = Host.Sockets.Stream.Tcp
    module Forwarded = Unix

    (* type flow = [ `Direct of Direct.flow | `Forwarded of Forwarded.flow ] *)

    let connect ~sw ~net ?read_buffer_size:_ (ip, port) =
      if Tcp.mem (ip, port) then
        match Unix.connect ~sw ~net (ip, port) with
        | Ok flow -> Ok (flow :> <Eio.Flow.two_way; Eio.Flow.close; Iflow.r>)
        | Error e -> Error e
      else
        match Direct.connect ~sw ~net (ip, port) with
        | Ok flow -> Ok flow
        | Error e -> Error e

    type error = [ `Direct of Direct.error ]

    let pp_error ppf = function
      | `Direct err -> Direct.pp_error ppf err
      (* | `Forwarded err -> Forwarded.pp_error ppf err *)

    (*

    type write_error =
      [ `Closed
      | `Direct of Direct.write_error
      | `Forwarded of Forwarded.write_error ]

    let pp_write_error ppf = function
      | `Closed -> Fmt.string ppf "Closed"
      | `Direct err -> Direct.pp_write_error ppf err
      | `Forwarded err -> Forwarded.pp_write_error ppf err

    let wrap_direct_error t =
      match t with
      | Ok x -> Ok x
      | Error err -> Error (`Direct err)

    let wrap_forwarded_error t =
      match t with
      | Ok x -> Ok x
      | Error err -> Error (`Forwarded err)

    let read = function
      | `Direct flow -> wrap_direct_error @@ Direct.read flow
      | `Forwarded flow -> wrap_forwarded_error @@ Forwarded.read flow

    let write flow bufs =
      match flow with
      | `Direct flow -> wrap_direct_error @@ Direct.write flow bufs
      | `Forwarded flow -> wrap_forwarded_error @@ Forwarded.write flow bufs

    let writev flow bufs =
      match flow with
      | `Direct flow -> wrap_direct_error @@ Direct.writev flow bufs
      | `Forwarded flow -> wrap_forwarded_error @@ Forwarded.writev flow bufs

    let close = function
      | `Direct flow -> Direct.close flow
      | `Forwarded flow -> Forwarded.close flow

    let shutdown_write = function
      | `Direct flow -> Direct.shutdown_write flow
      | `Forwarded flow -> Forwarded.shutdown_write flow

    let shutdown_read = function
      | `Direct flow -> Direct.shutdown_read flow
      | `Forwarded flow -> Forwarded.shutdown_read flow
  *)
  end
end

module Proxy = struct
  let proxy a b =
    let open Eio in
    Switch.run @@ fun sw ->
    let a2b =
      Fiber.fork_promise ~sw @@ fun () ->
      try
        Flow.copy a b;
        Flow.shutdown a `Receive;
        Flow.shutdown b `Send;
        Ok ()
      with exn -> Error (Printexc.to_string exn)
    in
    let b2a =
      Fiber.fork_promise ~sw @@ fun () ->
      try
        Flow.copy b a;
        Flow.shutdown b `Receive;
        Flow.shutdown a `Send;
        Ok ()
      with exn -> Error (Printexc.to_string exn)
    in
    let a_stats = Eio.Promise.await_exn a2b in
    let b_stats = Eio.Promise.await_exn b2a in
    match a_stats, b_stats with
    | Ok a_stats, Ok b_stats -> Ok ()
    | Error e1  , Error e2   -> Error (`A_and_B (e1, e2))
    | Error e1  ,  _         -> Error (`A e1)
    | _         , Error e2   -> Error (`B e2)

    let pp_error ppf = function
    | `A_and_B (e1, e2) ->
      Fmt.pf ppf "flow proxy a: %s; flow proxy b: %s" e1 e2
    | `A e -> Fmt.pf ppf "flow proxy a: %s" e
    | `B e -> Fmt.pf ppf "flow proxy b: %s" e
end

module Test = struct
  module Remote = Host.Sockets.Stream.Unix
(*
  module Proxy =
    Mirage_flow_combinators.Proxy (Remote) (Host.Sockets.Stream.Tcp) *)

  type server = Host.Sockets.Stream.Unix.server

  let start_forwarder ~sw ~net ~mono path =
    let s = Host.Sockets.Stream.Unix.bind ~sw net path in
    Host.Sockets.Stream.Unix.listen ~sw net s (fun flow ->
        Log.info (fun f -> f "accepted flow");
        let local = Read_some.of_flow flow in
        match Handshake.Request.read local with
        | Error e ->
            Log.info (fun f ->
                f "reading handshake request %a" Handshake.Message.pp_error e)
        | Ok h -> (
            let req = Handshake.Request.to_string h in
            Log.info (fun f -> f "%s: connecting" req);
            match Host.Sockets.Stream.Tcp.connect ~sw ~net
              (h.Handshake.Request.dst_ip, h.Handshake.Request.dst_port) with
            | Error (`Msg m) -> (
                Log.info (fun f -> f "%s: %s" req m);
                match Handshake.Response.write local
                  { Handshake.Response.accepted = false } with
                | exception e ->
                    Log.info (fun f ->
                        f "%s: writing handshake response %s" req (Printexc.to_string e))
                | () ->
                    Log.info (fun f -> f "%s: returned handshake response" req)
            )
            | Ok remote ->
                Log.info (fun f -> f "%s: connected" req);
                Fun.protect
                  (fun () ->
                    match Handshake.Response.write local
                      { Handshake.Response.accepted = true } with
                    | exception e ->
                        Log.info (fun f ->
                            f "%s: writing handshake response %s" req (Printexc.to_string e))
                    | () -> (
                        Log.info (fun f -> f "%s: proxying data" req);
                        match Proxy.proxy local remote with
                        | Error e ->
                            Log.info (fun f ->
                                f "%s: TCP proxy failed with %a" req
                                  Proxy.pp_error e)
                        | Ok () -> ()))
                  ~finally:(fun () ->
                    Log.info (fun f -> f "%s: disconnecting from remote" req);
                    Flow.close remote)));
    s

  let shutdown = Host.Sockets.Stream.Unix.shutdown
end
