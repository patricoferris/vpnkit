(*
 * Copyright (C) 2016 David Scott <dave@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)
open Eio

let src =
  let src = Logs.Src.create "Dns_forward_eio" ~doc:"Eio-based I/O" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let default_read_buffer_size = 65536
let max_udp_length = 65507
(* IP datagram (65535) - IP header(20) - UDP header(8) *)

module Common = struct
  (** Both UDP and TCP *)
  let errorf fmt = Printf.ksprintf (fun s -> Error (`Msg s)) fmt

  type address = Ipaddr.t * int

  let sockaddr_of_address (dst, dst_port) =
    ( Eio_unix.Ipaddr.of_unix @@ Unix.inet_addr_of_string @@ Ipaddr.to_string dst,
      dst_port )

  let string_of_address (dst, dst_port) =
    Ipaddr.to_string dst ^ ":" ^ string_of_int dst_port

  let _getsockname fn_name fd_opt =
    match fd_opt with
    | None -> failwith (fn_name ^ ": socket is closed")
    | Some fd -> (
        match Unix.getsockname fd with
        | Unix.ADDR_INET (iaddr, port) ->
            ( Ipaddr.V4
                (Ipaddr.V4.of_string_exn (Unix.string_of_inet_addr iaddr)),
              port )
        | _ -> invalid_arg (fn_name ^ ": passed a non-TCP socket"))
end

module Tcp = struct
  include Common

  let of_flow ~read_buffer_size address flow = object
    inherit Flow.two_way

    val address = address

    method address = address

    method shutdown = Flow.shutdown flow
    method copy src = Flow.copy src flow
    method read_into = flow#read_into

    method close = Flow.close flow

    val read_buffer_size = read_buffer_size
    val mutable read_buffer = Cstruct.empty

    method read =
    if Cstruct.length read_buffer = 0 then
      read_buffer <- Cstruct.create read_buffer_size;
    let got = Flow.single_read flow read_buffer in
    let results = Cstruct.sub read_buffer 0 got in
    read_buffer <- Cstruct.shift read_buffer got;
    results
  end

  let string_of_flow flow =
    Printf.sprintf "tcp -> %s" (string_of_address flow#address)

  (* let writev flow bufs =
    try
      Flow.write flow bufs;
      Ok ()
    with
    | Exn.Io (Net.E (Net.Connection_reset _), _) -> Error `Closed
    | e ->
        Log.err (fun f ->
            f "%s: write caught %s returning Eof" (string_of_flow flow)
              (Printexc.to_string e));
        Error `Closed *)

  let connect ~sw ~net ?(read_buffer_size = default_read_buffer_size) address =
    let description = Printf.sprintf "tcp -> %s" (string_of_address address) in
    Log.debug (fun f -> f "%s: connect" description);
    let sockaddr = `Tcp (sockaddr_of_address address) in
    try
      let flow = Net.connect ~sw net sockaddr in
      Ok (of_flow ~read_buffer_size address flow :> <Iflow.rw; Flow.two_way; Flow.close>)
    with e ->
      errorf "%s: Net.connect: caught %s" description (Printexc.to_string e)

  let close t =
    Flow.close (t :> Flow.close);
    Log.debug (fun f -> f "%s: Tcp.close" (string_of_flow t))
  (* Eio should handle this ? Flow.close flow *)

  type server = {
    mutable flow : Net.listening_socket option;
    read_buffer_size : int;
    address : address;
  }

  let string_of_server t =
    Printf.sprintf "listen:tcp <- %s" (string_of_address t.address)

  let bind ~sw net address =
    try
      let flow =
        Net.listen ~reuse_addr:true ~sw ~backlog:5 net
          (`Tcp (sockaddr_of_address address))
      in
      Ok
        {
          flow = Some flow;
          read_buffer_size = default_read_buffer_size;
          address;
        }
    with e ->
      errorf "listen:tcp <- %s caught %s"
        (string_of_address address)
        (Printexc.to_string e)

  let getsockname server =
    (* TODO: fix *)
    Obj.magic server
  (* getsockname "Tcp.getsockname" server.flow *)

  let shutdown server =
    match server.flow with
    | None -> ()
    | Some flow ->
        server.flow <- None;
        Log.debug (fun f ->
            f "%s: close server socket" (string_of_server server));
        Flow.close flow

  let addr_of_sockaddr = function
    | `Tcp (ip, port) ->
        ( Eio_unix.Ipaddr.to_unix ip |> Unix.string_of_inet_addr
          |> Ipaddr.of_string_exn,
          port )
    | _ -> failwith "Unknown incoming socket address!"

  let close_noop (flow : Flow.two_way) = object
    inherit Flow.two_way
    method read_into = flow#read_into
    method shutdown = flow#shutdown
    method copy = flow#copy
    method close = ()
  end

  let listen ~sw (server : server) cb =
    let rec loop sock =
      Net.accept_fork ~sw sock
        ~on_error:(fun e -> traceln "%s" (Printexc.to_string e))
        (fun client sockaddr ->
          let read_buffer_size = server.read_buffer_size in
          let addr = addr_of_sockaddr sockaddr in
          let flow = of_flow ~read_buffer_size addr (close_noop client) in
          Fun.protect
            (fun () ->
              try cb (flow :> <Iflow.rw; Flow.two_way; Flow.close>)
              with e ->
                Log.info (fun f ->
                    f "tcp:%s <- %a: caught %s so closing flow"
                      (string_of_server server) Net.Sockaddr.pp sockaddr
                      (Printexc.to_string e)))
            ~finally:(fun () -> close flow);
          loop sock)
    in
    match server.flow with
    | None -> ()
    | Some fd ->
        Fiber.fork ~sw (fun () ->
            try
              Fun.protect
                (fun () ->
                  (* Lwt_unix.listen fd 32; *)
                  loop fd)
                ~finally:(fun () -> shutdown server)
            with e ->
              Log.info (fun f ->
                  f "%s: caught %s so shutting down server"
                    (string_of_server server) (Printexc.to_string e)))
end

module Udp = struct
  include Common

  type flow_state = {
    mutable dgram : < Net.datagram_socket > option;
    read_buffer_size : int;
    mutable already_read : Cstruct.t option;
    sockaddr : Net.Ipaddr.v4v6 * int;
    address : address;
  }

  let string_of_flow t =
    Printf.sprintf "udp -> %s" (string_of_address t.address)

  let read t =
    match (t.dgram, t.already_read) with
    | None, _ -> raise End_of_file
    | Some _, Some data when Cstruct.length data > 0 ->
        t.already_read <- Some (Cstruct.sub data 0 0);
        (* next read is `Eof *)
        data
    | Some _, Some _ -> raise End_of_file
    | Some dgram, None -> (
        let buffer = Cstruct.create t.read_buffer_size in
        try
          (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
          let _from, n = Net.recv dgram buffer in
          let response = Cstruct.sub buffer 0 n in
          response
        with e ->
          Log.err (fun f ->
              f "%s: recvfrom caught %s returning Eof" (string_of_flow t)
                (Printexc.to_string e));
          raise End_of_file)

  (* let write t buf =
    match t.dgram with
    | None -> Error `Closed
    | Some d -> (
        try
          (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
          Net.send d (`Udp t.sockaddr) buf;
          Ok ()
        with e ->
          Log.err (fun f ->
              f "%s: sendto caught %s returning Eof" (string_of_flow t)
                (Printexc.to_string e));
          Error `Closed) *)

  (* let writev t bufs = write t (Cstruct.concat bufs) *)

  type server = {
    mutable server : < Net.datagram_socket > option;
    address : address;
  }

  let string_of_server t =
    Printf.sprintf "listen udp:%s" (string_of_address t.address)

  let getsockname _server = raise (Failure "TODO")
  (* getsockname "Udp.getsockname" server.server_fd *)

  let bind ~sw net address =
    try
      let addr = sockaddr_of_address address in
      let sock = Net.datagram_socket ~sw net (`Udp addr) in
      Ok { server = Some (sock :> Net.datagram_socket); address }
    with e ->
      errorf "udp:%s: bind caught %s"
        (string_of_address address)
        (Printexc.to_string e)

  let shutdown t =
    match t.server with
    | None -> ()
    | Some _fd ->
        t.server <- None;
        Log.debug (fun f -> f "%s: close" (string_of_server t))
  (* Lwt_unix.close fd *)

  let of_dgram ?(read_buffer_size = max_udp_length) ?(already_read = None)
  sockaddr address d =
    let state = { dgram = Some d; read_buffer_size; already_read; sockaddr; address } in
    object
      inherit Flow.two_way
      inherit Iflow.r

      val state = state

      method copy = failwith "Not implemented... yet?"

      method read = read state

      method read_into buf =
        let r = read state in
        let len = min (Cstruct.length buf) (Cstruct.length r) in
        Cstruct.blit r 0 buf 0 len;
        len

      (* method read_methods = [] *)

      method shutdown _ = ()
      method close = ()
    end

  let connect ~sw ~net ?read_buffer_size address =
  Log.debug (fun f -> f "udp -> %s: connect" (string_of_address address));
  (* Win32 requires all sockets to be bound however macOS and Linux don't *)
  let dgram = Net.datagram_socket ~sw net (`Udp (Net.Ipaddr.V4.any, 0)) in
  let sockaddr = sockaddr_of_address address in
  Ok
    (of_dgram ?read_buffer_size sockaddr address
      (dgram :> Net.datagram_socket) :> <Iflow.rw; Flow.two_way; Flow.close>)

  let listen ~sw t flow_cb =
    let buffer = Cstruct.create max_udp_length in
    match t.server with
    | None -> ()
    | Some d ->
        let rec loop () =
          let res =
            try
              (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
              let sockaddr, n = Net.recv d buffer in
              let data = Cstruct.sub buffer 0 n in
              (* construct a flow with this buffer available for reading *)
              let ((ip, port) as sockaddr) =
                match sockaddr with `Udp address -> address
              in
              let address =
                ( Eio_unix.Ipaddr.to_unix ip |> Unix.string_of_inet_addr
                  |> Ipaddr.of_string_exn,
                  port )
              in
              let flow =
                of_dgram ~read_buffer_size:0 ~already_read:(Some data) sockaddr
                  address d
              in
              Fiber.fork ~sw (fun () ->
                  try flow_cb flow
                  with e ->
                    Log.info (fun f ->
                        f "%s: listen callback caught: %s" (string_of_server t)
                          (Printexc.to_string e)));
              true
            with e ->
              Log.err (fun f ->
                  f "%s: listen caught %s shutting down server"
                    (string_of_server t) (Printexc.to_string e));
              false
          in
          match res with false -> () | true -> loop ()
        in
        Fiber.fork ~sw loop
end

module R = struct
  open Dns_forward
  module Udp_client = Rpc.Client.Nonpersistent.Make (Udp) (Framing.Udp)
  module Udp = Resolver.Make (Udp_client)
  module Tcp_client = Rpc.Client.Persistent.Make (Tcp) (Framing.Tcp)
  module Tcp = Resolver.Make (Tcp_client)
end

module Server = struct
  open Dns_forward
  module Udp_server = Rpc.Server.Make (Udp) (Framing.Udp)
  module Udp = Server.Make (Udp_server) (R.Udp)
  module Tcp_server = Rpc.Server.Make (Tcp) (Framing.Tcp)
  module Tcp = Server.Make (Tcp_server) (R.Tcp)
end

module Resolver = R
