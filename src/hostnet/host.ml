open Eio
module Eluv = Eio_luv.Low_level

let sockaddr_of_address (dst, dst_port) =
  ( Eio_unix.Ipaddr.of_unix @@ Unix.inet_addr_of_string @@ Ipaddr.to_string dst,
    dst_port )

let src =
  let src = Logs.Src.create "Eio" ~doc:"Host interface using Eio" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let log_exception_continue description f =
  let to_string = function Failure x -> x | e -> Printexc.to_string e in
  try f () with e ->
    Log.warn (fun f -> f "%s: %s" description (to_string e))

let make_sockaddr (ip, port) =
  match ip with
  | Ipaddr.V4 _ -> Luv.Sockaddr.ipv4 (Ipaddr.to_string ip) port
  | Ipaddr.V6 _ -> Luv.Sockaddr.ipv6 (Ipaddr.to_string ip) port

let parse_datagram_sockaddr (v : Net.Sockaddr.datagram) =
  let (`Udp (ip, port)) = v in
  let ip = Eio_unix.Ipaddr.to_unix ip |> Unix.string_of_inet_addr in
  Ok (Ipaddr.of_string_exn ip, port)

let string_of_address (dst, dst_port) =
  Ipaddr.to_string dst ^ ":" ^ string_of_int dst_port

let ( >>= ) = Result.bind

let ( >>*= ) m f = match m with
  | Error (`Msg m) -> failwith m
  | Ok x -> f x

module Common = struct
  (** FLOW boilerplate *)

  type error = [ `Msg of string ]
  type write_error = [ Mirage_flow.write_error | error ]

  let pp_error ppf (`Msg x) = Fmt.string ppf x

  let pp_write_error ppf = function
    | #Mirage_flow.write_error as e -> Mirage_flow.pp_write_error ppf e
    | #error as e -> pp_error ppf e
end

module Sockets = struct
  module Datagram = struct
    type address = Ipaddr.t * int

    let string_of_address = string_of_address

    module Udp = struct
      include Common

      type flow_state = {
        idx : int option;
        label : string;
        description : string;
        mutable fd : <Net.datagram_socket; Flow.close> option;
        mutable already_read : Cstruct.t option;
        sockaddr : Ipaddr.t * int;
        address : address;
      }

      type address = Ipaddr.t * int

      let string_of_flow t = Fmt.str "udp -> %s" (string_of_address t.address)

      let read t =
        match (t.fd, t.already_read) with
        | None, _ -> Ok `Eof
        | Some _, Some data when Cstruct.length data > 0 ->
            t.already_read <- Some (Cstruct.sub data 0 0);
            (* next read is `Eof *)
            Ok (`Data data)
        | Some _, Some _ -> Ok `Eof
        | Some fd, None ->
            (* TODO: Partial READS and buffers!!!! *)
            let buf = Cstruct.create Constants.max_udp_length in
            (* Correct? *)
            let rec recv () =
              let peer, read = Net.recv fd buf in
              match parse_datagram_sockaddr peer with
              | Error _ ->
                Log.warn (fun f ->
                    f
                      "Socket.%s.read: dropping response from \
                      unknown peer"
                      t.label);
                recv ()
              | Ok address when address <> t.address ->
                  Log.warn (fun f ->
                      f
                        "Socket.%s.read: dropping response from %s \
                        since we're connected to %s"
                        t.label
                        (string_of_address address)
                        (string_of_address t.address));
                  recv ()
              | Ok _ ->
                (* We got one! *)
                let buf = Cstruct.sub buf 0 read in
                Ok (`Data buf)
          in
            recv ()

      let writev t bufs =
        match t.fd with
        | None -> Error `Closed
        | Some fd ->
            (* TODO: Need sendv equivalent. *)
            let ip, port = t.sockaddr in
            let ip = Ipaddr.to_string ip |> Unix.inet_addr_of_string |> Eio_unix.Ipaddr.of_unix in
            Net.send fd (`Udp (ip, port)) (Cstruct.concat bufs);
            Ok ()

      let write t buf = writev t [ buf ]

      let close t =
        match t.fd with
        | None -> ()
        | Some fd ->
            t.fd <- None;
            Log.debug (fun f ->
                f "Socket.%s.close: %s" t.label (string_of_flow t));
            let () =
              match t.idx with
              | Some idx -> Connection_limit.deregister idx
              | None -> ()
            in
              Flow.close fd

      let shutdown_read _t = ()
      let shutdown_write _t = ()

      type server = {
        idx : int;
        label : string;
        ds : <Net.datagram_socket; Flow.close>;
        ds_mutex : Eio.Mutex.t;
        mutable closed : bool;
        mutable disable_connection_tracking : bool;
      }

      let of_fd ?idx ?(read_buffer_size=4096) ?(already_read = None) ~description
          sockaddr address fd =
        let label =
          match fst address with
          | Ipaddr.V4 _ -> "UDPv4"
          | Ipaddr.V6 _ -> "UDPv6"
        in
        let state =
          {
            idx;
            label;
            description;
            fd = Some fd;
            already_read;
            sockaddr;
            address;
          }
        in object
          inherit Eio.Flow.two_way

          method read =
            match read state with
            | Ok (`Data buf) -> buf
            | Ok `Eof -> raise End_of_file
            | Error _ -> failwith "Unexpected read error"

          method close = close state

          method read_into buf =
            match read state with
            | Ok (`Data r) ->
              let len = min (Cstruct.length buf) (Cstruct.length r) in
              Cstruct.blit r 0 buf 0 len;
              len
            | Ok `Eof -> raise End_of_file
            | Error _ -> failwith "Unexpected faildure in UDP"

          method shutdown _ = ()

          method copy src =
            let buf = Cstruct.create read_buffer_size in
            try
              while true do
                let got = Flow.single_read src buf in
                let buf' = Cstruct.sub buf 0 got in
                write state buf' |> Result.get_ok
              done
            with End_of_file -> ()
        end

      let connect ~sw ~net ?read_buffer_size address =
        let description = "udp:" ^ string_of_address address in
        let label =
          match address with
          | Ipaddr.V4 _, _ -> "UDPv4"
          | Ipaddr.V6 _, _ -> "UDPv6"
        in
        let ip, port = address in
        let eio_ip = Ipaddr.to_string ip |> Unix.inet_addr_of_string |> Eio_unix.Ipaddr.of_unix in
        let sock =
          match Connection_limit.register description with
          | Error e -> Error e
          | Ok idx -> (
                try
                  let sock = Net.datagram_socket ~sw net (`Udp (eio_ip, port)) in
                  Ok (sock, address, idx)
                with e -> (
                  Connection_limit.deregister idx;
                  Error (`Msg (Fmt.to_to_string Exn.pp e))
                )
          )
        in
        match sock with
        | Error (`Msg m) ->
            let msg =
              Fmt.str "Socket.%s.connect %s: %s" label
                (string_of_address address)
                m
            in
            Log.info (fun f -> f "%s" msg);
            Error (`Msg msg)
        | Ok (fd, sockaddr, idx) ->
              (Ok
                 (of_fd ~idx ?read_buffer_size ~description sockaddr address fd))

      let make ~idx ~label ds =
        let ds_mutex = Eio.Mutex.create () in
        {
          idx;
          label;
          ds;
          ds_mutex;
          closed = false;
          disable_connection_tracking = false;
        }

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let bind ~sw net ?(description = "") (ip, port) =
        let label =
          match ip with Ipaddr.V4 _ -> "UDPv4" | Ipaddr.V6 _ -> "UDPv6"
        in
        let description =
          Fmt.str "udp:%a:%d %s" Ipaddr.pp ip port description
        in
        let sock =
          match Connection_limit.register description with
          | Error e -> Error e
          | Ok idx -> (
              try
                let addr = sockaddr_of_address (ip, port) in
                let sock = Net.datagram_socket ~sw net (`Udp addr) in
                Ok (sock, idx)
              with e ->
                Error (`Msg (Fmt.str "udp:%s: bind caught %s"
                  (string_of_address (ip, port))
                  (Printexc.to_string e)))
          )
        in
        match sock with
        | Error (`Msg m) ->
            let msg =
              Fmt.str "Socket.%s.bind %s:%d: %s" label (Ipaddr.to_string ip)
                port m
            in
            Log.err (fun f -> f "%s" msg);
            failwith msg
        | Ok (fd, idx) -> make ~idx ~label fd

      let of_bound_fd ~sw:_ ?read_buffer_size:_ _fd =
        failwith "TODO: Eio_unix.sock_as_fd"
        (* Luv_lwt.in_luv (fun return ->
            match Luv_unix.Os_fd.Socket.from_unix fd with
            | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
            | Ok socket -> (
                match Luv.UDP.init () with
                | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                | Ok udp -> (
                    match Luv.UDP.open_ udp socket with
                    | Error err ->
                        Luv.Handle.close udp ignore;
                        return (Error (`Msg (Luv.Error.strerror err)))
                    | Ok () -> (
                        match Luv.UDP.getsockname udp with
                        | Error _ ->
                            (* This can fail for ICMP sockets, but they still work. *)
                            let label = "unknown" in
                            let idx =
                              Connection_limit.register_no_limit "udp"
                            in
                            return (Ok (idx, label, udp))
                        | Ok sockaddr ->
                            let ip =
                              match Luv.Sockaddr.to_string sockaddr with
                              | None -> "None"
                              | Some x -> x
                            in
                            let port =
                              match Luv.Sockaddr.port sockaddr with
                              | None -> "None"
                              | Some x -> string_of_int x
                            in
                            let label = "udp:" ^ ip ^ ":" ^ port in
                            let idx =
                              Connection_limit.register_no_limit "udp"
                            in
                            return (Ok (idx, label, udp))))))
        >>*= fun (idx, label, udp) ->
        Lwt.return (make ~idx ~label udp) *)

      let getsockname _ = failwith "TODO"
        (* Luv_lwt.in_luv (fun return ->
            match Luv.UDP.getsockname fd with
            | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
            | Ok sockaddr -> (
                match parse_sockaddr sockaddr with
                | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                | Ok (ip, port) -> return (Ok (ip, port))))
        >>*= fun x ->
        Lwt.return x *)

      let shutdown server =
        if not server.closed then (
          server.closed <- true;
          Connection_limit.deregister server.idx;
          Flow.close server.ds
        )

      let recvfrom server buf =
        let fd = server.ds in
            (* Correct? *)
        let rec recv () =
          let peer, read = Net.recv fd buf in
          match parse_datagram_sockaddr peer with
          | Error _ ->
            Log.warn (fun f ->
                f
                  "Socket.%s.read: dropping response from \
                  unknown peer"
                  server.label);
            recv ()
          | Ok addr ->
            (* We got one! *)
            read, addr
          in
            recv ()

      let listen ~sw _net t flow_cb =
        let rec loop () =
          let v =
          try
            (* Allocate a fresh buffer because the packet will be
                processed in a background thread *)
            let buffer = Cstruct.create Constants.max_udp_length in
            let n, address = recvfrom t buffer in
            let data = Cstruct.sub buffer 0 n in
            (* construct a flow with this buffer available for reading *)
            (* No new fd so no new idx *)
            let description = Fmt.str "udp:%s" (string_of_address address) in
            let flow =
              of_fd ~description ~read_buffer_size:0
                ~already_read:(Some data) address address t.ds
            in
              Fiber.fork ~sw (fun () ->
                try flow_cb flow with e ->
                Log.info (fun f ->
                  f "Socket.%s.listen callback caught: %s" t.label
                    (Printexc.to_string e))
              );
              true
          with e -> (
            Log.info (fun f ->
                f "Socket.%s.listen caught %s shutting down server" t.label
                  (Printexc.to_string e));
            false
          )
          in
        match v with
        | false -> ()
        | true -> loop ()
      in
        Fiber.fork ~sw loop

      let sendto server (ip, port) ?(ttl = 64) buf =
        ignore ttl;
        (* Avoid a race between the setSocketTTL and the send_ba *)
        let v =
          Eio.Mutex.use_ro server.ds_mutex (fun () ->
            (* TODO: No TTL for eio socket *)
            let ip = Ipaddr.to_string ip |> Unix.inet_addr_of_string |> Eio_unix.Ipaddr.of_unix in
            Net.send server.ds (`Udp (ip, port)) buf;
            Ok ())
        in
        match v with
        | Error (`Msg m) ->
            let msg =
              Fmt.str "%s.sendto %s: %s" server.label
                (string_of_address (ip, port))
                m
            in
            Log.info (fun f -> f "%s" msg);
            failwith m
        | Ok () -> ()
    end
  end

  module Stream = struct
    (* Common across TCP and Pipes *)

    module Tcp = struct
      include Common

      type address = Ipaddr.t * int

      let get_test_address () =
        let localhost = Unix.inet_addr_of_string "127.0.0.1" in
        let s = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
        Unix.bind s (Unix.ADDR_INET (localhost, 0));
        let sa = Unix.getsockname s in
        Unix.close s;
        match sa with
        | Unix.ADDR_INET (_, port) -> (Ipaddr.of_string_exn "127.0.0.1", port)
        | _ -> failwith "get_test_address"

      type flow_state = {
        idx : int;
        label : string;
        description : string;
        fd : <Flow.two_way; Flow.close>;
        mutable closed : bool;
      }

      let shutdown_read _ = ()

      let shutdown_write { label = _; fd; closed; _ } =
        if not closed then (
          Flow.shutdown fd `Send
        )
        else ()

      let read t =
        if t.closed
        then (Log.info (fun f -> f "read %s already closed: EOF" t.description); Ok `Eof)
        else begin
          (* TODO: Hmmm, allocating a buffer like this is bad!?
             Either we need a better API for this or we should
             allocate a bigger buffer, read into offsets and only
             if we reach the end do we allocate a new buffer. *)
          let acc = ref [] in
          let () =
            try
              while true do
                let buf = Cstruct.create 1024 in
                let n = Flow.single_read t.fd buf in
                acc := Cstruct.sub buf 0 n :: !acc
              done
            with End_of_file -> ()
          in
            Ok (`Data (List.rev !acc |> Cstruct.concat))
        end
      let writev t bufs =
        if t.closed (* || t.shutdown *)
        then (Log.info (fun f -> f "writev %s already closed: EPIPE" t.description); Error (`Msg "EPIPE"))
        else Ok (Flow.write t.fd bufs)
      let write t buf = writev t [ buf ]

      let close t =
        if not t.closed then (
          t.closed <- true;
          Connection_limit.deregister t.idx;
          Flow.close t.fd
        )

      let of_fd ~label ~idx ?(read_buffer_size=4096) ~description fd =
        let closed = false in
        let state = { idx; label; description; fd; closed } in object
          inherit Eio.Flow.two_way

          method close = close state

          method read =
            match read state with
            | Ok (`Data buf) -> buf
            | Ok `Eof -> raise End_of_file
            | Error _ -> failwith "Unexpected error in TCP"

          method read_into buf =
            match read state with
            | Ok (`Data r) ->
              let len = min (Cstruct.length buf) (Cstruct.length r) in
              Cstruct.blit r 0 buf 0 len;
              len
            | Ok `Eof -> raise End_of_file
            | Error _ -> failwith "Unexpected faildure in UDP"

          method shutdown _ = ()

          method copy src =
            let buf = Cstruct.create read_buffer_size in
            try
              while true do
                let got = Flow.single_read src buf in
                let buf' = Cstruct.sub buf 0 got in
                write state buf' |> Result.get_ok
              done
            with End_of_file -> ()
        end

      let read_into t buf =
        try Ok (`Data (Flow.read_exact t buf)) with End_of_file -> Ok `Eof

      let connect ~sw ~net ?read_buffer_size:_ (ip, port) =
        let description = Fmt.str "tcp:%a:%d" Ipaddr.pp ip port in
        let label =
          match ip with Ipaddr.V4 _ -> "TCPv4" | Ipaddr.V6 _ -> "TCPv6"
        in
        match Connection_limit.register description with
        | Error _ ->
            (Error
               (`Msg
                 (Printf.sprintf "Socket.%s.connect: hit connection limit"
                    label)))
        | Ok idx ->
          let sockaddr = `Tcp (sockaddr_of_address (ip, port)) in
          try
            let flow = Net.connect ~sw net sockaddr in
            Ok (of_fd ~label ~idx ~description flow)
          with e ->
            Connection_limit.deregister idx;
            let msg =
              Fmt.str "Socket.%s.connect %s:%d: %a" label (Ipaddr.to_string ip)
                port Exn.pp e
            in
            Error (`Msg msg)

      type server = {
        label : string;
        mutable listening_fds : (int * (Ipaddr.t * int) * Net.listening_socket) list;
        mutable disable_connection_tracking : bool;
      }

      let label_of ip =
        match ip with Ipaddr.V4 _ -> "TCPv4" | Ipaddr.V6 _ -> "TCPv6"

      let make ?read_buffer_size:_ ip listening_fds =
        let label = label_of ip in
        { label; listening_fds; disable_connection_tracking = false }

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let getsockname server =
        match server.listening_fds with
        | [] -> failwith "socket is closed"
        | (_, (ip, port), _) :: _ -> ip, port

      let bind_one ~sw net ?(description = "") (ip, port) =
        let label =
          match ip with Ipaddr.V4 _ -> "TCPv4" | Ipaddr.V6 _ -> "TCPv6"
        in
        let description =
          Fmt.str "tcp:%a:%d %s" Ipaddr.pp ip port description
        in
        match Connection_limit.register description with
        | Error _ as e -> e
        | Ok idx ->
          try
            let flow =
              Net.listen ~reuse_addr:true ~sw ~backlog:5 net
                (`Tcp (sockaddr_of_address (ip, port)))
            in
            Ok (idx, label, flow, port)
          with e ->
            let msg =
              Fmt.str "Socket.%s.bind_one %s:%d: %a" label (Ipaddr.to_string ip)
                port Exn.pp e
            in
            Log.err (fun f -> f "%s" msg);
            Error (`Msg msg)

      let bind ~sw net ?description (ip, requested_port) =
        bind_one ~sw net ?description (ip, requested_port)
        >>*= fun (idx, _label, fd, bound_port) ->
            (* On some systems localhost will resolve to ::1 first and this can
               cause performance problems (particularly on Windows). Perform a
               best-effort bind to the ::1 address. *)
            let extra =
              try
                if
                  Ipaddr.compare ip (Ipaddr.V4 Ipaddr.V4.localhost) = 0
                  || Ipaddr.compare ip (Ipaddr.V4 Ipaddr.V4.any) = 0
                then (
                  Log.debug (fun f ->
                      f "Attempting a best-effort bind of ::1:%d" bound_port);
                  bind_one ~sw net (Ipaddr.(V6 V6.localhost), bound_port)
                  >>*= fun (idx, _, fd, _) ->
                  [ (idx, (ip, bound_port), fd) ])
                else []
              with e ->
                Log.debug (fun f ->
                    f "Ignoring failed bind to ::1:%d (%a)" bound_port Fmt.exn e);
                []
            in
              make ip ((idx, (ip, bound_port), fd) :: extra)

      let shutdown server =
        let fds = server.listening_fds in
        server.listening_fds <- [];
        List.iter
          (fun (idx, _, fd) ->
            Connection_limit.deregister idx;
            Flow.close fd)
          fds

      let of_bound_fd ~sw:_ ?read_buffer_size:_ _fd =
        failwith "Eio_unix.sock_as_fd: TCP"
        (* Luv_lwt.in_luv (fun return ->
            match Luv_unix.Os_fd.Socket.from_unix fd with
            | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
            | Ok socket -> (
                match Luv.TCP.init () with
                | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
                | Ok tcp -> (
                    match Luv.TCP.open_ tcp socket with
                    | Error err ->
                        Luv.Handle.close tcp (fun () ->
                            return (Error (`Msg (Luv.Error.strerror err))))
                    | Ok () -> (
                        match Luv.TCP.getsockname tcp with
                        | Error err ->
                            Luv.Handle.close tcp (fun () ->
                                return (Error (`Msg (Luv.Error.strerror err))))
                        | Ok sockaddr -> (
                            match Luv.Sockaddr.to_string sockaddr with
                            | None ->
                                Luv.Handle.close tcp (fun () ->
                                    return
                                      (Error
                                         (`Msg
                                           "TCP.getsockname returned no IP \
                                            address")))
                            | Some x -> (
                                match Ipaddr.of_string x with
                                | Error (`Msg m) ->
                                    Luv.Handle.close tcp (fun () ->
                                        return
                                          (Error
                                             (`Msg
                                               ("TCP.getsockname returned an \
                                                 invalid IP: " ^ x ^ ": " ^ m))))
                                | Ok ip -> (
                                    match Luv.Sockaddr.port sockaddr with
                                    | None ->
                                        Luv.Handle.close tcp (fun () ->
                                            return
                                              (Error
                                                 (`Msg
                                                   "TCP.getsockname returned \
                                                    no port number")))
                                    | Some port ->
                                        let description =
                                          Printf.sprintf "tcp:%s:%d" x port
                                        in
                                        let idx =
                                          Connection_limit.register_no_limit
                                            description
                                        in
                                        return (Ok (idx, (ip, port), tcp)))))))))
        >>*= fun (idx, (ip, port), fd) ->
        Lwt.return (make ip [ (idx, (ip, port), fd) ]) *)

      let close_noop (flow : Flow.two_way) = object
        inherit Flow.two_way
        method read_into = flow#read_into
        method shutdown = flow#shutdown
        method copy = flow#copy
        method close = ()
      end

      (* TODO: There's no way to split the bind and listen in Eio. *)
      let listen ~sw _net server' cb =
        let handle_connection client label description idx =
          let flow = of_fd ~label ~idx ~description client in
          log_exception_continue "TCP.listen" (fun () -> cb flow)
        in
        List.iter
          (fun (_, (ip, port), fd) ->
            let description =
              Fmt.str "%s:%s:%d" server'.label (Ipaddr.to_string ip)
                port
            in
            Net.accept_fork ~sw ~on_error:(fun e -> Log.debug (fun f -> f "TCP Listen: %a" Fmt.exn e)) fd (fun client sockaddr ->
              match
                ( Connection_limit.register description,
                  server'.disable_connection_tracking )
              with
              | Ok idx, _ ->
                  handle_connection (close_noop client) server'.label
                    description idx
              | Error _, true ->
                  let idx =
                    Connection_limit.register_no_limit
                      description
                  in
                  handle_connection (close_noop client) server'.label
                    description idx
              | _ -> ()
            ))
          server'.listening_fds
    end

    module Unix = struct
      include Common

      type address = string

      let get_test_address () =
        let i = Random.int 1_000_000 in
        if Sys.os_type = "Win32" then
          Printf.sprintf "\\\\.\\pipe\\vpnkittest%d" i
        else Printf.sprintf "/tmp/vpnkittest.%d" i

      type flow_state = {
        idx : int;
        description : string;
        flow : Flow.two_way;
        mutable closed : bool;
      }

      let shutdown_read _ = ()

      let shutdown_write { flow; closed; _ } =
        if not closed then begin
          try Flow.shutdown flow `Send with
          | err ->
            Log.warn (fun f ->
              f "Pipe.shutdown_write: %a" Exn.pp err)
        end
        else ()

        let read t =
          if t.closed
          then (Log.info (fun f -> f "read %s already closed: EOF" t.description); Ok `Eof)
          else begin
            (* TODO: Hmmm, allocating a buffer like this is bad!?
               Either we need a better API for this or we should
               allocate a bigger buffer, read into offsets and only
               if we reach the end do we allocate a new buffer. *)
            let acc = ref [] in
            let () =
              try
                while true do
                  let buf = Cstruct.create 1024 in
                  let n = Flow.single_read t.flow buf in
                  acc := Cstruct.sub buf 0 n :: !acc
                done
              with End_of_file -> ()
            in
              Ok (`Data (List.rev !acc |> Cstruct.concat))
          end
      let writev t bufs =
        if t.closed (* || t.shutdown *)
        then (Log.info (fun f -> f "writev %s already closed: EPIPE" t.description); Error (`Msg "EPIPE"))
        else Ok (Flow.write t.flow bufs)
      let write t buf = writev t [ buf ]

      let close t =
        if not t.closed then (
          t.closed <- true;
          Connection_limit.deregister t.idx;
          (* Flow.close t.flow *)
        )

      let of_flow ~idx ?(read_buffer_size=4096) ~description flow =
        let closed = false in
        let state = { idx; description; flow; closed } in object
          inherit Eio.Flow.two_way

          method read =
            match read state with
            | Ok (`Data buf) -> buf
            | Ok `Eof -> raise End_of_file
            | Error _ -> failwith "Unexpected read error"

          method close = close state

          method read_into buf =
            match read state with
            | Ok (`Data r) ->
              let len = min (Cstruct.length buf) (Cstruct.length r) in
              Cstruct.blit r 0 buf 0 len;
              len
            | Ok `Eof -> raise End_of_file
            | Error _ -> failwith "Unexpected faildure in UDP"

          method shutdown _ = ()

          method copy src =
            let buf = Cstruct.create read_buffer_size in
            try
              while true do
                let got = Flow.single_read src buf in
                let buf' = Cstruct.sub buf 0 got in
                write state buf' |> Result.get_ok
              done
            with End_of_file -> ()

        end

      let read_into t buf =
        try Ok (`Data (Flow.read_exact t buf)) with End_of_file -> Ok `Eof

      let unsafe_get_raw_fd _t = failwith "unsafe_get_raw_fd unimplemented"

      let connect ~sw ~net ?read_buffer_size:_ path =
        let description = "unix:" ^ path in
        let res =
            match Connection_limit.register description with
            | Error e -> Error e
            | Ok idx -> (
                try
                  let conn = Net.connect ~sw net (`Unix path) in
                  Ok (idx, conn)
                with e -> (
                    Connection_limit.deregister idx;
                    let msg =
                      Fmt.str "Pipe.connect %s: %a" path
                        Exn.pp e
                    in
                    Log.err (fun f -> f "%s" msg);
                    Error (`Msg msg)
                )
            )
        in
        match res with
        | Error e -> Error e
        | Ok (idx, fd) -> Ok (of_flow ~description ~idx (fd :> Flow.two_way))

      type server = {
        idx : int;
        flow : Net.listening_socket;
        mutable closed : bool;
        mutable disable_connection_tracking : bool;
      }

      let bind ~sw net ?(description = "") path =
        let description = Fmt.str "unix:%s %s" path description in
          Unix.unlink path;
          match Connection_limit.register description with
            | Error _ -> failwith description
            | Ok idx -> (
              try
                let flow = Net.listen ~backlog:5 ~sw net (`Unix path) in
                {
                  idx;
                  flow;
                  closed = false;
                  disable_connection_tracking = false;
                }
              with e ->
                Connection_limit.deregister idx;
                raise e
            )

      let getsockname _server = invalid_arg "TODO: Unix.sockname passed a non-Unix socket"

      let disable_connection_tracking server =
        server.disable_connection_tracking <- true

      let listen ~sw _net ({ flow; _ } as server') cb =
        let handle_connection client description idx =
          let flow = of_flow ~idx ~description client in
          log_exception_continue "Pipe.listen" (fun () -> cb flow)
        in
        let description =
          "unix:"
          ^
          match getsockname flow with
          | Ok path -> path
          | Error err -> "(error " ^ Luv.Error.strerror err ^ ")"
        in
        Net.accept_fork ~sw flow ~on_error:(fun e -> Logs.warn (fun f -> f "Pipe.accept_fork: %a" Exn.pp e))
        (fun client _addr ->
          match
            ( Connection_limit.register description,
              server'.disable_connection_tracking )
          with
          | Ok idx, _ ->
              handle_connection client description idx
          | Error _, true ->
              let idx =
                Connection_limit.register_no_limit description
              in
              handle_connection client description idx
          | _, _ -> Logs.debug (fun f -> f "Closing")
        )

      let of_bound_fd ~sw:_ ?read_buffer_size:_ _fd =
        failwith "Eio_unix.FD.as_socket"
        (* let v =
          match Eio_unix.FD.as_socket ~sw ~close_unix:true fd with
          | Error err -> Error (`Msg (Luv.Error.strerror err))
          | Ok fd -> (
              match Luv.Pipe.init () with
              | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
              | Ok pipe -> (
                  match Luv.File.open_osfhandle fd with
                  | Error err ->
                      Luv.Handle.close pipe (fun () ->
                          return (Error (`Msg (Luv.Error.strerror err))))
                  | Ok file -> (
                      match Luv.Pipe.open_ pipe file with
                      | Error err ->
                          Luv.Handle.close pipe (fun () ->
                              return (Error (`Msg (Luv.Error.strerror err))))
                      | Ok () -> (
                          match Luv.Pipe.getsockname pipe with
                          | Error err ->
                              Luv.Handle.close pipe (fun () ->
                                  return
                                    (Error (`Msg (Luv.Error.strerror err))))
                          | Ok path ->
                              let description = "unix:" ^ path in
                              let idx =
                                Connection_limit.register_no_limit description
                              in
                              return (Ok (pipe, idx))))))
        in
        match v with
        | Error (`Msg m) ->
            Log.warn (fun f -> f "%s" m);
            failwith m
        | Ok (flow, idx) ->
            { idx; flow; closed = false; disable_connection_tracking = false } *)

      let shutdown server =
        if not server.closed then (
          server.closed <- true;
          Connection_limit.deregister server.idx;
          Flow.close server.flow
        )
    end
  end
end

module type ClientServer = sig
  include Sig.FLOW_CLIENT
  include Sig.FLOW_SERVER with type address := address

  val get_test_address : unit -> address
end

module TestServer (F : ClientServer) = struct
  let with_server ~sw ~net address f =
    let server = F.bind ~sw net address in
    Fun.protect (fun () -> f server) ~finally:(fun () -> F.shutdown server)

  let with_flow flow f = Fun.protect f ~finally:(fun () -> Flow.close flow)

  let one_connection ~sw ~net () =
    let address = F.get_test_address () in
    with_server address (fun server ->
        let connected = Stream.create 1 in
        F.listen ~sw net server (fun flow ->
            Stream.add connected (); Flow.close flow);
        F.connect ~sw ~net address
        >>*= fun flow ->
            with_flow flow (fun () ->
                Stream.take connected; ()))

  let stream_data ~sw ~net () =
    let address = F.get_test_address () in
       with_server address (fun server ->
           let received = Stream.create 1 in
           F.listen ~sw net server (fun flow ->
               let digest = with_flow flow (fun () ->
                   let sha = Sha1.init () in
                   let buf = Cstruct.create 1024 in
                   let rec loop () =
                     match Flow.single_read flow buf with
                     | exception End_of_file -> ()
                     | i ->
                        let buf = Cstruct.sub buf 0 i in
                        let ba = Cstruct.to_bigarray buf in
                        Sha1.update_buffer sha ba;
                        loop ()
                   in
                   loop ();
                   Sha1.(to_hex @@ finalize sha))
              in
              Stream.add received digest);
           F.connect ~sw ~net address
           >>*= fun flow ->
               let sent_digest = with_flow flow (fun () ->
                   let buf = Cstruct.create 1048576 in
                   let sha = Sha1.init () in
                   let rec loop = function
                     | 0 -> ()
                     | n -> (
                         let len = Random.int (Cstruct.length buf - 1) in
                         let subbuf = Cstruct.sub buf 0 len in
                         for i = 0 to Cstruct.length subbuf - 1 do
                           Cstruct.set_uint8 subbuf i (Random.int 256)
                         done;
                         let ba = Cstruct.to_bigarray subbuf in
                         Sha1.update_buffer sha ba;
                         match Flow.write flow [ subbuf ] with
                         | exception e -> raise e
                         | () -> loop (n - 1))
                   in
                   loop 10;
                   Sha1.(to_hex @@ finalize sha))
              in
               let received_digest = Stream.take received in
               if received_digest <> sent_digest then
                 failwith
                   (Printf.sprintf "received digest (%s) <> sent digest (%s)"
                      received_digest sent_digest);
                  )
end

let%test_module "Sockets.Stream.Unix" =
  (module struct
    module Tests = TestServer (Sockets.Stream.Unix)

    let%test_unit "one connection" = (* TODO: Eio_mock needed for these *) ()
    let%test_unit "stream data" = (* TODO: Eio_mock needed for these *) ()
  end)

let%test_module "Sockets.Stream.TCP" =
  (module struct
    module Tests = TestServer (Sockets.Stream.Tcp)

    let%test_unit "one connection" = (* TODO: Eio_mock needed for these *) ()
    let%test_unit "stream data" = (* TODO: Eio_mock needed for these *) ()
  end)

module Files = struct

  let read_file path = Path.load path

  let%test "read a file" =
    let expected = Buffer.create 8192 in
    for i = 0 to 1024 do
      Buffer.add_int64_be expected (Int64.of_int i)
    done;
    let filename = Filename.temp_file "vpnkit" "file" in
    let oc = open_out_bin filename in
    output_string oc (Buffer.contents expected);
    close_out oc;
    let result = read_file filename in
    Sys.remove filename;
    Buffer.contents expected = actual

  type watch = { h : [ `FS_event ] Luv.Handle.t }

  let unwatch w =
    match Luv.FS_event.stop w.h with
    | Error err -> failwith @@ Luv.Error.strerror err
    | Ok () -> ()

  let watch_file (path : Eio.Fs.dir Eio.Path.t) callback =
    match Luv.FS_event.init () with
    | Error _ -> Error (`Msg "watch file failed")
    | Ok h ->
    let _ = Eio_luv.Low_level.File.Events.next h (snd path) in
    callback ();
    Ok ({ h })
    (* Luv_lwt.in_luv (fun return ->
        match Luv.FS_event.init () with
        | Error err -> return (Error (`Msg (Luv.Error.strerror err)))
        | Ok h ->
            Luv.FS_event.start h path (function
              | Ok _ | Error `ENOENT -> Luv_lwt.in_lwt_async callback
              | Error err ->
                  Log.warn (fun f ->
                      f "watching %s: %s" path (Luv.Error.err_name err)));
            (* Guarantee to trigger the callback at least once, otherwise the client has to duplicate code *)
            Luv_lwt.in_lwt_async callback;
            return (Ok { h })) *)

  let%test "watch a file" =
    let filename = Filename.temp_file "vpnkit" "file" in
    let oc = open_out_bin filename in
    Luv_lwt.run
      (let m = Lwt_mvar.create () in
       watch_file filename (fun () -> Lwt.async (fun () -> Lwt_mvar.put m ()))
       >>= function
       | Error (`Msg m) ->
           close_out oc;
           Sys.remove filename;
           failwith m
       | Ok w ->
           output_string oc "one";
           flush oc;
           Lwt_mvar.take m >>= fun () ->
           output_string oc "two";
           flush oc;
           Lwt_mvar.take m >>= fun () ->
           close_out oc;
           Sys.remove filename;
           unwatch w >>= fun () -> Lwt.return true)
end

module Dns = struct
  let getaddrinfo net node _family =
    let res = Net.getaddrinfo net node in
      List.fold_left
        (fun acc (addr_info : Net.Sockaddr.t) ->
          match addr_info with
          | `Tcp (ip, _port) | `Udp (ip, _port) -> (
              match Ipaddr.of_string (Eio_unix.Ipaddr.to_unix ip |> Unix.string_of_inet_addr) with
              | Error (`Msg m) -> (
                  Log.err (fun f ->
                      f
                        "getaddrinfo %s returned invalid IP %a: \
                        %s"
                        node Net.Ipaddr.pp ip m);
                  acc
              )
              | Ok ip -> ip :: acc
            )
          | _ -> acc
        ) [] res

  let localhost_local = Dns.Name.of_string "localhost.local"

  let resolve_getaddrinfo net question =
    let open Dns.Packet in
    let qname, ips =
      match question with
      | { q_class = Q_IN; q_name; _ } when q_name = localhost_local ->
          Log.debug (fun f -> f "DNS lookup of localhost.local: return NXDomain");
          q_name, []
      | { q_class = Q_IN; q_type = Q_A; q_name; _ } ->
          let ips = getaddrinfo net (Dns.Name.to_string q_name) `INET in
          q_name, ips
      | { q_class = Q_IN; q_type = Q_AAAA; q_name; _ } ->
          let ips = getaddrinfo net (Dns.Name.to_string q_name) `INET6 in
          q_name, ips
      | _ -> Dns.Name.of_string "", []
    in
    match qname, ips with
    | _, [] -> []
    | q_name, ips ->
        let answers =
          List.map
            (function
              | Ipaddr.V4 v4 ->
                  {
                    name = q_name;
                    cls = RR_IN;
                    flush = false;
                    ttl = 0l;
                    rdata = A v4;
                  }
              | Ipaddr.V6 v6 ->
                  {
                    name = q_name;
                    cls = RR_IN;
                    flush = false;
                    ttl = 0l;
                    rdata = AAAA v6;
                  })
            ips
        in
        answers

  let resolve = resolve_getaddrinfo
end

let compact () =
  let start = Unix.gettimeofday () in
  Gc.compact ();
  let stats = Gc.stat () in
  let time = Unix.gettimeofday () -. start in

  Log.info (fun f ->
      f
        "Gc.compact took %.1f seconds. Heap has heap_words=%d live_words=%d \
         free_words=%d top_heap_words=%d stack_size=%d"
        time stats.Gc.heap_words stats.Gc.live_words stats.Gc.free_words
        stats.Gc.top_heap_words stats.Gc.stack_size)

let start_background_gc clock config =
  match config with
  | None -> Log.info (fun f -> f "No periodic Gc.compact enabled")
  | Some s ->
      let s = float_of_int s in
      let rec with_timeout v =
        Time.sleep clock v;
        compact ();
        with_timeout s
      in
      with_timeout 5.
