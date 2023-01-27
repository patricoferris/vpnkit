open Eio

let src =
  let src =
    Logs.Src.create "port forward" ~doc:"forward local ports to the VM"
  in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let log_exception_continue description f =
  try f () with e -> Log.warn (fun f -> f "%s: caught %a" description Fmt.exn e)

let allowed_addresses = ref None

let set_allowed_addresses ips =
  Log.info (fun f -> f "allowing binds to %s" (match ips with
    | None     -> "any IP addresses"
    | Some ips -> String.concat ", " (List.map Ipaddr.to_string ips)
    ));
  allowed_addresses := ips

let errorf fmt = Fmt.kstr (fun e -> Error (`Msg e)) fmt
let errorf' fmt = Fmt.kstr (fun e -> Error (`Msg e)) fmt

module Port = struct
  type t = Forwarder.Frame.Destination.t

  let to_string = function
    | `Tcp (ip, port) ->
      Fmt.str "tcp:%a:%d" Ipaddr.pp ip port
    | `Udp (ip, port) ->
      Fmt.str "udp:%a:%d" Ipaddr.pp ip port
    | `Unix path ->
      Fmt.str "unix:%s" (Base64.encode_exn path)

  let of_string x =
    try
      match Stringext.split ~on:':' x with
      | [ proto; ip; port ] ->
        let port = int_of_string port in
        let ip = Ipaddr.of_string_exn ip in
        begin match String.lowercase_ascii proto with
        | "tcp" -> Ok (`Tcp(ip, port))
        | "udp" -> Ok (`Udp(ip, port))
        | _ -> errorf "unknown protocol: should be tcp or udp"
        end
      | [ "unix"; path ] -> Ok (`Unix (Base64.decode_exn path))
      | _ -> errorf "port should be of the form proto:IP:port or unix:path"
    with
    | _ -> errorf "port is not a proto:IP:port or unix:path: '%s'" x

end

module Make
    (Connector: Sig.Connector)
    (Socket: Sig.SOCKETS) =
struct

  type server = [
    | `Tcp of Socket.Stream.Tcp.server
    | `Udp of Socket.Datagram.Udp.server
    | `Unix of Socket.Stream.Unix.server
  ]

  type t = {
    mutable local: Port.t;
    remote_port: Port.t;
    mutable server: server option;
  }

  type key = Port.t

  let get_key t = t.local

  let to_string t =
    Fmt.str "%s:%s" (Port.to_string t.local) (Port.to_string t.remote_port)

  let description_of_format =
    "tcp:<local IP>:<local port>:tcp:<remote IP>:<remote port>
udp:<local IP>:<local port>:udp:<remote IP>:<remote port>
unix:<base64-encoded local path>:unix:<base64-encoded remote path>"

  let check_bind_allowed ip = match !allowed_addresses with
  | None -> () (* no restriction *)
  | Some ips ->
    let match_ip allowed_ip =
      let exact_match = Ipaddr.compare allowed_ip ip = 0 in
      let wildcard = match ip, allowed_ip with
      | Ipaddr.V4 _, Ipaddr.V4 x when x = Ipaddr.V4.any -> true
      | _, _ -> false
      in
      exact_match || wildcard
    in
    if List.fold_left (||) false (List.map match_ip ips)
    then ()
    else raise (Unix.Unix_error(Unix.EPERM, "bind", ""))

  module Mux = Forwarder.Multiplexer

  (* Since we only need one connection to the port forwarding service,
     connect on demand and cache it. *)
  let get_mux ~sw =
    let mux = ref None in
    let m = Eio.Mutex.create () in
    fun () ->
      Eio.Mutex.use_rw ~protect:false m
        (fun () ->
          (* If there is a multiplexer but it is broken, reconnect *)
          begin match !mux with
          | None -> ()
          | Some m ->
            if not(Mux.is_running m) then begin
              Log.err (fun f -> f "Multiplexer has shutdown, reconnecting");
              mux := None;
              Mux.disconnect m
            end else ()
          end;
          match !mux with
          | None ->
            let remote = Connector.connect () in
            let mux' = Mux.connect ~sw remote "port-forwarding"
              (fun flow destination ->
                Log.err (fun f -> f "Unexpected connection from %s via port multiplexer" (Forwarder.Frame.Destination.to_string destination));
                Mux.Channel.close flow
              ) in
            mux := Some mux';
            mux'
          | Some m -> m
        )

  let open_channel ~sw destination =
    let mux = get_mux ~sw () in
    let c = Mux.Channel.connect mux destination in
    Eio.Switch.on_release sw (fun () -> Mux.Channel.close c);
    c

  let start_tcp_proxy ~sw ~net ~mono description remote_port server =
    let module Proxy = Mirage_flow_combinators.Proxy in
    Socket.Stream.Tcp.listen ~sw net server (fun local ->
        Eio.Switch.run @@ fun sw ->
        let remote = open_channel ~sw remote_port in
        Log.debug (fun f -> f "%s: connected" description);
        match Proxy.proxy ~mono (Mux.Channel.to_flow remote) (local :> <Eio.Flow.two_way; read : Cstruct.t>) with
        | Error e ->
          Log.err (fun f ->
              f "%s proxy failed with %a" description Proxy.pp_error e)
        | Ok (l_stats, r_stats) ->
          Log.debug (fun f ->
              f "%s completed: l2r = %a; r2l = %a" description
                Mirage_flow.pp_stats l_stats
                Mirage_flow.pp_stats r_stats
            )
      )

  let start_unix_proxy ~sw ~net ~mono description remote_port server =
    let module Proxy = Mirage_flow_combinators.Proxy in
    Socket.Stream.Unix.listen ~sw net server (fun local ->
        Switch.run @@ fun sw ->
        let remote = open_channel ~sw remote_port in
        Log.debug (fun f -> f "%s: connected" description);
        match Proxy.proxy ~mono (Mux.Channel.to_flow remote) (local :> <Flow.two_way; read : Cstruct.t>) with
        | Error e ->
          Log.err (fun f ->
              f "%s proxy failed with %a" description Proxy.pp_error e)
        | Ok (l_stats, r_stats) ->
          Log.debug (fun f ->
              f "%s completed: l2r = %a; r2l = %a" description
                Mirage_flow.pp_stats l_stats
                Mirage_flow.pp_stats r_stats
            )
      )

  let conn_read flow buf =
    match Mux.Channel.read_into flow buf with
    | Ok `Eof       -> raise End_of_file
    | Error e       -> Fmt.kstr failwith "%a" Mux.Channel.pp_error e
    | Ok (`Data ()) -> ()

  let conn_write flow buf =
    match Mux.Channel.write flow buf with
    | Error `Closed -> raise End_of_file
    | Error e       -> Fmt.kstr failwith "%a" Mux.Channel.pp_write_error e
    | Ok ()         -> ()

  let start_udp_proxy ~sw description remote_port server =
    let from_internet_buffer = Cstruct.create Constants.max_udp_length in
    (* We write to the internet using the from_vsock_buffer *)
    let from_vsock_buffer =
      Cstruct.create (Constants.max_udp_length + Forwarder.Frame.Udp.max_sizeof)
    in
    let handle fd =
      (* Construct the vsock header in a separate buffer but write the payload
         directly from the from_internet_buffer *)
      let write_header_buffer = Cstruct.create Forwarder.Frame.Udp.max_sizeof in
      let write v buf (ip, port) =
        let udp = Forwarder.Frame.Udp.({
            ip; port;
            payload_length = Cstruct.length buf;
        }) in
        let header = Forwarder.Frame.Udp.write_header udp write_header_buffer in
        conn_write v header;
        conn_write v buf
      in
      (* Read the vsock header and payload into the same buffer, and write it
         to the internet from there. *)
      let read v =
        conn_read v (Cstruct.sub from_vsock_buffer 0 2);
        let frame_length = Cstruct.LE.get_uint16 from_vsock_buffer 0 in
        if frame_length > (Cstruct.length from_vsock_buffer) then begin
          Log.err (fun f ->
              f "UDP encapsulated frame length is %d but buffer has length %d: \
                 dropping" frame_length (Cstruct.length from_vsock_buffer));
          None
        end else begin
          let rest = Cstruct.sub from_vsock_buffer 2 (frame_length - 2) in
          conn_read v rest;
          let udp, payload = Forwarder.Frame.Udp.read from_vsock_buffer in
          Some (payload, (udp.Forwarder.Frame.Udp.ip, udp.Forwarder.Frame.Udp.port))
        end
      in
      let rec from_internet v =
        let res =
          try
              let len, address = Socket.Datagram.Udp.recvfrom fd from_internet_buffer in
              write v (Cstruct.sub from_internet_buffer 0 len) address;
              true
          with
            | Unix.Unix_error(Unix.EBADF, _, _) -> false
            | e ->
              Log.err (fun f ->
                  f "%s: shutting down recvfrom thread: %a" description Fmt.exn e);
              false
        in
        match res with
        | true -> from_internet v
        | false -> ()
      in
      let rec from_vsock v =
        let res =
          try
            match read v with
            | None                -> false
            | Some (buf, address) ->
              Socket.Datagram.Udp.sendto fd address buf;
              true
          with e ->
            Log.debug (fun f ->
                f "%s: shutting down from vsock thread: %a"
                  description Fmt.exn e);
            false
        in
        match res with
        | true -> from_vsock v
        | false -> ()
      in
      Log.debug (fun f ->
          f "%s: connecting to vsock port %s" description
            (Port.to_string remote_port));
      Eio.Switch.run @@ fun sw ->
      let remote = open_channel ~sw remote_port in
      Log.debug (fun f ->
          f "%s: connected to vsock port %s" description
            (Port.to_string remote_port));
      (* FIXME(samoht): why ignoring that thread here? *)
      let _ = from_vsock remote in
      from_internet remote
    in
    Fiber.fork ~sw (fun () ->
        log_exception_continue "udp handle" (fun () -> handle server))

  let start ~sw ~net ~mono t =
    match t.local with
    | `Tcp (local_ip, local_port) -> (
      let description =
        Fmt.str "forwarding from tcp:%a:%d" Ipaddr.pp local_ip local_port
      in
      try
          check_bind_allowed local_ip;
          let server = Socket.Stream.Tcp.bind ~sw net ~description (local_ip, local_port) in
          t.server <- Some (`Tcp server);
          (* Resolve the local port yet (the fds are already bound) *)
          let _, bound_port = Socket.Stream.Tcp.getsockname server in
          t.local <- ( match t.local with
            | `Tcp (ip, 0) -> `Tcp (ip, bound_port)
            | _ -> t.local );
          start_tcp_proxy ~sw ~net ~mono (to_string t) t.remote_port server;
          Ok t
      with
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) ->
          errorf' "Bind for %a:%d failed: port is already allocated"
            Ipaddr.pp local_ip local_port
        | Unix.Unix_error(Unix.EADDRNOTAVAIL, _, _) ->
          errorf' "listen tcp %a:%d: bind: cannot assign requested address"
            Ipaddr.pp local_ip local_port
        | Unix.Unix_error(Unix.EPERM, _, _) ->
          errorf' "Bind for %a:%d failed: permission denied"
            Ipaddr.pp local_ip local_port
        | e ->
          errorf' "Bind for %a:%d: unexpected error %a" Ipaddr.pp local_ip
            local_port Fmt.exn e
        )
    | `Udp (local_ip, local_port) -> (
      let description =
        Fmt.str "forwarding from udp:%a:%d" Ipaddr.pp local_ip local_port
      in
      try
          check_bind_allowed local_ip;
          let server = Socket.Datagram.Udp.bind ~sw net ~description (local_ip, local_port) in
          t.server <- Some (`Udp server);
          (* Resolve the local port yet (the fds are already bound) *)
          let _, bound_port = Socket.Datagram.Udp.getsockname server in
          t.local <- ( match t.local with
            | `Udp (ip, 0) -> `Udp (ip, bound_port)
            | _ -> t.local );
          start_udp_proxy ~sw (to_string t) t.remote_port server;
          Ok t
      with
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) ->
          errorf' "Bind for %a:%d failed: port is already allocated"
            Ipaddr.pp local_ip local_port
        | Unix.Unix_error(Unix.EADDRNOTAVAIL, _, _) ->
          errorf' "listen udp %a:%d: bind: cannot assign requested address"
            Ipaddr.pp local_ip local_port
        | Unix.Unix_error(Unix.EPERM, _, _) ->
          errorf' "Bind for %a:%d failed: permission denied"
            Ipaddr.pp local_ip local_port
        | e ->
          errorf' "Bind for %a:%d: unexpected error %a" Ipaddr.pp local_ip
            local_port Fmt.exn e
        )
    | `Unix path ->
      let description =
        Fmt.str "forwarding from unix:%s" path
      in
      try
          let server = Socket.Stream.Unix.bind ~sw net ~description path in
          t.server <- Some (`Unix server);
          start_unix_proxy ~sw ~net ~mono (to_string t) t.remote_port server;
          Ok t
      with
        | Unix.Unix_error(Unix.EADDRINUSE, _, _) ->
          errorf' "Bind for %s failed: port is already allocated" path
        | Unix.Unix_error(Unix.EADDRNOTAVAIL, _, _) ->
          errorf' "listen %s: bind: cannot assign requested address" path
        | Unix.Unix_error(Unix.EPERM, _, _) ->
          errorf' "Bind for %s failed: permission denied" path
        | e ->
          errorf' "Bind for %s: unexpected error %a" path
            Fmt.exn e

  let stop t =
    Log.debug (fun f -> f "%s: closing listening socket" (to_string t));
    match t.server with
    | Some (`Tcp s) -> Socket.Stream.Tcp.shutdown s
    | Some (`Udp s) -> Socket.Datagram.Udp.shutdown s
    | Some (`Unix s) -> Socket.Stream.Unix.shutdown s
    | None -> ()

  let of_string x =
    match Stringext.split ~on:':' ~max:6 x with
    | [ proto1; ip1; port1; proto2; ip2; port2 ] ->
      begin
        match
          Port.of_string (proto1 ^ ":" ^ ip1 ^ ":" ^ port1),
          Port.of_string (proto2 ^ ":" ^ ip2 ^ ":" ^ port2)
        with
        | Error x, _ -> Error x
        | _, Error x -> Error x
        | Ok local, Ok remote_port ->
          Ok { local; remote_port; server = None }
      end
    | [ "unix"; path1; "unix"; path2 ] ->
      begin
        match
          Port.of_string ("unix:" ^ path1),
          Port.of_string ("unix:" ^ path2)
        with
        | Error x, _ -> Error x
        | _, Error x -> Error x
        | Ok local, Ok remote_port ->
          Ok { local; remote_port; server = None }
      end
    | _ ->
      errorf "Failed to parse request [%s], expected %s" x description_of_format
end
