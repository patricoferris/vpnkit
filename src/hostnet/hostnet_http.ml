open Astring
open Eio

let src =
  let src = Logs.Src.create "http" ~doc:"HTTP proxy" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let errorf fmt = Fmt.kstr (fun e -> Error (`Msg e)) fmt

module Match = struct

  module One = struct
    module Element = struct
      (* One element of a DNS name *)
      type t = Any | String of string

      let of_string = function
      | "*" | "" -> Any
      | x -> String x

      let to_string = function
      | Any -> "*"
      | String x -> x

      let matches x = function
      | Any -> true
      | String y -> x = y
    end

    type t =
      | Subdomain of Element.t list
      | CIDR of Ipaddr.V4.Prefix.t
      | IP of Ipaddr.V4.t

    let of_string s =
      match Ipaddr.V4.Prefix.of_string s with
      | Error _ ->
        begin match Ipaddr.V4.of_string s with
        | Error _ ->
          let bits = Astring.String.cuts ~sep:"." s in
          Subdomain (List.map Element.of_string bits)
        | Ok ip -> IP ip
        end
      | Ok prefix -> CIDR prefix

    let to_string = function
    | Subdomain x ->
      "Subdomain " ^ String.concat ~sep:"." @@ List.map Element.to_string x
    | CIDR prefix -> "CIDR " ^ Ipaddr.V4.Prefix.to_string prefix
    | IP ip -> "IP " ^ Ipaddr.V4.to_string ip

    let matches_ip ip = function
    | CIDR prefix -> Ipaddr.V4.Prefix.mem ip prefix
    | IP ip' -> Ipaddr.V4.compare ip ip' = 0
    | _ -> false

    let matches_host host = function
    | CIDR _ | IP _ -> false
    | Subdomain domains ->
      let bits = Astring.String.cuts ~sep:"." host in
      (* does 'bits' match 'domains' *)
      let rec loop bits domains = match bits, domains with
      | _, [] -> true
      | [], _ :: _ -> false
      | b :: bs, d :: ds -> Element.matches b d && loop bs ds in
      loop (List.rev bits) (List.rev domains)

    let matches thing exclude =
      match Ipaddr.V4.of_string thing with
      | Error _ -> matches_host thing exclude
      | Ok ip -> matches_ip ip exclude
  end

  type t = One.t list

  let none = []

  let of_string s =
    let open Astring in
    (* Accept either space or comma-separated ignoring whitespace *)
    let parts =
      String.fields ~empty:false
        ~is_sep:(fun c -> c = ',' || Char.Ascii.is_white c) s
    in
    List.map One.of_string parts

  let to_string t = String.concat ~sep:" " @@ (List.map One.to_string t)

  let matches thing t =
    List.fold_left (||) false (List.map (One.matches thing) t)

end

module Make
    (Ip: Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t)
    (Udp: Tcpip.Udp.S with type ipaddr = Ipaddr.V4.t)
    (Tcp: Tcpip.Tcp.S with type ipaddr = Ipaddr.V4.t)
    (Remote: Sig.FLOW_CLIENT with type address = Ipaddr.t * int)
    (Dns_resolver: Sig.DNS)
= struct

  type proxy = Uri.t

  let string_of_proxy = Uri.to_string

  (* Support both http://user:pass@host:port/ and host:port *)
  let proxy_of_string x =
    (* Is it a URL? *)
    let uri = Uri.of_string x in
    match Uri.host uri, Uri.port uri with
    | Some _, Some _ -> Some uri
    | _, _ ->
      begin match String.cuts ~sep:":" x with
      | [] ->
        Log.err (fun f -> f "Failed to parse HTTP(S) proxy as URI or host:port: %s" x);
        None
      | [host; port] ->
        begin
          try
            let port = int_of_string port in
            Some (Uri.make ~scheme:"http" ~host ~port ())
          with Failure _ ->
            Log.err (fun f -> f "Failed to parse HTTP(S) proxy as URI or host:port: %s" x);
            None
        end
      | _ ->
        Log.err (fun f -> f "Failed to parse HTTP(S) proxy as URI or host:port: %s" x);
        None
      end

  let string_of_address (ip, port) = Fmt.str "%s:%d" (Ipaddr.to_string ip) port

  type t = {
    http: proxy option;
    https: proxy option;
    exclude: Match.t;
    transparent_http_ports: int list;
    transparent_https_ports: int list;
    allow_enabled: bool;
    allow: Match.t;
    allow_error_msg: string;
  }

  let resolve_ip ~net name_or_ip =
    match Ipaddr.of_string name_or_ip with
    | Error _ ->
      let open Dns.Packet in
      let question =
        make_question ~q_class:Q_IN Q_A (Dns.Name.of_string name_or_ip)
      in
      let rrs = Dns_resolver.resolve net question in
      (* Any IN record will do (NB it might be a CNAME) *)
      let rec find_ip = function
        | { cls = RR_IN; rdata = A ipv4; _ } :: _ -> Ok (Ipaddr.V4 ipv4)
        | _ :: rest -> find_ip rest
        | [] -> errorf "Failed to lookup host: %s" name_or_ip in
      find_ip rrs
    | Ok x ->Ok x

  let to_json t =
    let open Ezjsonm in
    let http = match t.http with
    | None   -> []
    | Some x -> [ "http",  string @@ string_of_proxy x ]
    in
    let https = match t.https with
    | None   -> []
    | Some x -> [ "https", string @@ string_of_proxy x ]
    in
    let exclude = [ "exclude", string @@ Match.to_string t.exclude ] in
    let transparent_http_ports = [ "transparent_http_ports", list int t.transparent_http_ports ] in
    let transparent_https_ports = [ "transparent_https_ports", list int t.transparent_https_ports ] in
    let allow_enabled = [ "allow_enabled", bool t.allow_enabled ] in
    let allow = [ "allow", list string @@ List.map Match.One.to_string t.allow ] in
    let allow_error_msg = [ "allow_error_msg", string t.allow_error_msg ] in
    dict (http @ https @ exclude @ transparent_http_ports @ transparent_https_ports @ allow_enabled @ allow @ allow_error_msg)

  let default_error_msg = "Connections to %s are forbidden by policy. Please contact your IT administrator."

  let of_json j =
    try
      let open Ezjsonm in
      let http =
        try Some (get_string @@ find j [ "http" ])
        with Not_found -> None
      in
      let https =
        try Some (get_string @@ find j [ "https" ])
        with Not_found -> None
      in
      let exclude =
        try Match.of_string @@ get_string @@ find j [ "exclude" ]
        with Not_found -> Match.none
      in
      let transparent_http_ports =
        try get_list get_int @@ find j [ "transparent_http_ports" ]
        with Not_found -> [ 80 ] in
      let transparent_https_ports =
        try get_list get_int @@ find j [ "transparent_https_ports" ]
        with Not_found -> [ 443 ] in
      let allow_enabled =
        try (get_bool @@ find j [ "allow_enabled" ])
        with Not_found -> false
      in
      let allow =
        try List.map Match.One.of_string @@ get_list get_string @@ find j [ "allow" ]
        with Not_found -> [] in
      let allow_error_msg =
        try get_string @@ find j [ "allow_error_msg" ]
        with Not_found -> default_error_msg in
      let http = match http with None -> None | Some x -> proxy_of_string x in
      let https = match https with None -> None | Some x -> proxy_of_string x in
      Ok { http; https; exclude; transparent_http_ports; transparent_https_ports; allow_enabled; allow; allow_error_msg }
    with e ->
      Error (`Msg (Printf.sprintf "parsing json: %s" (Printexc.to_string e)))

  let to_string t = Ezjsonm.to_string ~minify:true @@ to_json t

  let create ?http ?https ?exclude ?(transparent_http_ports=[ 80 ]) ?(transparent_https_ports=[ 443 ]) ?(allow_enabled=false) ?(allow=[]) ?(allow_error_msg = default_error_msg) () =
    let http = match http with None -> None | Some x -> proxy_of_string x in
    let https = match https with None -> None | Some x -> proxy_of_string x in
    let exclude = match exclude with None -> [] | Some x -> Match.of_string x in
    let allow = List.map Match.One.of_string allow in
    let t = { http; https; exclude; transparent_http_ports; transparent_https_ports; allow_enabled; allow; allow_error_msg } in
    Log.info (fun f -> f "HTTP proxy settings changed to: %s" (to_string t));
    Ok t

  module Incoming = struct
    module Request = struct
      include Cohttp_eio.Body
      include Cohttp_eio.Server
      include Http.Request
    end
    module Response = struct
      include Cohttp_eio.Body
      include Cohttp_eio.Server
      include Http.Response
    end
  end
  module Outgoing = struct
    module Request = struct
      include Cohttp_eio.Body
      include Cohttp_eio.Server
      include Http.Request
    end
    module Response = struct
      include Cohttp_eio.Body
      include Cohttp_eio.Server
      include Http.Response
    end
  end

  (* Since we've already layered a channel on top, we can't use the Mirage_flow.proxy
     since it would miss the contents already buffered. Therefore we write out own
     channel-level proxy here: *)
  let proxy_bytes ~incoming ~outgoing ~flow ~remote =
    (* forward outgoing to ingoing *)
    (* TODO: Is this the right semantics? *)
    let a_t flow ~incoming ~outgoing () =
      let rec loop () =
        let continue =
          try
              Flow.copy outgoing incoming;
              true
          with e ->
              Log.warn (fun f -> f "a_t: caught unexpected exception: %s" (Printexc.to_string e));
              false
        in
        if continue then loop () else Flow.close flow
      in
      loop () in

    (* forward ingoing to outgoing *)
    let b_t remote ~incoming ~outgoing () =
      let warn pp e =
        Log.warn (fun f -> f "Unexpected exeption %a in proxy" pp e);
      in
      let rec loop () =
        let continue =
          try
            Flow.copy incoming outgoing;
            true
          with e ->
            Log.warn (fun f -> f "b_t: caught unexpected exception: %s" (Printexc.to_string e));
            false
          in
        if continue then loop () else Flow.shutdown remote `Send
      in
      loop () in
    Eio.Fiber.all [
      a_t flow ~incoming ~outgoing;
      b_t remote ~incoming ~outgoing
    ]

  let rec proxy_body_request_exn ~reader:(req, reader) =
    let open Incoming.Request in
    let body_writer handle_chunk =
      let _ : Http.Header.t option = Incoming.Request.read_chunked req reader handle_chunk in
      ()
    in
    Cohttp_eio.Body.{ body_writer; trailer_writer = (fun _ -> ())}

  let rec proxy_body_response_exn ~reader:(req, reader) =
    let open Incoming.Request in
    let body_writer handle_chunk = let _ = Outgoing.Response.read_chunked req reader handle_chunk in () in
      Cohttp_eio.Body.{ body_writer; trailer_writer = (fun _ -> ())}

  (* Take a request and a pair (incoming, outgoing) of channels, send
     the request to the outgoing channel and then proxy back any response.
     This function can raise exceptions because Cohttp can raise exceptions. *)
  let proxy_request ~description ~incoming ~outgoing ~flow ~remote ~req:(req, req_body) =
    (* Cohttp can fail promises so we catch them here *)
    try
        (* let reader = Eio.Buf_read.of_buffer (Cstruct.create 1024).buffer in *)
        (* let reader = Incoming.Request.make_body_reader req incoming in *)
        Log.info (fun f -> f "Outgoing.Request.write");
        let outgoing_read_buf = Eio.Buf_read.of_flow ~max_size:max_int outgoing in
        Eio.Buf_write.with_flow flow @@ fun w ->
        Cohttp_eio.Client.write_request false req w (
            match Incoming.Request.has_body req with
            | `Yes     -> Cohttp_eio.Body.Chunked (proxy_body_request_exn ~reader:(req, req_body))
            | `No      -> Cohttp_eio.Body.Empty
            | `Unknown ->
              Log.warn (fun f ->
                  f "Request.has_body returned `Unknown: not sure what \
                      to do");
              Cohttp_eio.Body.Empty
          );
        Log.info (fun f -> f "Outgoing.Response.read");

        let res = Cohttp_eio.Client.response outgoing_read_buf in
        match res, outgoing_read_buf with
        | exception End_of_file ->
          Log.warn (fun f -> f "%s: EOF" (description false));
          false
        | exception e ->
          Log.warn (fun f ->
              f "%s: Failed to parse HTTP response: %s"
                (description false) (Printexc.to_string e));
          false
        | res, body ->
          Log.info (fun f ->
              f "%s: %s %s"
                (description false)
                (Http.Version.to_string (Http.Response.version res))
                (Http.Status.to_string (Http.Response.status res)));
          Log.debug (fun f ->
              f "%a" Http.Response.pp res);
          let res_headers = Http.Response.headers res in
          let connection_close =
            (* HTTP 1.0 defaults to Connection: close *)
            match Http.Response.version res, Http.Header.get res_headers "connection" with
            | _, Some "keep-alive" -> false
            | _, Some "close" -> true
            | `HTTP_1_0, _ -> true
            | _, _ -> false in
          match Http.Request.meth req, Http.Response.status res with
          | `CONNECT, `OK ->
            (* Write the response and then switch to proxying the bytes *)
            (Eio.Buf_write.with_flow incoming @@ fun w -> Cohttp_eio.Server.write_response w (res, Cohttp_eio.Body.Empty));
            (* Incoming.Response.write ~flush:true (fun _writer -> Lwt.return_unit) res incoming; *)
            proxy_bytes ~incoming ~outgoing ~flow ~remote;
            Log.debug (fun f -> f "%s: HTTP CONNECT complete" (description false));
            false
          | _, _ ->
            (* Otherwise stay in HTTP mode *)
            Eio.Buf_write.with_flow incoming @@ fun w ->
            Cohttp_eio.Server.write_response w (res,
                match Http.Request.meth req, Buf_read.at_end_of_input body with
                | `HEAD, true ->
                  (* Bug in cohttp.1.0.2: according to Section 9.4 of RFC2616
                    https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
                    > The HEAD method is identical to GET except that the server
                    > MUST NOT return a message-body in the response.
                  *)
                  Log.debug (fun f -> f "%s: HEAD requests MUST NOT have response bodies" (description false));
                  Cohttp_eio.Body.Empty
                | _, true     ->
                  Log.info (fun f -> f "%s: proxying body" (description false));
                  Cohttp_eio.Body.Chunked (proxy_body_response_exn ~reader:(req, body))
                | _, false      ->
                  Log.info (fun f -> f "%s: no body to proxy" (description false));
                  Cohttp_eio.Body.Empty
                (* | _, `Unknown when connection_close ->
                  (* There may be a body between here and the EOF *)
                  Log.info (fun f -> f "%s: proxying until EOF" (description false));
                  Cohttp_eio.Body.Chunked (proxy_body_response_exn ~reader)
                | _, `Unknown ->
                  Log.warn (fun f ->
                      f "Response.has_body returned `Unknown: not sure \
                          what to do");
                  Cohttp_eio.Body.Empty *)
              );
            not connection_close
        with e ->
        Log.warn (fun f -> f "proxy_request caught exception: %s" (Printexc.to_string e));
        false

  let add_proxy_authorization proxy headers =
    let proxy_authorization = "Proxy-Authorization" in
    let headers = Http.Header.remove headers proxy_authorization in
    match Uri.userinfo proxy with
      | None -> headers
      | Some s -> Http.Header.add headers proxy_authorization ("Basic " ^ (Base64.encode_exn s))

  let address_of_proxy ~net ~localhost_names ~localhost_ips proxy =
    match Uri.host proxy, Uri.port proxy with
    | None, _ ->
      Error (`Msg ("HTTP proxy URI does not include a hostname: " ^ (Uri.to_string proxy)))
    | _, None ->
      Error (`Msg ("HTTP proxy URI does not include a port: " ^ (Uri.to_string proxy)))
    | Some host, Some port ->
      let host =
        if List.mem (Dns.Name.of_string host) localhost_names
        then "localhost"
        else host in
      resolve_ip ~net host
      |> function
      | Error e -> Error e
      | Ok ip ->
        let ip =
          if List.mem ip localhost_ips
          then Ipaddr.(V4 V4.localhost)
          else ip in
        Ok (ip, port)

  let send_error status incoming description =
    let header = "HTTP/1.1 " ^ status ^ " " ^ description ^ "\r\nConnection: closed\r\n\r\n" in
    let body = {|
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title> |} ^ description ^ {| </title>
  </head>
  <body>
    <h1>|} ^ description ^ {|</h1>
    <p>
      Please check:
    </p>
    <ul>
      <li> if your Internet connection is working </li>
      <li> your HTTP proxy setting</li>
    </ul>
    <p>
    This message comes from the HTTP proxy in <a href=\"https://github.com/moby/vpnkit\">moby/vpnkit</a>.
  </p>
  </body>
</html>
    |} in
    let response = header ^ body in
    Eio.Buf_write.with_flow incoming @@ fun w ->
    Eio.Buf_write.string w response ~off:0 ~len:(String.length response);
    Eio.Buf_write.flush w

  let tunnel_https_over_connect ~sw ~net ~localhost_names ~localhost_ips ~dst proxy =
    let listeners _port =
      Log.debug (fun f -> f "HTTPS TCP handshake complete");
      let process flow =
        try
            Fun.protect
              (fun () ->
                match address_of_proxy ~net ~localhost_names ~localhost_ips proxy with
                | Error (`Msg m) ->
                  Log.warn (fun f -> f "HTTP proxy: cannot forward to %s: %s" (Uri.to_string proxy) m)
                | Ok ((ip, port) as address) ->
                  let host = Ipaddr.V4.to_string dst in
                  let description outgoing =
                    Fmt.str "%s:443 %s %s:%d" host
                      (if outgoing then "-->" else "<--") (Ipaddr.to_string ip) port
                  in
                  Log.info (fun f -> f "%s: CONNECT" (description true));
                  let connect =
                    let host = Ipaddr.V4.to_string dst in
                    let port = 443 in
                    let uri = Uri.make ~host ~port () in
                    let headers = add_proxy_authorization proxy (Http.Header.init ()) in
                    let request = Http.Request.make ~meth:`CONNECT ~headers (Uri.to_string uri) in
                    { request with Http.Request.resource = host ^ ":" ^ (string_of_int port) }
                  in
                  match Remote.connect ~sw ~net address with
                  | Error _ ->
                    Log.warn (fun f ->
                        f "Failed to connect to %s" (string_of_address address))
                  | Ok remote ->
                    let outgoing_buf_read = Eio.Buf_read.of_flow ~max_size:max_int remote in
                    Fun.protect  (fun () ->
                        (Eio.Buf_write.with_flow remote @@ fun w -> Cohttp_eio.Client.write_request false connect w Cohttp_eio.Body.Empty);
                        match Cohttp_eio.Client.response outgoing_buf_read with
                        | exception End_of_file ->
                          Log.warn (fun f ->
                              f "EOF from %s" (string_of_address address))
                        | exception x ->
                          Log.warn (fun f ->
                              f "Failed to parse HTTP response on port %s: %s"
                                (string_of_address address) (Printexc.to_string x))
                        | res ->
                          Log.info (fun f ->
                              let open Http.Response in
                              f "%s: %s %s"
                                (description false)
                                (Http.Version.to_string res.version)
                                (Http.Status.to_string res.status));
                          Log.debug (fun f ->
                              f "%a" Http.Response.pp res);
                          proxy_bytes ~incoming:flow ~outgoing:remote ~flow ~remote
                      ) ~finally:(fun () -> Flow.close remote)
              ) ~finally:(fun () -> Flow.close flow)
        with e ->
          Log.warn (fun f -> f "tunnel_https_over_connect caught exception: %s" (Printexc.to_string e))
      in Some process
    in
    listeners

  (* A route is a decision about where to send an HTTP request. It depends on
     - whether a proxy is configured or not
     - the URI or the Host: header in the request
     - whether the request matches the proxy excludes or not *)
  type route = {
    next_hop_address: (Ipaddr.t * int);
    host: string;
    port: int;
    description: bool -> string;
    ty: [ `Origin | `Proxy ];
  }

  let get_host req =
    (* A host in the URI takes precedence over a host: header *)
    let uri = Cohttp.Request.uri req in
    match Uri.host uri, Http.Header.get req.Http.Request.headers "host" with
    | None, None ->
      Log.warn (fun f -> f "HTTP request had no host in the URI nor in the host: header: %a"
        Http.Request.pp req);
      Error `Missing_host_header
    | Some host, _
    | None, Some host ->
      (* If the port is missing then it is assumed to be 80 *)
      let port = match Uri.port uri with None -> 80 | Some p -> p in
      Ok (host, port)

  let route ?(localhost_names=[]) ?(localhost_ips=[]) ~net proxy exclude allow_enabled allow req =
    match get_host req with
    | Error x -> Error x
    | Ok (host, port) ->
      Log.debug (fun f -> f "host from request = %s:%d" host port);
      if allow_enabled && not(Match.matches host allow)
      then Error (`Refused host)
      else
      (* A proxy URL must have both a host and a port to be useful *)
      let hostport_from_proxy = match proxy with
        | None -> None
        | Some uri ->
          begin match Uri.host uri, Uri.port uri with
          | Some host, Some port ->
            Log.debug (fun f -> f "upstream proxy is %s:%d" host port);
            Some (host, port)
          | Some host, None ->
            Log.warn (fun f -> f "HTTP proxy %s has no port number" host);
            None
          | _, _ ->
            Log.warn (fun f -> f "HTTP proxy has no host");
            None
          end in
      let hostport_and_ty = match hostport_from_proxy with
        (* No proxy means we must send to the origin server *)
        | None -> Some ((host, port), `Origin)
        (* If a proxy is configured it depends on whether the request matches the excludes *)
        | Some proxy ->
          if Match.matches host exclude
          then Some ((host, port), `Origin)
          else Some (proxy, `Proxy) in
      begin match hostport_and_ty with
      | None ->
        Log.warn (fun f -> f "Failed to route request: %a" Http.Request.pp req);
        Error `Missing_host_header
      | Some ((next_hop_host, next_hop_port), ty) ->
        let next_hop_host =
          if List.mem (Dns.Name.of_string next_hop_host) localhost_names
          then "localhost"
          else next_hop_host in
        Log.debug (fun f -> f "next_hop_address is %s:%d" next_hop_host next_hop_port);
        resolve_ip ~net next_hop_host
        |> function
        | Error (`Msg m) -> Error (`Msg m)
        | Ok next_hop_ip ->
          let next_hop_ip =
            if List.mem next_hop_ip localhost_ips
            then Ipaddr.(V4 V4.localhost)
            else next_hop_ip in
          let description outgoing =
            Printf.sprintf "HTTP proxy %s %s:%d Host:%s:%d (%s)"
              (if outgoing then "-->" else "<--") (Ipaddr.to_string next_hop_ip) next_hop_port host port
              (match ty with `Origin -> "Origin" | `Proxy -> "Proxy") in
          Ok { next_hop_address = (next_hop_ip, next_hop_port); host; port; description; ty }
      end

  let fetch ?localhost_names ?localhost_ips ~net ~flow proxy exclude allow_enabled allow allow_error_msg incoming (req, body) =
    Eio.Switch.run @@ fun sw ->
    let meth = Http.Request.meth req in
    let uri = Cohttp.Request.uri req  in
    match route ?localhost_names ?localhost_ips ~net proxy exclude allow_enabled allow req with
    | Error `Missing_host_header ->
      send_error "400" incoming "request must contain an absolute URI";
      false
    | Error (`Refused host) ->
      send_error "403" incoming (Stringext.replace_all allow_error_msg ~pattern:"%s" ~with_:host);
      false
    | Error (`Msg m) ->
      send_error "503" incoming m;
      false
    | Ok { next_hop_address; host; port; description; ty } ->
      Log.info (fun f ->
          f "%s: %s %s"
            (description true)
            (Http.(Method.to_string meth))
            (Uri.path uri));
      Log.debug (fun f ->
          f "%s: received %a"
            (description false)
            Http.Request.pp req
          );
      begin
        match Remote.connect ~sw ~net next_hop_address with
      | Error _ ->
        let message = match ty with
          | `Origin -> Printf.sprintf "unable to connect to %s. Do you need an HTTP proxy?" (string_of_address next_hop_address)
          | `Proxy -> Printf.sprintf "unable to connect to HTTP proxy %s" (string_of_address next_hop_address) in
        Log.warn (fun f -> f "%s: %s" (description true) message);
        send_error "503" incoming message;
        false
      | Ok remote ->
        Fun.protect (fun () ->
          Log.info (fun f ->
              f "%s: Successfully connected to %s" (description true) (string_of_address next_hop_address));
          (* let outgoing = Outgoing.C.create remote in *)
          match ty, Http.Request.meth req with
          | `Origin, `CONNECT ->
            (* return 200 OK and start a TCP proxy *)
            let response = "HTTP/1.1 200 OK\r\n\r\n" in
            Eio.Buf_write.with_flow incoming (fun w ->
              Eio.Buf_write.string w response ~off:0 ~len:(String.length response);
            );
            proxy_bytes ~incoming ~outgoing:remote ~flow ~remote;
            Log.debug (fun f -> f "%s: HTTP CONNECT complete" (description false));
            false
          | _, _ ->
            (* If the request is to an origin server we should convert back to a relative URI
               and a Host: header.
               If the request is to a proxy then the URI should be absolute and should match
               the Host: header.
               In all cases we should make sure the host header is correct. *)
            let host_and_port = host ^ (match port with 80 -> "" | _ -> ":" ^ (string_of_int port)) in
            let headers = Http.Header.replace req.Http.Request.headers "host" host_and_port in
            (* If the request is to a proxy then we should add a Proxy-Authorization header *)
            let headers = match proxy with
              | None -> headers
              | Some proxy -> add_proxy_authorization proxy headers in
            let resource = match ty, Http.Request.meth req with
              | `Origin, _ -> Uri.path_and_query uri
              | `Proxy, `CONNECT -> host_and_port
              | `Proxy, _ -> Uri.with_scheme (Uri.with_host (Uri.with_port uri (Some port)) (Some host)) (Some "http") |> Uri.to_string in
            let req = { req with Http.Request.headers; resource } in
            Log.debug (fun f -> f "%s: sending %a"
              (description false)
              Http.Request.pp req
            );
            proxy_request ~description ~incoming ~outgoing:remote ~flow ~remote ~req:(req, body)
        )
        ~finally:(fun () -> Flow.close remote)
      end

  (* A regular, non-transparent HTTP proxy implementation.
     If [proxy] is [None] then requests will be sent to origin servers;
     otherwise they will be sent to the upstream proxy. *)
  let explicit_proxy ~net ~localhost_names ~localhost_ips proxy exclude allow_enabled allow allow_error_msg () =
    let listeners _port =
      Log.debug (fun f -> f "HTTP TCP handshake complete");
      let process flow =
        try
            Fun.protect (fun () ->
                let incoming = Eio.Buf_read.of_flow ~max_size:max_int flow in
                let rec loop () =
                  match Cohttp_eio.Server.read_request incoming with
                  | exception End_of_file -> ()
                  | exception x ->
                    Log.warn (fun f ->
                        f "HTTP proxy failed to parse HTTP request: %s"
                          (Printexc.to_string x));
                  | req ->
                    match fetch ~net ~localhost_names ~localhost_ips ~flow proxy exclude allow_enabled allow allow_error_msg flow (req, incoming) with
                    | true ->
                      (* keep the connection open, read more requests *)
                      loop ()
                    | false ->
                      Log.debug (fun f -> f "HTTP session complete, closing connection")
                  in
                  loop ()
              ) ~finally:(fun () -> Flow.close flow)
      with e ->
        Log.warn (fun f -> f "explicit_proxy caught exception: %s" (Printexc.to_string e))
      in
      Some process
    in
    listeners

  let transparent_http ~net ~dst ~localhost_names ~localhost_ips proxy exclude allow_enabled allow allow_error_msg =
    let listeners _port =
      Log.debug (fun f -> f "HTTP TCP handshake complete");
      let process flow =
        try
            Fun.protect (fun () ->
              let incoming = Eio.Buf_read.of_flow ~max_size:max_int flow in
              let rec loop () =
                match Cohttp_eio.Server.read_request incoming with
                | exception End_of_file -> ()
                | exception x ->
                  Log.warn (fun f ->
                      f "Failed to parse HTTP request on port %a:80: %s"
                        Ipaddr.V4.pp dst (Printexc.to_string x))
                | req ->
                  (* If there is no Host: header or host in the URI then add a
                    Host: header with the destination IP address -- this is not perfect
                    but better than nothing and the majority of people will supply a Host:
                    header these days because otherwise virtual hosts don't work *)
                  let req =
                    match get_host req with
                    | Error `Missing_host_header ->
                      { req with Cohttp.Request.headers = Cohttp.Header.replace req.headers "host" (Ipaddr.V4.to_string dst) }
                    | Ok _ -> req in
                  match fetch ~net ~localhost_names ~localhost_ips ~flow (Some proxy) exclude allow_enabled allow allow_error_msg flow (req, incoming) with
                  | true ->
                    (* keep the connection open, read more requests *)
                    loop ()
                  | false ->
                    Log.debug (fun f -> f "HTTP session complete, closing connection")
                  in
                loop ()
              )
              ~finally:(fun () -> Flow.close flow)
    with e ->
      Log.warn (fun f -> f "transparent_http caught exception: %s" (Printexc.to_string e))
      in Some process
    in
    listeners

  let transparent_proxy_handler ~sw ~net ~localhost_names ~localhost_ips ~dst:(ip, port) ~t =
    match t.http, t.https with
    | Some proxy, _ when List.mem port t.transparent_http_ports -> Some (transparent_http ~net ~dst:ip ~localhost_names ~localhost_ips proxy t.exclude t.allow_enabled t.allow t.allow_error_msg)
    | _, Some proxy when List.mem port t.transparent_https_ports ->
      if Match.matches (Ipaddr.V4.to_string ip) t.exclude
      then None
      else Some (tunnel_https_over_connect ~sw ~net ~localhost_names ~localhost_ips ~dst:ip proxy)
    | _, _ -> None

  let explicit_proxy_handler ~sw:_ ~net ~localhost_names ~localhost_ips ~dst:(_, port) ~t =
    match port, t.http, t.https with
    | 3128, proxy, _
    | 3129, _, proxy -> Some (explicit_proxy ~net ~localhost_names ~localhost_ips proxy t.exclude t.allow_enabled t.allow t.allow_error_msg ())
    (* For other ports, refuse the connection *)
    | _, _, _ -> None
end
