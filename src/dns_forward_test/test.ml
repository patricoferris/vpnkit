
module Error = Dns_forward.Error.Infix

let fresh_id =
  let next = ref 1000 in
  fun () ->
    let this = !next in
    next := !next mod 0xffff;
    this

let make_a_query name =
  let open Dns.Packet in
  let id = fresh_id () in
  let detail = { qr = Query; opcode = Standard; aa = true; tc = false; rd = true; ra = false; rcode = NoError } in
  let questions = [ make_question Q_A name ] in
  let answers = [] in
  let authorities = [] in
  let additionals = [] in
  let pkt = { id; detail; questions; answers; authorities; additionals } in
  marshal pkt

let parse_response response =
  let pkt = Dns.Packet.parse response in
  match pkt.Dns.Packet.detail with
  | { Dns.Packet.qr = Dns.Packet.Query; _ } ->
      Error (`Msg "parsed a response which was actually a query in disguise")
  | { Dns.Packet.qr = Dns.Packet.Response; _ } ->
      begin match pkt.Dns.Packet.answers with
      | [ { Dns.Packet.rdata = Dns.Packet.A ipv4; _ } ] ->
          Ok ipv4
      | xs -> Error (`Msg (Printf.sprintf "failed to find answers: [ %s ]" (String.concat "; " (List.map Dns.Packet.rr_to_string xs))))
      end

let fresh_port =
  let next = ref 0 in
  fun () ->
    let port = !next in
    incr next;
    port

let with_cancellable_switch fn =
  let exception All_done of (unit, [`Msg of string]) result in
  try
    Eio.Switch.run @@ fun sw ->
    let finish res = Eio.Switch.fail sw (All_done res) in
    fn ~sw finish
  with
    | All_done res -> res
    | exn -> raise exn

let test_server () =
  let open Eio in
  match Eio_main.run begin fun env ->
      Switch.run @@ fun sw ->
      let net = Stdenv.net env in
      let clock = Stdenv.clock env in
      let module S = Server.Make(Rpc) in
      let s = S.make [ "foo", Ipaddr.V4 Ipaddr.V4.localhost; "bar", Ipaddr.of_string_exn "1.2.3.4" ] in
      let open Error in
      (* The virtual address we run our server on: *)
      let port = fresh_port () in
      let address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      S.serve ~sw ~address net s
      >>= fun _ ->
      let expected_dst = ref false in
      let message_cb ?src:_ ?dst:d ~buf:_ () =
        ( match d with
        | Some d ->
            if Dns_forward.Config.Address.compare address d = 0 then expected_dst := true
        | None ->
            ()
        )
      in
      Rpc.connect ~gen_transaction_id:Random.int ~message_cb address
      >>= fun c ->
      let request = make_a_query (Dns.Name.of_string "foo") in
      Rpc.rpc ~sw clock net c request
      >>= fun response ->
      parse_response response
      >>= fun ipv4 ->
      Alcotest.(check string) "IPv4" "127.0.0.1" (Ipaddr.V4.to_string ipv4);
      Rpc.disconnect c;
      if not (!expected_dst) then failwith ("Expected destination address never seen in message_cb");
      Eio.Switch.fail sw Exit;
      Ok ()
    end with
  | Ok () | exception Exit ->
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  | Error (`Msg m) -> failwith m

let test_local_lookups ~net ~mono ~clock () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  match
      Eio.Switch.run @@ fun sw ->
      let module S = Server.Make(Rpc) in
      let foo_public = "8.8.8.8" in
      let foo_private = "192.168.1.1" in
      (* a public server mapping 'foo' to a public ip *)
      let public_server = S.make [ "foo", Ipaddr.of_string_exn foo_public ] in
      let port = fresh_port () in
      let public_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      let open Error in
      S.serve ~sw ~address:public_address net public_server
      >>= fun _ ->
      let module R = Dns_forward.Resolver.Make(Rpc) in
      let open Dns_forward.Config in
      let servers = Server.Set.of_list [
          { Server.address = public_address; zones = Domain.Set.empty; timeout_ms = None; order = 0 };
        ] in
      let config = { servers; search = []; assume_offline_after_drops = None } in
      let local_names_cb question =
        let open Dns.Packet in
        match question with
        | { q_name; q_type = Q_A; _ } ->
            let rdata = A (Ipaddr.V4.of_string_exn foo_private) in
            let name = q_name and cls = RR_IN and flush = false and ttl = 100l in
            Some [ { name; cls; flush; ttl; rdata } ]
        | _ ->
            None
      in
      let r = R.create ~local_names_cb ~gen_transaction_id:Random.int config in
      let module F = Dns_forward.Server.Make(Rpc)(R) in
      let f = F.create r in
      let port = fresh_port () in
      let f_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      let open Error in
      F.serve ~sw ~net ~mono ~clock ~address:f_address f
      >>= fun () ->
      Rpc.connect ~gen_transaction_id:Random.int f_address
      >>= fun c ->
      let request = make_a_query (Dns.Name.of_string "foo") in
      Rpc.rpc ~sw clock net c request
      >>= fun response ->
      parse_response response
      >>= fun ipv4 ->
      Alcotest.(check string) "IPv4" foo_private (Ipaddr.V4.to_string ipv4);
      Rpc.disconnect c;
      F.destroy f;
      Eio.Switch.fail sw Exit;
      Ok ()
    with
  | Ok () | exception Exit ->
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  | Error (`Msg m) -> failwith m

let test_udp_nonpersistent ~net ~mono ~clock () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  match
      Eio.Switch.run @@ fun sw ->
      let module Proto_server = Dns_forward.Rpc.Server.Make(Flow)(Dns_forward.Framing.Udp(Flow)) in
      let module Proto_client = Dns_forward.Rpc.Client.Nonpersistent.Make(Flow)(Dns_forward.Framing.Udp(Flow)) in
      let module S = Server.Make(Proto_server) in
      let foo_public = "8.8.8.8" in
      (* a public server mapping 'foo' to a public ip *)
      let public_server = S.make [ "foo", Ipaddr.of_string_exn foo_public ] in
      let port = fresh_port () in
      let public_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      let open Error in
      S.serve ~sw ~address:public_address net public_server
      >>= fun _ ->
      let module R = Dns_forward.Resolver.Make(Proto_client) in
      let open Dns_forward.Config in
      let servers = Server.Set.of_list [
          { Server.address = public_address; zones = Domain.Set.empty; timeout_ms = None; order = 0 };
        ] in
      let config = { servers; search = []; assume_offline_after_drops = None } in
      let r = R.create ~gen_transaction_id:Random.int config in
      let module F = Dns_forward.Server.Make(Proto_server)(R) in
      let f = F.create r in 
      let port = fresh_port () in
      let f_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      let open Error in
      F.serve ~sw ~net ~mono ~clock ~address:f_address f
      >>= fun () ->
      let expected_dst = ref false in
      let message_cb ?src:_ ?dst ~buf:_ () =
        ( match dst with
        | Some d ->
            if Dns_forward.Config.Address.compare f_address d = 0 then expected_dst := true
        | None ->
            ()
        )
      in
      Proto_client.connect ~gen_transaction_id:Random.int ~message_cb f_address
      >>= fun c ->
      let request = make_a_query (Dns.Name.of_string "foo") in
      let send_request () =
        Proto_client.rpc ~sw clock net c request
        >>= fun response ->
        (* Check the response has the correct transaction id *)
        let request' = Dns.Packet.parse request
        and response' = Dns.Packet.parse response in
        Alcotest.(check int) "DNS.id" request'.Dns.Packet.id response'.Dns.Packet.id;
        parse_response response
        >>= fun ipv4 ->
        Alcotest.(check string) "IPv4" foo_public (Ipaddr.V4.to_string ipv4);
        Ok ()
      in
      let rec seq f = function
      | 0 -> Ok ()
      | n ->
          f ()
          >>= fun () ->
          seq f (n - 1) in
      let rec par f = function
      | 0 -> Ok ()
      | n ->
          let first = f () in
          let rest = par f (n - 1) in
          first
          >>= fun () ->
          rest in
      (* Run 5 threads each sending 1000 requests *)
      par (fun () -> seq send_request 1000) 5
      >>= fun () ->
      Proto_client.disconnect c;
      F.destroy f;
      if not (!expected_dst) then failwith ("Expected destination address never seen in message_cb");
      Eio.Switch.fail sw Exit;
      Ok ()
  with
  | Ok () | exception Exit ->
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  | Error (`Msg m) -> failwith m

let test_tcp_multiplexing ~net ~mono ~clock () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  match
      Eio.Switch.run @@ fun sw ->
      let module Proto_server = Dns_forward.Rpc.Server.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
      let module Proto_client = Dns_forward.Rpc.Client.Persistent.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
      let module S = Server.Make(Proto_server) in
      let foo_public = "8.8.8.8" in
      (* a public server mapping 'foo' to a public ip *)
      let public_server = S.make [ "foo", Ipaddr.of_string_exn foo_public ] in
      let port = fresh_port () in
      let public_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      let open Error in
      S.serve ~sw ~address:public_address net public_server
      >>= fun _ ->
      let module R = Dns_forward.Resolver.Make(Proto_client) in
      let open Dns_forward.Config in
      let servers = Server.Set.of_list [
          { Server.address = public_address; zones = Domain.Set.empty; timeout_ms = None; order = 0 };
        ] in
      let config = { servers; search = []; assume_offline_after_drops = None } in
      let r = R.create ~gen_transaction_id:Random.int config in
      let module F = Dns_forward.Server.Make(Proto_server)(R) in
      let f = F.create r in
      let port = fresh_port () in
      let f_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      let open Error in
      F.serve ~sw ~net ~mono ~clock ~address:f_address f
      >>= fun () ->
      let expected_dst = ref false in
      let message_cb ?src:_ ?dst ~buf:_ () =
        ( match dst with
        | Some d ->
            if Dns_forward.Config.Address.compare f_address d = 0 then expected_dst := true
        | None ->
            ()
        )
      in
      Proto_client.connect ~gen_transaction_id:Random.int ~message_cb f_address
      >>= fun c ->
      let request = make_a_query (Dns.Name.of_string "foo") in
      let send_request () =
        Proto_client.rpc ~sw clock net c request
        >>= fun response ->
        (* Check the response has the correct transaction id *)
        let request' = Dns.Packet.parse request
        and response' = Dns.Packet.parse response in
        Alcotest.(check int) "DNS.id" request'.Dns.Packet.id response'.Dns.Packet.id;
        parse_response response
        >>= fun ipv4 ->
        Alcotest.(check string) "IPv4" foo_public (Ipaddr.V4.to_string ipv4);
        Ok () in
      let rec seq f = function
      | 0 -> Ok ()
      | n ->
          f ()
          >>= fun () ->
          seq f (n - 1) in
      let rec par f = function
      | 0 -> Ok ()
      | n ->
          let first = f () in
          let rest = par f (n - 1) in
          first
          >>= fun () ->
          rest in
      (* Run 5 threads each sending 1000 requests *)
      par (fun () -> seq send_request 1000) 5
      >>= fun () ->
      Proto_client.disconnect c;
      F.destroy f;
      if not (!expected_dst) then failwith ("Expected destination address never seen in message_cb");
      Eio.Switch.fail sw Exit;
      Ok ()
    with
  | Ok () | exception Exit ->
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  | Error (`Msg m) -> failwith m

(* One good one bad server should behave like the good server *)
let test_good_bad_server ~net ~mono ~clock () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  match
      Eio.Switch.run @@ fun sw ->
      let module Proto_server = Dns_forward.Rpc.Server.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
      let module Proto_client = Dns_forward.Rpc.Client.Persistent.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
      let module S = Server.Make(Proto_server) in
      let foo_public = "8.8.8.8" in
      (* a public server mapping 'foo' to a public ip *)
      let public_server = S.make ~delay:0.1 [ "foo", Ipaddr.of_string_exn foo_public ] in
      let port = fresh_port () in
      let public_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      let open Error in
      S.serve ~sw ~address:public_address net public_server
      >>= fun _ ->
      let bad_server = S.make [] in
      let port = fresh_port () in
      let bad_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      S.serve ~sw ~address:bad_address net bad_server
      >>= fun _ ->
      let module R = Dns_forward.Resolver.Make(Proto_client) in
      let open Dns_forward.Config in
      (* Forward to a good server and a bad server, both with timeouts. The request to
         the bad request should fail fast but the good server should be given up to
         the timeout to respond *)
      let servers = Server.Set.of_list [
          { Server.address = public_address; zones = Domain.Set.empty; timeout_ms = Some 1000; order = 0 };
          { Server.address = bad_address; zones = Domain.Set.empty; timeout_ms = Some 1000; order = 0 };
        ] in
      let config = { servers; search = []; assume_offline_after_drops = None } in
      let r = R.create ~gen_transaction_id:Random.int config in
      let request = make_a_query (Dns.Name.of_string "foo") in
      let request () =
        R.answer ~sw ~net ~mono ~clock request r
        |> function
        | Ok reply ->
            let len = Cstruct.length reply in
            let buf = reply in
            begin match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
            | Some { Dns.Packet.answers = _ :: _ ; _ } -> true
            | Some packet -> failwith ("test_good_bad_server bad response: " ^ (Dns.Packet.to_string packet))
            | None -> failwith "test_good_bad_server: failed to parse response"
            end
        | Error _ -> failwith "test_good_bad_server timeout: did the failure overtake the success?" in
      let timeout () =
        Eio_unix.sleep 5.;
        false 
      in
      let ok = Eio.Fiber.first request timeout in
      if not ok then failwith "test_good_bad_server hit timeout";
      R.destroy r;
      Eio.Switch.fail sw Exit;
      Ok ()
    with
  | Ok () | exception Exit ->
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  | Error (`Msg m) -> failwith m

(* One good one dead server should behave like the good server *)
let test_good_dead_server ~net ~mono ~clock:_ () =
  let clock = Fake.Clock.make () in
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  match
      Eio.Switch.run @@ fun sw ->
      let module Proto_server = Dns_forward.Rpc.Server.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
      let module Proto_client = Dns_forward.Rpc.Client.Persistent.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
      let module S = Server.Make(Proto_server) in
      let foo_public = "8.8.8.8" in
      (* a public server mapping 'foo' to a public ip *)
      let public_server = S.make [ "foo", Ipaddr.of_string_exn foo_public ] in
      let public_address =
        let port = fresh_port () in
        { Dns_forward.Config.Address.ip = Ipaddr.(V4 V4.localhost); port } in
      let open Error in
      S.serve ~sw ~address:public_address net public_server
      >>= fun _ ->
      let bad_server = S.make ~delay:30. [] in
      let bad_address =
        let port = fresh_port () in
        { Dns_forward.Config.Address.ip = Ipaddr.(V4 V4.localhost); port } in
      S.serve ~sw ~address:bad_address net bad_server
      >>= fun _ ->
      let module R = Dns_forward.Resolver.Make(Proto_client) in
      let open Dns_forward.Config in
      (* Forward to a good server and a bad server, both with timeouts. The request to
         the bad request should fail fast but the good server should be given up to
         the timeout to respond *)
      let servers = Server.Set.of_list [
          { Server.address = public_address; zones = Domain.Set.empty; timeout_ms = Some 1000; order = 0 };
          { Server.address = bad_address; zones = Domain.Set.empty; timeout_ms = Some 1000; order = 0 };
        ] in
      let config = { servers; search = []; assume_offline_after_drops = Some 1 } in
      let r = R.create ~gen_transaction_id:Random.int config in
      let request = make_a_query (Dns.Name.of_string "foo") in
      let t = 
        Eio.Fiber.fork_promise ~sw (fun () -> R.answer ~sw ~net ~mono:(mono :> Eio.Time.Mono.t) ~clock:(clock :> Eio.Time.clock) request r)
      in
      (* First request will trigger the internal timeout and mark the bad server
         as offline. The sleep timeout here will only trigger if this fails. *)
      Fake.Clock.advance clock 1.;
      (* HACK: we want to let all threads run until they block but we don't have
         an API for that. This assumes that all computation will finish in 0.1s *)
      Eio_unix.sleep 0.1;
      Fake.Clock.advance clock 1.;
      (* Eio_mock.Clock.Mono.advance mono; *)
      Eio_unix.sleep 0.1;
      Eio.Fiber.first
        (fun () -> (Eio_unix.sleep 1.; failwith "test_good_dead_server: initial request had no response"))
        (fun () -> ignore (Eio.Promise.await_exn t));
      (* The bad server should be marked offline and no-one will wait for it *)
      Fake.Clock.reset clock;
      Fake.Clock.advance clock 0.5; (* avoid the timeouts winning the race with the actual result *)
      let request =
        match R.answer ~sw ~net ~mono:(mono :> Eio.Time.Mono.t) ~clock:(clock :> Eio.Time.clock) request r with
        | Ok reply ->
            let len = Cstruct.length reply in
            let buf = reply in
            begin match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
            | Some { Dns.Packet.answers = _ :: _ ; _ } -> true
            | Some packet -> failwith ("test_good_dead_server bad response: " ^ (Dns.Packet.to_string packet))
            | None -> failwith "test_good_dead_server: failed to parse response"
            end
        | Error _ -> failwith "test_good_dead_server timeout: did the failure overtake the success?" in
      let timeout =
        Eio_unix.sleep 5.;
        false 
      in
      let ok = Eio.Fiber.first (fun () -> request) (fun () -> timeout) in
      if not ok then failwith "test_good_dead_server hit timeout";
      R.destroy r;
      Eio.Switch.fail sw Exit;
      Ok ()
   with
  | Ok () | exception Exit ->
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  | Error (`Msg m) -> failwith m

(* One bad server should be ignored *)
let test_bad_server ~net ~mono ~clock () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  match
      Eio.Switch.run @@ fun sw ->
      let module Proto_server = Dns_forward.Rpc.Server.Make(Flow)(Dns_forward.Framing.Tcp(Flow))in
      let module Proto_client = Dns_forward.Rpc.Client.Persistent.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
      let module S = Server.Make(Proto_server) in
      let foo_public = "8.8.8.8" in
      (* a public server mapping 'foo' to a public ip *)
      let public_server = S.make ~simulate_bad_question:true [ "foo", Ipaddr.of_string_exn foo_public ] in
      let port = fresh_port () in
      let public_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      let open Error in
      S.serve ~sw ~address:public_address net public_server
      >>= fun _ ->
      let module R = Dns_forward.Resolver.Make(Proto_client) in
      let open Dns_forward.Config in
      let port = fresh_port () in
      let bad_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      (* Forward to a good server and a bad server, both with timeouts. The request to
         the bad request should fail fast but the good server should be given up to
         the timeout to respond *)
      let servers = Server.Set.of_list [
          { Server.address = public_address; zones = Domain.Set.empty; timeout_ms = Some 1000; order = 0 };
          { Server.address = bad_address; zones = Domain.Set.empty; timeout_ms = Some 1000; order = 0 };
        ] in
      let config = { servers; search = []; assume_offline_after_drops = None } in
      let r = R.create ~gen_transaction_id:Random.int config in
      let request = make_a_query (Dns.Name.of_string "foo") in
      let request () =
          Eio.Switch.run @@ fun sw ->
          match R.answer ~sw ~net ~mono ~clock request r with
          | Ok _ -> Ok ()
          | Error _ -> failwith "test_bad_server rpc error" 
      in
      let timeout = Eio.Time.with_timeout clock 0.5 request in
      match timeout with
      | Ok () -> Alcotest.fail "test_bad_server did not hit timeout"
      | Error `Timeout ->
        R.destroy r;
        Eio.Switch.fail sw Exit;
        Ok ();
    with
  | Ok () | exception Exit ->
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  | Error (`Msg m) -> failwith m

let test_timeout ~net ~mono ~clock () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  let module Proto_server = Dns_forward.Rpc.Server.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
  let module Proto_client = Dns_forward.Rpc.Client.Persistent.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
  let module S = Server.Make(Proto_server) in
  let foo_public = "8.8.8.8" in
  (* a public server mapping 'foo' to a public ip *)
  let bar_server = S.make ~delay:60. [ "foo", Ipaddr.of_string_exn foo_public ] in
  let port = fresh_port () in
  let bar_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in

  let open Error in
  match
      Eio.Switch.run @@ fun sw ->
      S.serve ~sw ~address:bar_address net bar_server
      >>= fun _ ->
      (* a resolver which uses both servers *)
      let module R = Dns_forward.Resolver.Make(Proto_client) in
      let open Dns_forward.Config in
      let servers = Server.Set.of_list [
          { Server.address = bar_address; zones = Domain.Set.empty; timeout_ms = Some 0; order = 0 }
        ] in
      let config = { servers; search = []; assume_offline_after_drops = None } in
      let r = R.create ~gen_transaction_id:Random.int config in
      let request = make_a_query (Dns.Name.of_string "foo") in
      let request () =
        Eio.Switch.run @@ fun sw ->
        match R.answer ~sw ~net ~mono ~clock request r with
        | Error _ ->
          Ok true
        | Ok _ -> failwith "got a result when timeout expected"
      in
      let timeout = Eio.Time.with_timeout clock 5. request in
      match timeout with
      | Ok false -> failwith "server timeout was not respected"
      | Ok true | Error `Timeout ->
        R.destroy r;
        Eio.Switch.fail sw Exit;
        Ok ()
    with
  | Ok () | exception Exit ->
      (* the disconnects and close should have removed all the connections: *)
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
      Alcotest.(check int) "bar_server queries" 1 (S.get_nr_queries bar_server);
  | Error (`Msg m) -> failwith m

let test_cache ~net ~mono ~clock () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  let module Proto_server = Dns_forward.Rpc.Server.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
  let module Proto_client = Dns_forward.Rpc.Client.Persistent.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
  let module S = Server.Make(Proto_server) in
  let foo_public = "8.8.8.8" in
  (* a public server mapping 'foo' to a public ip *)
  let bar_server = S.make [ "foo", Ipaddr.of_string_exn foo_public ] in
  let port = fresh_port () in
  let bar_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in

  let open Error in
  match
      Eio.Switch.run @@ fun sw ->
      S.serve ~sw ~address:bar_address net bar_server
      >>= fun server ->
      (* a resolver which uses both servers *)
      let module R = Dns_forward.Resolver.Make(Proto_client) in
      let open Dns_forward.Config in
      let servers = Server.Set.of_list [
          { Server.address = bar_address; zones = Domain.Set.empty; timeout_ms = Some 1000; order = 0 }
        ] in
      let config = { servers; search = []; assume_offline_after_drops = None } in
      let r = R.create ~gen_transaction_id:Random.int config in
      let request = make_a_query (Dns.Name.of_string "foo") in
      match R.answer ~sw ~net ~mono ~clock request r with
      | Error _ -> failwith "failed initial lookup"
      | Ok _ ->
          S.shutdown server;
          match R.answer ~sw ~net ~mono ~clock request r with
          | Error (`Msg m) -> failwith ("failed cached lookup: " ^ m)
          | Ok _ ->
              R.destroy r;
              Eio.Switch.fail sw Exit;
              Ok ()
    with
  | Ok () | exception Exit ->
      (* the disconnects and close should have removed all the connections: *)
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
      Alcotest.(check int) "bar_server queries" 1 (S.get_nr_queries bar_server);
  | Error (`Msg m) -> failwith m

(* One slow private server, one fast public server with different bindings for
   the same name. The order field guarantees that we take the answer from the
   slow private server. *)
let test_order ~net ~mono ~clock () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  let module Proto_server = Dns_forward.Rpc.Server.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
  let module Proto_client = Dns_forward.Rpc.Client.Persistent.Make(Flow)(Dns_forward.Framing.Tcp(Flow)) in
  let module S = Server.Make(Proto_server) in
  let foo_public = "8.8.8.8" in
  let foo_private = "192.168.1.1" in
  (* a public server mapping 'foo' to a public ip *)
  let public_server = S.make [ "foo", Ipaddr.of_string_exn foo_public ] in
  let port = fresh_port () in
  let public_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
  (* a private server mapping 'foo' to a private ip *)
  let private_server = S.make [ "foo", Ipaddr.of_string_exn foo_private ] in
  let port = fresh_port () in
  let private_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in

  let open Error in
  match
      Eio.Switch.run @@ fun sw ->
      S.serve ~sw ~address:public_address net public_server
      >>= fun _ ->
      S.serve ~sw ~address:private_address net private_server
      >>= fun _ ->

      (* a resolver which uses both servers *)
      let module R = Dns_forward.Resolver.Make(Proto_client) in
      let open Dns_forward.Config in
      let servers = Server.Set.of_list [
          { Server.address = public_address; zones = Domain.Set.empty; timeout_ms = None; order = 1 };
          { Server.address = private_address; zones = Domain.Set.empty; timeout_ms = None; order = 0 }
        ] in
      let config = { servers; search = []; assume_offline_after_drops = None } in
      let r = R.create ~gen_transaction_id:Random.int config in
      let request = make_a_query (Dns.Name.of_string "foo") in
      let open Error in
      R.answer ~sw ~net ~mono ~clock request r
      >>= fun response ->
      parse_response response
      >>= fun ipv4 ->
      Alcotest.(check string) "IPv4" foo_private (Ipaddr.V4.to_string ipv4);
      R.destroy r;
      Eio.Switch.fail sw Exit;
      Ok ()
    with
  | Ok () | exception Exit ->
      (* the disconnects and close should have removed all the connections: *)
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
      (* We now query all servers matching a zone *)
      Alcotest.(check int) "private_server queries" 1 (S.get_nr_queries private_server);
      Alcotest.(check int) "public_server queries" 1 (S.get_nr_queries public_server);
  | Error (`Msg m) -> failwith m

let test_forwarder_zone ~net ~mono ~clock () =
  Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
  let module S = Server.Make(Rpc) in
  let foo_public = "8.8.8.8" in
  let foo_private = "192.168.1.1" in
  (* a VPN mapping 'foo' to an internal ip *)
  let foo_server = S.make [ "foo", Ipaddr.of_string_exn foo_private ] in
  let port = fresh_port () in
  let foo_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
  (* a public server mapping 'foo' to a public ip *)
  let bar_server = S.make [ "foo", Ipaddr.of_string_exn foo_public ] in
  let port = fresh_port () in
  let bar_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in

  let open Error in
  match
      Eio.Switch.run @@ fun sw ->
      S.serve ~sw ~address:foo_address net foo_server
      >>= fun _ ->

      S.serve ~sw ~address:bar_address net bar_server
      >>= fun _ ->
      (* a resolver which uses both servers *)
      let module R = Dns_forward.Resolver.Make(Rpc) in
      let open Dns_forward.Config in
      let servers = Server.Set.of_list [
          { Server.address = foo_address; zones = Domain.Set.add [ "foo" ] Domain.Set.empty; timeout_ms = None; order = 0 };
          { Server.address = bar_address; zones = Domain.Set.empty; timeout_ms = None; order = 0 }
        ] in
      let config = { servers; search = []; assume_offline_after_drops = None } in
      let r = R.create ~gen_transaction_id:Random.int config in
      let module F = Dns_forward.Server.Make(Rpc)(R) in
      let f = F.create r in
      let port = fresh_port () in
      let f_address = { Dns_forward.Config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost; port } in
      let open Error in
      F.serve ~sw ~net ~mono ~clock ~address:f_address f
      >>= fun () ->
      Rpc.connect ~gen_transaction_id:Random.int f_address
      >>= fun c ->
      let request = make_a_query (Dns.Name.of_string "foo") in
      Rpc.rpc ~sw clock net c request
      >>= fun response ->
      parse_response response
      >>= fun ipv4 ->
      Alcotest.(check string) "IPv4" foo_private (Ipaddr.V4.to_string ipv4);
      Rpc.disconnect c;
      F.destroy f;
      Eio.Switch.fail sw Exit;
      Ok ()
    with
  | Ok () | exception Exit ->
      (* the disconnects and close should have removed all the connections: *)
      Alcotest.(check int) "number of connections" 0 (List.length @@ Rpc.get_connections ());
      (* The server should have sent the query only to foo and not to bar *)
      Alcotest.(check int) "foo_server queries" 1 (S.get_nr_queries foo_server);
      Alcotest.(check int) "bar_server queries" 0 (S.get_nr_queries bar_server);
  | Error (`Msg m) -> failwith m


let with_env env fn =
  let net = Eio.Stdenv.net env in
  let mono = Eio.Stdenv.mono_clock env in
  let clock = Eio.Stdenv.clock env in
  fn ~net ~mono ~clock

let test_infra_set env = [
  "Server responds correctly", `Quick, test_server;
  "Bad server responses are ignored", `Quick, (with_env env test_bad_server);
]

let test_protocol_set env = [
  "TCP multiplexing", `Quick, (with_env env test_tcp_multiplexing);
  "UDP non-persistent", `Quick, (with_env env test_udp_nonpersistent);
]

let test_forwarder_set env = [
  "Per-server timeouts", `Quick, (with_env env test_timeout);
  "Zone config respected", `Quick, (with_env env test_forwarder_zone);
  "Local names resolve ok", `Quick, (with_env env test_local_lookups);
  "Server order", `Quick, (with_env env test_order);
  "Caching", `Quick, (with_env env test_cache);
  "Tolerate bad server", `Quick, (with_env env test_good_bad_server);
  "Tolerate broken server", `Quick, (with_env env test_good_dead_server);
]

open Dns_forward.Config

let config_examples = [
  "nameserver 10.0.0.2\nnameserver 1.2.3.4#54\nsearch a b c",
  { servers = Server.Set.of_list [
        { Server.address = { Address.ip = Ipaddr.V4 (Ipaddr.V4.of_string_exn "10.0.0.2"); port = 53 }; zones = Domain.Set.empty; timeout_ms = None; order = 0 };
        { Server.address = { Address.ip = Ipaddr.V4 (Ipaddr.V4.of_string_exn "1.2.3.4"); port = 54 }; zones = Domain.Set.empty; timeout_ms = None; order = 0 };
      ]; search = [ "a"; "b"; "c" ]; assume_offline_after_drops = None
  };
  "nameserver 10.0.0.2\n",
  { servers = Server.Set.of_list [
        { Server.address = { Address.ip = Ipaddr.V4 (Ipaddr.V4.of_string_exn "10.0.0.2"); port = 53 }; zones = Domain.Set.empty; timeout_ms = None; order = 0 };
      ]; search = []; assume_offline_after_drops = None
  };
  String.concat "\n" [
    "# a pretend VPN zone with a private nameserver";
    "nameserver 1.2.3.4";
    "zone mirage.io foo.com";
    "timeout 5000";
    "order 1";
    "";
    "# a default nameserver";
    "nameserver 8.8.8.8";
  ], {
    servers = Server.Set.of_list [
        { Server.address = { Address.ip = Ipaddr.V4 (Ipaddr.V4.of_string_exn "8.8.8.8"); port = 53 }; zones = Domain.Set.empty; timeout_ms = None; order = 0; };
        { Server.address = { Address.ip = Ipaddr.V4 (Ipaddr.V4.of_string_exn "1.2.3.4"); port = 53 };
          zones = Domain.Set.of_list [ [ "mirage"; "io" ]; [ "foo"; "com" ] ];
          timeout_ms = Some 5000;
          order = 1;
        };
      ]; search = []; assume_offline_after_drops = None;
  };
]

let test_parse_config txt expected () =
  match of_string txt with
  | Error (`Msg m) -> failwith m
  | Ok x ->
      if compare expected x <> 0
      then failwith ("failed to parse " ^ txt)

let test_config = List.map (fun (txt, expected) ->
    "DNS_" ^ (String.escaped txt), `Quick, test_parse_config txt expected
  ) config_examples

let () =
  Eio_main.run @@ fun env ->
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug);
  Random.self_init ();
  Alcotest.run "dns-forward" [
    "test_infrastructure", test_infra_set env;
    "test_forwarding", test_forwarder_set env;
    "test_protocols", test_protocol_set env;
    "test_config parsing", test_config;
  ]
