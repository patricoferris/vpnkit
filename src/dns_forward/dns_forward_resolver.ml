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

let src =
  let src = Logs.Src.create "Dns_forward" ~doc:"DNS resolution" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)
open Eio

let nchoose_split list =
  let ready, waiting = List.fold_left
    (fun (term, acc) p ->
      match Promise.peek p with
      | Some _ -> (Promise.await_exn p :: term, acc)
      | None -> (term, p :: acc))
    ([], []) list
  in
    List.rev ready, List.rev waiting

let is_in_domain name domain =
  let name' = List.length name and domain' = List.length domain in
  name' >= domain'
  &&
  let to_remove = name' - domain' in
  let rec trim n xs =
    match (n, xs) with
    | 0, _ -> xs
    | _, [] -> invalid_arg "trim"
    | n, _ :: xs -> trim (n - 1) xs
  in
  let trimmed_name = trim to_remove name in
  trimmed_name = domain

module IntSet = Set.Make (struct
  type t = int

  let compare (a : int) (b : int) = compare a b
end)

let choose_servers config request =
  let open Dns.Packet in
  let open Dns_forward_config in
  (* Match the name in the query against the configuration *)
  match request with
  | { questions = [ { q_name; _ } ]; _ } ->
      let labels = Dns.Name.to_string_list q_name in
      let matching_servers =
        List.filter
          (fun server ->
            Domain.Set.fold
              (fun zone acc -> acc || is_in_domain labels zone)
              server.Server.zones false)
          config
      in
      let all =
        match matching_servers with
        | _ :: _ ->
            (* If any of the configured domains match, send to these servers *)
            matching_servers
        | [] ->
            (* Otherwise send to all servers *)
            config
      in
      (* Now we order by the order field *)
      let orders =
        List.fold_left
          (fun set server -> IntSet.add server.Server.order set)
          IntSet.empty all
      in
      List.map
        (fun order ->
          List.filter (fun server -> server.Server.order = order) all)
        (IntSet.elements orders)
  | _ -> []

let or_fail_msg = function
  | Result.Error `Eof -> raise End_of_file
  | Result.Error (`Msg m) -> failwith m
  | Result.Ok x -> x

module type S = Dns_forward_s.RESOLVER

module Make (Client : Dns_forward_s.RPC_CLIENT) = struct
  module Cache = Dns_forward_cache

  type address = Dns_forward_config.Address.t

  type message_cb =
    ?src:address -> ?dst:address -> buf:Cstruct.t -> unit -> unit

  type connection = {
    server : Dns_forward_config.Server.t;
    client : Client.t;
    mutable reply_expected_since : int64 option;
    (* if None: we don't expect a reply
       if Some t: we haven't heard from the server since time t *)
    mutable replies_missing : int;
    (* the number of requests we've sent which have not been replied to *)
    mutable online : bool; (* true if we assume the server is online *)
  }

  type t = {
    connections : connection list;
    local_names_cb : Dns.Packet.question -> Dns.Packet.rr list option;
    cache : Cache.t;
    config : Dns_forward_config.t;
  }

  let create ?(local_names_cb = fun _ -> None) ~gen_transaction_id ?message_cb
      config =
    let connections =
      List.map
        (fun server ->
          let client =
            or_fail_msg
            @@ Client.connect ~gen_transaction_id ?message_cb
                 server.Dns_forward_config.Server.address
          in
          let reply_expected_since = None in
          let replies_missing = 0 in
          let online = true in
          { server; client; reply_expected_since; replies_missing; online })
        (Dns_forward_config.Server.Set.elements
           config.Dns_forward_config.servers)
    in
    let cache = Cache.make () in
    { connections; local_names_cb; cache; config }

  let destroy t =
    Cache.destroy t.cache;
    List.iter (fun c -> Client.disconnect c.client) t.connections

  let answer ~sw ~net ~mono ~clock buffer t =
    let len = Cstruct.length buffer in
    let buf = buffer in
    let open Dns.Packet in
    match Dns.Protocol.Server.parse (Cstruct.sub buf 0 len) with
    | Some ({ questions = [ question ]; _ } as request) -> (
        (* Given a set of answers (resource records), synthesize an answer to the
           current question. *)
        let reply answers =
          let id = request.id in
          let detail =
            {
              request.detail with
              Dns.Packet.qr = Dns.Packet.Response;
              ra = true;
            }
          in
          let questions = request.questions in
          let authorities = [] and additionals = [] in
          { id; detail; questions; answers; authorities; additionals }
        in

        (* Look for any local answers to this question *)
        match t.local_names_cb question with
        | Some answers -> Ok (marshal @@ reply answers)
        | None -> (
            (* Ask one server, with caching. Possible results are:
               Ok (`Success buf): succesful reply
               Ok (`Failure buf): an error like NXDomain
               Error (`Msg m): a low-level error or timeout
            *)
            let one_rpc server =
              let open Dns_forward_config in
              let address = server.Server.address in
              (* Look in the cache *)
              match Cache.answer t.cache address question with
              | Some answers -> Ok (`Success (marshal @@ reply answers))
              | None -> (
                  let c =
                    List.find (fun c -> c.server = server) t.connections
                  in
                  let now_ns = Time.Mono.now mono in
                  (* If no timeout is configured, we will stop listening after
                     5s to avoid leaking threads if a server is offline *)
                  let timeout_ns =
                    match server.Server.timeout_ms with
                    | None -> Duration.of_sec 5
                    | Some x -> Duration.of_ms x
                  in
                  (* If no assume_offline_after_drops is configured then set this
                     to 5s. *)
                  let assume_offline_after_drops =
                    match t.config.assume_offline_after_drops with
                    | Some c -> c
                    | None -> 5
                  in
                  (* Within the overall timeout_ms (configured by the user) we will send
                     the request at 1s intervals to guard against packet drops. *)
                  let delays_ns =
                    let rec make from =
                      if from > timeout_ns then []
                      else from :: make (Int64.add from Duration.(of_sec 1))
                    in
                    make 0L
                  in
                  let requests =
                    List.map
                      (fun delay_ns () ->
                        Eio.Time.sleep clock
                          (Int64.to_float delay_ns /. 1_000_000_000.);
                        Client.rpc ~sw clock net c.client buffer)
                      delays_ns
                  in
                  let timeout () =
                    Eio.Time.sleep clock
                      (Int64.to_float timeout_ns /. 1_000_000_000.);
                    Error (`Msg "timeout")
                  in
                  match Fiber.any (timeout :: requests) with
                  | Error x ->
                      if c.reply_expected_since = None then
                        c.reply_expected_since <-
                          Some (Mtime.to_uint64_ns now_ns);
                      c.replies_missing <-
                        c.replies_missing + List.length delays_ns;
                      if
                        assume_offline_after_drops < c.replies_missing
                        && c.online
                      then (
                        Log.err (fun f ->
                            f
                              "Upstream DNS server %s has dropped %d packets \
                               in a row: assuming it's offline"
                              (Dns_forward_config.Address.to_string address)
                              c.replies_missing);
                        c.online <- false);
                      Error x
                  | Ok reply -> (
                    Logs.debug (fun f -> f "Got a reply!");
                      c.reply_expected_since <- None;
                      c.replies_missing <- 0;
                      if not c.online then (
                        Log.info (fun f ->
                            f "Upstream DNS server %s is back online"
                              (Dns_forward_config.Address.to_string address));
                        c.online <- true);
                      (* Determine whether it's a success or a failure; if a success
                         then insert the value into the cache. *)
                      let len = Cstruct.length reply in
                      let buf = reply in
                      match
                        Dns.Protocol.Server.parse (Cstruct.sub buf 0 len)
                      with
                      | Some
                          {
                            detail = { rcode = NoError; _ };
                            answers = _ :: _ as answers;
                            _;
                          } ->
                          Cache.insert ~clock t.cache address question answers;
                          Ok (`Success reply)
                      | packet -> Ok (`Failure (packet, reply))))
            in

            (* Ask many servers but first
               - Filter the list of servers using any "zone" setting -- this will
                 prevent queries for private names being leaked to public servers
                 (if configured).
               - Group the servers into lists of equal priorities.
               - Send all the requests concurrently. *)
            let many_rpcs connections =
              let equal_priority_groups =
                choose_servers
                  (List.map (fun c -> c.server) connections)
                  request
              in
              (* Send all requests in parallel to minimise the chance of hitting a
                 timeout. Positive replies will be cached, but servers which don't
                 recognise the name will be queried each time. *)
              List.map
                (List.map (fun d ->
                     Fiber.fork_promise ~sw (fun () -> one_rpc d)))
                equal_priority_groups
            in

            let online, offline =
              List.partition (fun c -> c.online) t.connections
            in
            if online = [] && t.connections <> [] then (
              let open Dns_forward_config in
              Log.warn (fun f ->
                  f "There are no online DNS servers configured.");
              Log.warn (fun f ->
                  f "DNS servers %s are all marked offline"
                    (String.concat ", "
                       (List.map
                          (fun c ->
                            Address.to_string @@ c.server.Server.address)
                          offline))));
            (* For all the offline servers, send the requests as a "ping" to see
               if they are alive or not. Any response will flip them back to online
               but we won't consider their responses until the next RPC *)
            let _ = many_rpcs offline in

            (* For all the online servers, send the requests and return the waiting
               threads. *)
            let online_results = many_rpcs online in

            (* Wait for the best result from a set of equal priority requests *)
            let rec wait best_so_far remaining =
              Logs.debug (fun f -> f "Waiting %i" (List.length remaining));
              if remaining = [] then best_so_far
              else
                let terminated, remaining = nchoose_split remaining in
                match
                  List.fold_left
                    (fun best_so_far next ->
                      match best_so_far with
                      | Ok (`Success result) ->
                          (* No need to wait for any of the rest: one success is good enough *)
                          Ok (`Success result)
                      | best_so_far -> (
                          match (best_so_far, next) with
                          | _, Ok (`Success result) -> Ok (`Success result)
                          | ( Ok (`Failure (a_packet, a_reply)),
                              Ok (`Failure (b_packet, b_reply)) ) -> (
                              match (a_packet, b_packet) with
                              (* Prefer NXDomain to errors like Refused *)
                              | Some { detail = { rcode = NXDomain; _ }; _ }, _
                                ->
                                  Ok (`Failure (a_packet, a_reply))
                              | _, Some { detail = { rcode = NXDomain; _ }; _ }
                                ->
                                  Ok (`Failure (b_packet, b_reply))
                              | _, _ ->
                                  (* other than that, the earlier error is better *)
                                  Ok (`Failure (a_packet, a_reply)))
                          | Error _, Ok (`Failure (b_packet, b_reply)) ->
                              (* prefer a high-level error over a low-level (e.g. socket) error *)
                              Ok (`Failure (b_packet, b_reply))
                          | best_so_far, _ -> best_so_far))
                    best_so_far terminated
                with
                | Ok (`Success result) -> Ok (`Success result)
                | best_so_far ->
                  Eio.Fiber.yield ();
                  wait best_so_far remaining
            in
            (* Wait for each equal priority group at a time *)
            let res =
              List.fold_left
                (fun best_so_far next ->
                  match best_so_far with
                  | Ok (`Success result) -> Ok (`Success result)
                  | best_so_far -> wait best_so_far next)
                (Error (`Msg "no servers configured"))
                online_results
            in
            match res with
            | Ok (`Success reply) -> Ok reply
            | Ok (`Failure (_, reply)) -> Ok reply
            | Error x -> Error x))
    | Some { questions = _; _ } ->
        Error (`Msg "cannot handle DNS packets where len(questions)<>1")
    | None -> Error (`Msg "failed to parse request")
end
