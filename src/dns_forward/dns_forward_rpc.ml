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
  let src = Logs.Src.create "Dns_forward" ~doc:"DNS over SOCKETS" in
  Logs.Src.set_level src (Some Logs.Info);
  src

let ( >>= ) = Result.bind

module Log = (val Logs.src_log src : Logs.LOG)

module Client = struct
  module type S = Dns_forward_s.RPC_CLIENT

  module Nonpersistent = struct
    module Make
        (Sockets : Dns_forward_s.FLOW_CLIENT with type address = Ipaddr.t * int)
        (Packet : Dns_forward_s.READERWRITER with type flow = Sockets.flow) =
    struct
      type address = Dns_forward_config.Address.t
      type request = Cstruct.t
      type response = Cstruct.t

      type message_cb =
        ?src:address -> ?dst:address -> buf:Cstruct.t -> unit -> unit

      type t = {
        address : address;
        free_ids : Dns_forward_free_id.t;
        message_cb : message_cb;
      }

      let connect ~gen_transaction_id
          ?(message_cb = fun ?src:_ ?dst:_ ~buf:_ () -> ()) address =
        let free_ids = Dns_forward_free_id.make ~g:gen_transaction_id () in
        Ok { address; free_ids; message_cb }

      let to_string t = Dns_forward_config.Address.to_string t.address

      let rpc ~sw _clock net (t : t) buffer =
        let buf = buffer in
        match
          Dns.Protocol.Server.parse (Cstruct.sub buf 0 (Cstruct.length buffer))
        with
        | Some request ->
            (* Although we aren't multiplexing requests on the same flow (unlike the
               Persistent case below) we still rewrite the request id
               - to limit the number of sockets we allocate
               - to work around clients who use predictable request ids *)

            (* The id whose scope is the link to the client *)
            let client_id = request.Dns.Packet.id in
            (* The id whose scope is the link to the server *)
            Dns_forward_free_id.with_id t.free_ids (fun free_id ->
                (* Copy the buffer since this function will be run in parallel with the
                   same buffer *)
                let buffer =
                  let tmp = Cstruct.create (Cstruct.length buffer) in
                  Cstruct.blit buffer 0 tmp 0 (Cstruct.length buffer);
                  tmp
                in
                (* Rewrite the query id before forwarding *)
                Cstruct.BE.set_uint16 buffer 0 free_id;
                Log.debug (fun f ->
                    f "%s mapping DNS id %d -> %d" (to_string t) client_id
                      free_id);

                match
                  Sockets.connect ~sw ~net
                    ( t.address.Dns_forward_config.Address.ip,
                      t.address.Dns_forward_config.Address.port )
                with
                | Error _ as e -> e
                | Ok flow ->
                    Fun.protect
                      (fun () ->
                        let rw = Packet.connect flow in
                        t.message_cb ~dst:t.address ~buf:buffer ();

                        (* An existing connection to the server might have been closed by the server;
                           therefore if we fail to write the request, reconnect and try once more. *)
                        Packet.write rw buffer >>= fun () ->
                        Packet.read rw >>= fun buf ->
                        t.message_cb ~src:t.address ~buf ();
                        (* Rewrite the query id back to the original *)
                        Cstruct.BE.set_uint16 buf 0 client_id;
                        Ok buf)
                      ~finally:(fun () -> Sockets.close flow))
        | _ ->
            Log.err (fun f ->
                f "%s: rpc: failed to parse request" (to_string t));
            Error (`Msg (to_string t ^ ":failed to parse request"))

      let disconnect _ = ()
    end
  end

  module Persistent = struct
    module Make
        (Sockets : Dns_forward_s.FLOW_CLIENT with type address = Ipaddr.t * int)
        (Packet : Dns_forward_s.READERWRITER with type flow = Sockets.flow) =
    struct
      open Eio

      type address = Dns_forward_config.Address.t
      type request = Cstruct.t
      type response = Cstruct.t

      type message_cb =
        ?src:address -> ?dst:address -> buf:Cstruct.t -> unit -> unit

      type t = {
        address : address;
        mutable client_address : address;
        mutable rw : Packet.t option;
        mutable disconnect_on_idle : unit;
        wakeners :
          ( int,
            Dns.Packet.question * (Cstruct.t, exn) result Eio.Promise.u )
          Hashtbl.t;
        m : Eio.Mutex.t;
        free_ids : Dns_forward_free_id.t;
        message_cb : message_cb;
      }

      module FlowError = Dns_forward_error.FromFlowError (Sockets)

      let to_string t = Dns_forward_config.Address.to_string t.client_address

      let disconnect t =
        Mutex.use_ro t.m (fun () ->
            match t with
            | { rw = Some rw; _ } as t ->
                t.rw <- None;
                let error =
                  Failure (to_string t ^ ": connection to server was closed")
                in
                Hashtbl.iter
                  (fun id (question, u) ->
                    Log.info (fun f ->
                        f "%s %04x: disconnect: failing request for question %s"
                          (to_string t) id
                          (Dns.Packet.question_to_string question));
                    (* It's possible that the response just arrived but hasn't been
                       processed by the client thread *)
                    try Promise.resolve_error u error
                    with Invalid_argument _ ->
                      Log.warn (fun f ->
                          f
                            "%s %04x: disconnect: response for DNS request \
                             just arrived in time"
                            (to_string t) id))
                  t.wakeners;
                Packet.close rw
            | _ -> ())

      (* Receive all the responses and demux to the right thread. When the connection
         is closed, `read_buffer` will fail and this thread will exit. *)
      let dispatcher t rw () =
        let rec loop () =
          match Packet.read rw with
          | Error (`Msg m) ->
              Log.debug (fun f ->
                  f "%s: dispatcher shutting down: %s" (to_string t) m);
              disconnect t
          | Ok buffer -> (
              let buf = buffer in
              match
                Dns.Protocol.Server.parse
                  (Cstruct.sub buf 0 (Cstruct.length buffer))
              with
              | Some ({ Dns.Packet.questions = [ question ]; _ } as response) ->
                  let client_id = response.Dns.Packet.id in
                  if Hashtbl.mem t.wakeners client_id then
                    let expected_question, u =
                      Hashtbl.find t.wakeners client_id
                    in
                    if expected_question <> question then
                      Log.warn (fun f ->
                          f
                            "%s %04x: response arrived for a different \
                             question: expected %s <> got %s"
                            (to_string t) client_id
                            (Dns.Packet.question_to_string expected_question)
                            (Dns.Packet.question_to_string question))
                    else
                      (* It's possible that disconnect has already failed the thread *)
                      try Promise.resolve u (Ok buffer)
                      with Invalid_argument _ ->
                        Log.warn (fun f ->
                            f
                              "%s %04x: response arrived for DNS request just \
                               after disconnection"
                              (to_string t) client_id)
                  else
                    Log.debug (fun f ->
                        f "%s %04x: no wakener: it was probably cancelled"
                          (to_string t) client_id);
                  loop ()
              | _ ->
                  Log.err (fun f ->
                      f "%s: dispatcher failed to parse response" (to_string t));
                  raise (Failure "failed to parse response"))
        in
        try loop ()
        with e ->
          Log.info (fun f ->
              f "%s dispatcher caught %s" (to_string t) (Printexc.to_string e))

      let get_rw ~sw clock net t =
        (* Lwt.cancel t.disconnect_on_idle; *)
        let rw =
          Mutex.use_ro t.m (fun () ->
              match t.rw with
              | None ->
                  Sockets.connect ~sw ~net
                    ( t.address.Dns_forward_config.Address.ip,
                      t.address.Dns_forward_config.Address.port )
                  >>= fun flow ->
                  let rw = Packet.connect flow in
                  t.rw <- Some rw;
                  Fiber.fork ~sw (dispatcher t rw);
                  Ok rw
              | Some rw -> Ok rw)
        in
        (* Add a fresh idle timer *)
        t.disconnect_on_idle <-
          (Time.sleep clock 30.;
           disconnect t);
        rw

      let connect ~gen_transaction_id
          ?(message_cb = fun ?src:_ ?dst:_ ~buf:_ () -> ()) address =
        let rw = None in
        let m = Mutex.create () in
        let disconnect_on_idle = () in
        let wakeners = Hashtbl.create 7 in
        let free_ids = Dns_forward_free_id.make ~g:gen_transaction_id () in
        let client_address =
          {
            Dns_forward_config.Address.ip = Ipaddr.V4 Ipaddr.V4.localhost;
            port = 0;
          }
        in
        Ok
          {
            client_address;
            address;
            rw;
            disconnect_on_idle;
            wakeners;
            m;
            free_ids;
            message_cb;
          }

      let rpc ~sw clock net (t : t) buffer =
        let buf = buffer in
        match
          Dns.Protocol.Server.parse (Cstruct.sub buf 0 (Cstruct.length buffer))
        with
        | Some ({ Dns.Packet.questions = [ question ]; _ } as request) ->
            (* Note: the received request id is scoped to the connection with the
               client. Since we are multiplexing requests to a single server we need
               to track used/unused ids on the link to the server and remember the
               mapping to the client. *)

            (* The id whose scope is the link to the client *)
            let client_id = request.Dns.Packet.id in
            (* The id whose scope is the link to the server *)
            Dns_forward_free_id.with_id t.free_ids (fun free_id ->
                Fun.protect
                  (fun () ->
                    (* Copy the buffer since this function will be run in parallel with the
                       same buffer *)
                    let buffer =
                      let tmp = Cstruct.create (Cstruct.length buffer) in
                      Cstruct.blit buffer 0 tmp 0 (Cstruct.length buffer);
                      tmp
                    in
                    (* Rewrite the query id before forwarding *)
                    Cstruct.BE.set_uint16 buffer 0 free_id;
                    Log.debug (fun f ->
                        f "%s mapping DNS id %d -> %d" (to_string t) client_id
                          free_id);

                    let th, u = Promise.create () in
                    Hashtbl.replace t.wakeners free_id (question, u);

                    (* If we fail to connect, return the error *)
                    let v =
                      get_rw ~sw clock net t >>= fun rw ->
                      t.message_cb ~dst:t.address ~buf:buffer ();
                      (* An existing connection to the server might have been closed by the server;
                         therefore if we fail to write the request, reconnect and try once more. *)
                      match Packet.write rw buffer with
                      | Ok () -> Ok ()
                      | Error (`Msg m) -> (
                          Log.info (fun f ->
                              f
                                "%s: caught %s writing request, attempting to \
                                 reconnect"
                                (to_string t) m);
                          disconnect t;
                          match get_rw ~sw clock net t with
                          | Error _ as e -> e
                          | Ok rw ->
                              t.message_cb ~dst:t.address ~buf:buffer ();
                              Packet.write rw buffer)
                    in
                    match v with
                    | Error (`Msg m) -> Error (`Msg m)
                    | Ok () ->
                        let buf = Promise.await_exn th in
                        (* will be woken up by the dispatcher *)
                        t.message_cb ~src:t.address ~buf ();
                        (* Rewrite the query id back to the original *)
                        Cstruct.BE.set_uint16 buf 0 client_id;
                        Ok buf)
                  ~finally:(fun () ->
                    (* This happens on cancel, disconnect, successful response *)
                    Hashtbl.remove t.wakeners free_id))
        | _ ->
            Log.err (fun f ->
                f "%s: rpc: failed to parse request" (to_string t));
            Error (`Msg (to_string t ^ ":failed to parse request"))
    end
  end
end

module Server = struct
  module type S = Dns_forward_s.RPC_SERVER

  module Make
      (Sockets : Dns_forward_s.FLOW_SERVER with type address = Ipaddr.t * int)
      (Packet : Dns_forward_s.READERWRITER with type flow = Sockets.flow) =
  struct
    open Eio

    type address = Dns_forward_config.Address.t
    type request = Cstruct.t
    type response = Cstruct.t
    type server = { address : address; server : Sockets.server }

    let bind ~sw net address =
      Sockets.bind ~sw net
        ( address.Dns_forward_config.Address.ip,
          address.Dns_forward_config.Address.port )
      >>= fun server -> Ok { address; server }

    let listen ~sw { server; _ } cb =
      Sockets.listen ~sw server (fun flow ->
          let rw = Packet.connect flow in
          let rec loop () =
            Packet.read rw >>= fun request ->
            Fiber.fork ~sw (fun () ->
                match cb request with
                | Error _ -> ()
                | Ok response -> ignore (Packet.write rw response));
            loop ()
          in
          match loop () with
          | Error (`Msg m) ->
              Log.err (fun f -> f "server loop failed with: %s" m)
          | Ok () -> ());
      Ok ()

    let shutdown server = Sockets.shutdown server.server
  end
end
