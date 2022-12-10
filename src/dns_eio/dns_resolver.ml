(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2013-2015 David Sheets <sheets@alum.mit.edu>
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
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
 *)

open Eio
open Dns
open Operators
open Protocol

module DP = Packet

type result = Answer of DP.t | Error of exn

type commfn = {
  txfn    : Cstruct.t -> unit;
  rxfn    : (Cstruct.t -> Dns.Packet.t option) -> DP.t;
  timerfn : unit -> unit;
  cleanfn : unit -> unit;
}

let rec send_req txfn timerfn q =
  function
  | 0 -> ()
  | count ->
    txfn q;
    timerfn ();
    send_req txfn timerfn q (count - 1)

let nchoose_split list =
  let ready, waiting = List.fold_left
    (fun (term, acc) p ->
      match Promise.peek p with
      | Some _ -> (Promise.await p :: term, acc)
      | None -> (term, p :: acc))
    ([], []) list
  in
    List.rev ready, List.rev waiting

let send_pkt client ?alloc ({ txfn; rxfn; timerfn; _ }) pkt =
  Eio.Switch.run @@ fun sw ->
  let module R = (val client : CLIENT) in
  let cqpl = R.marshal ?alloc pkt in
  let resl = List.map (fun (ctxt,q) ->
    (* make a new socket for each request flavor *)
    (* start the requests in parallel and run them until success or timeout*)
    let t, w = Promise.create () in
    Fiber.fork ~sw (fun () -> Fiber.any [
      (fun () -> send_req txfn timerfn q 4; Error (R.timeout ctxt));
      (fun () ->
        try rxfn (R.parse ctxt) |> fun r -> Answer r with exn -> Error exn)
    ] |> fun v -> Promise.resolve w v);
    t
  ) cqpl in
  (* return an answer or all the errors if no request succeeded *)
  let rec select errors = function
    | [] -> raise (Dns_resolve_error errors)
    | ts ->
      let rs, ts = nchoose_split ts in
      let rec find_answer errors = function
        | [] -> select errors ts
        | (Answer a) :: _ -> a
        | (Error e) :: r -> find_answer (e::errors) r
      in
      find_answer errors rs
  in select [] resl

let resolve_pkt client ?alloc (commfn:commfn) pkt =
  try
      let r = send_pkt client ?alloc commfn pkt in
      commfn.cleanfn ();
      r
  with exn ->
      commfn.cleanfn ();
      raise exn

let resolve client
    ?alloc
    ?(dnssec=false)
    (commfn:commfn)
    (q_class:DP.q_class) (q_type:DP.q_type)
    (q_name:Name.t) =
  let id = (let module R = (val client : CLIENT) in R.get_id ()) in
  let q = Dns.Query.create ~id ~dnssec q_class q_type q_name in
  resolve_pkt client ?alloc commfn q

let gethostbyname
    ?alloc
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
    commfn
    name =
  let open DP in
  let domain = Name.of_string name in
  let r = resolve (module Dns.Protocol.Client) ?alloc commfn q_class q_type domain in
  List.fold_left (fun a x ->
      match x.rdata with
      | A ip -> Ipaddr.V4 ip :: a
      | AAAA ip -> Ipaddr.V6 ip :: a
      | _ -> a
    ) [] r.answers
  |> List.rev

let gethostbyaddr
    ?alloc
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
    commfn
    addr
  =
  let addr = Name.of_ipaddr (Ipaddr.V4 addr) in
  let open DP in
  let r = resolve (module Dns.Protocol.Client) ?alloc commfn q_class q_type addr in
  List.fold_left (fun a x ->
      match x.rdata with |PTR n -> (Name.to_string n)::a |_->a
    ) [] r.answers
  |> List.rev
