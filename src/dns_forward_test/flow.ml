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

open Dns_forward
module Error = Error.Infix

let errorf fmt = Printf.ksprintf (fun s -> Result.Error (`Msg s)) fmt

type address = Ipaddr.t * int
let string_of_address (ip, port) = Ipaddr.to_string ip ^ ":" ^ (string_of_int port)
type error = [ `Msg of string ]
let pp_error ppf (`Msg x) = Fmt.string ppf x
type write_error = Mirage_flow.write_error
let pp_write_error = Mirage_flow.pp_write_error

type flow = {
  l2r: Cstruct.t Lwt_dllist.t; (* pending data from left to right *)
  mutable l2r_closed: bool;
  l2r_c: Eio.Condition.t;
  l2r_m: Eio.Mutex.t;
  r2l: Cstruct.t Lwt_dllist.t; (* pending data from right to left *)
  mutable r2l_closed: bool;
  r2l_c: Eio.Condition.t;
  r2l_m: Eio.Mutex.t;
  client_address: address;
  server_address: address;
}

let openflow server_address =
  let l2r = Lwt_dllist.create () in
  let r2l = Lwt_dllist.create () in
  let l2r_c = Eio.Condition.create () in
  let r2l_c = Eio.Condition.create () in
  let l2r_m = Eio.Mutex.create () in
  let r2l_m = Eio.Mutex.create () in
  let l2r_closed = false in
  let r2l_closed = false in
  let client_address = Ipaddr.V4 Ipaddr.V4.localhost, 32768 in
  { l2r; r2l; l2r_c; r2l_c; l2r_m; r2l_m; l2r_closed; r2l_closed; client_address; server_address }

let otherend flow =
  { l2r = flow.r2l; l2r_c = flow.r2l_c; r2l = flow.l2r; r2l_c = flow.l2r_c;
    l2r_closed = flow.r2l_closed; r2l_closed = flow.l2r_closed;
    l2r_m = flow.l2r_m; r2l_m = flow.r2l_m;
    client_address = flow.server_address; server_address = flow.client_address }

let read flow =
  let rec wait () =
    if Lwt_dllist.is_empty flow.r2l && not(flow.r2l_closed) then begin
      Eio.Condition.await_no_mutex flow.r2l_c;
      wait ()
    end else () in
  wait ();
  if flow.r2l_closed
  then begin
    Ok `Eof
  end
  else begin 
    Logs.debug (fun f -> f "DATA");
    Ok (`Data (Lwt_dllist.take_r flow.r2l))
  end 

let write flow buf =
  Logs.debug (fun f -> f "WRITE");
  if flow.l2r_closed then Error `Closed else (
    ignore @@ Lwt_dllist.add_l buf flow.l2r;
    Eio.Condition.signal flow.l2r_c;
    Ok ()
  )

let shutdown_read flow =
  flow.r2l_closed <- true;
  Eio.Condition.signal flow.r2l_c

let shutdown_write flow =
  flow.l2r_closed <- true;
  Eio.Condition.signal flow.l2r_c

let writev flow bufs =
  Logs.debug (fun f -> f "WRITEV");
  if flow.l2r_closed then Error `Closed else (
    List.iter (fun buf -> ignore @@ Lwt_dllist.add_l buf flow.l2r) bufs;
    Eio.Condition.signal flow.l2r_c;
    Ok ()
  )

let nr_connects = Hashtbl.create 7

let get_connections () = Hashtbl.fold (fun k v acc -> (k, v) :: acc) nr_connects []

let close flow =
  let nr = Hashtbl.find nr_connects flow.server_address - 1 in
  if nr = 0 then Hashtbl.remove nr_connects flow.server_address else Hashtbl.replace nr_connects flow.server_address nr;
  flow.l2r_closed <- true;
  flow.r2l_closed <- true;
  Eio.Condition.signal flow.l2r_c;
  Eio.Condition.signal flow.r2l_c

type server = {
  mutable listen_cb: unit -> (flow, [ `Msg of string ]) result;
  address: address;
}
let bound = Hashtbl.create 7

let getsockname server = server.address

let connect ~sw:_ ~net:_ ?read_buffer_size:_ address =
  if Hashtbl.mem bound address then begin
    Hashtbl.replace nr_connects address (if Hashtbl.mem nr_connects address then Hashtbl.find nr_connects address + 1 else 1);
    let cb = (Hashtbl.find bound address).listen_cb in
    let flow = cb () in
    flow
  end else errorf "connect: no server bound to %s" (string_of_address address)

let bind ~sw:_ _net address =
  let listen_cb _ = Result.Error (`Msg "no callback") in
  let server = { listen_cb; address } in
  if Hashtbl.mem bound address
  then Result.Error (`Msg "address already bound")
  else begin
    Hashtbl.replace bound address server;
    Result.Ok server
  end
let listen ~sw server (cb: flow -> unit) =
  let listen_cb () =
    let flow = openflow server.address in
    Eio.Fiber.fork ~sw
      (fun () ->
         try
          cb (otherend flow)
         with _e -> ()
      );
    Result.Ok flow in
  server.listen_cb <- listen_cb
let shutdown server =
  server.listen_cb <- (fun _ -> Result.Error (`Msg "shutdown"));
  Hashtbl.remove bound server.address
