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

type inner_flow = {
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
  mutable unread : Cstruct.t option;
}

type flow = <
  Eio.Flow.two_way;
  Eio.Flow.close;
  expose : inner_flow
>

let get_flow t = Some (t :> <Eio.Flow.two_way; Eio.Flow.close>)

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
  { l2r; r2l; l2r_c; r2l_c; l2r_m; r2l_m; l2r_closed; r2l_closed; client_address; server_address; unread = None }

let otherend flow =
  { l2r = flow.r2l; l2r_c = flow.r2l_c; r2l = flow.l2r; r2l_c = flow.l2r_c;
    l2r_closed = flow.r2l_closed; r2l_closed = flow.l2r_closed;
    l2r_m = flow.l2r_m; r2l_m = flow.r2l_m;
    client_address = flow.server_address; server_address = flow.client_address; unread = flow.unread }

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
    let d = Lwt_dllist.take_r flow.r2l in
    Ok (`Data d)
  end 

let write flow buf =
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

let make t =
  object (self)
    inherit Eio.Flow.two_way

    method expose = t

    method close = close t

    (* Because of the already existing API, I've added this
       strange workaround to mimic how the old reading worked
       by storing unread data. *)
    method read_into v =
      match t.unread with
      | Some buf ->
          if t.r2l_closed then raise End_of_file else
          let size = Cstruct.length v in
          let unread_size =  Cstruct.length buf in
          (if size >= unread_size then t.unread <- None else t.unread <- Some (Cstruct.sub buf size (unread_size - size)));
          Cstruct.blit buf 0 v 0 (min unread_size size);
          min unread_size size
      | None -> 
        match read t with
        | Ok (`Data buf) ->
          let unread_size = Cstruct.length buf in
          let size = Cstruct.length v in
          (if size >= unread_size then t.unread <- None else t.unread <- Some (Cstruct.sub buf size (unread_size - size)));
          Cstruct.blit buf 0 v 0 (min unread_size size);
          min unread_size size
        | Ok `Eof -> raise End_of_file
        | Error _ -> failwith "Error"

    method write buf = 
      match write t (Cstruct.concat buf) with
      | Ok () -> ()
      | Error `Closed -> failwith "Closed!"

    (* For now we rely on not copying data *)
    method copy src = assert false

    method shutdown = function
      | `Send -> shutdown_write t
      | `Receive -> shutdown_read t
      | `All ->
        shutdown_read t;
        shutdown_write t 
  end

let of_address address =
  let t = openflow address in
  make t

let otherend flow =
  let t = flow#expose in
  make (otherend t)

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
let listen ~sw server cb =
  let listen_cb () =
    let flow = of_address server.address in
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