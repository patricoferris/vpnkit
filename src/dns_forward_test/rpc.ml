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

type request = Cstruct.t
type response = Cstruct.t
type address = Config.Address.t
let string_of_address a = Ipaddr.to_string a.Config.Address.ip ^ ":" ^ (string_of_int a.Config.Address.port)

type cb = request -> (response, [ `Msg of string ]) result

type message_cb = ?src:address -> ?dst:address -> buf:Cstruct.t -> unit -> unit

type t = {
  mutable cb: cb;
  client_address: address;
  server_address: address;
  message_cb: message_cb;
}

let rpc ~sw:_ _clock _net t request =
  t.message_cb ~src:t.client_address ~dst:t.server_address ~buf:request ();
  t.cb request
  |> function
  | Result.Ok response ->
      t.message_cb ~src:t.server_address ~dst:t.client_address ~buf:response ();
      Result.Ok response
  | Result.Error e ->
      Result.Error e

let nr_connects = Hashtbl.create 7

let get_connections () = Hashtbl.fold (fun k v acc -> (k, v) :: acc) nr_connects []

let disconnect t =
  let nr = Hashtbl.find nr_connects t.server_address - 1 in
  if nr = 0 then Hashtbl.remove nr_connects t.server_address else Hashtbl.replace nr_connects t.server_address nr;
  t.cb <- (fun _ -> Result.Error (`Msg "disconnected"))

type server = {
  mutable listen_cb: cb;
  address: address;
}
let bound = Hashtbl.create 7

let connect ~gen_transaction_id:_ ?(message_cb = (fun ?src:_ ?dst:_ ~buf:_ () -> ())) address =
  (* Use a fixed client address for now *)
  let client_address = { Config.Address.ip = Ipaddr.of_string_exn "1.2.3.4"; port = 32768 } in
  if Hashtbl.mem bound address then begin
    Hashtbl.replace nr_connects address (if Hashtbl.mem nr_connects address then Hashtbl.find nr_connects address else 1);
    let cb = (Hashtbl.find bound address).listen_cb in
    Result.Ok { cb; client_address; server_address = address; message_cb }
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
let listen ~sw:_ server cb =
  server.listen_cb <- cb;
  Result.Ok ()
let shutdown server =
  server.listen_cb <- (fun _ -> Result.Error (`Msg "shutdown"));
  Hashtbl.remove bound server.address
