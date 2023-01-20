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
open Eio

module type Comparable = sig
  type t

  val compare : t -> t -> int
end

module type FLOW_CLIENT = sig
  type address

  val connect :
    sw:Eio.Switch.t ->
    net:Eio.Net.t ->
    ?read_buffer_size:int ->
    address ->
    (<Iflow.rw; Flow.two_way; Flow.close>, [ `Msg of string ]) result
end

module type FLOW_SERVER = sig
  type server

  type address

  val bind :
    sw:Eio.Switch.t ->
    Eio.Net.t ->
    address ->
    (server, [ `Msg of string ]) result

  val getsockname : server -> address

  val listen : sw:Eio.Switch.t -> server -> (<Iflow.rw; Flow.two_way; Flow.close> -> unit) -> unit
  val shutdown : server -> unit
end

module type RPC_CLIENT = sig
  type request = Cstruct.t
  type response = Cstruct.t
  type address = Dns_forward_config.Address.t
  type t

  type message_cb =
    ?src:address -> ?dst:address -> buf:Cstruct.t -> unit -> unit

  val connect :
    gen_transaction_id:(int -> int) ->
    ?message_cb:message_cb ->
    address ->
    (t, [ `Msg of string ]) result

  val rpc :
    sw:Eio.Switch.t ->
    Eio.Time.clock ->
    Eio.Net.t ->
    t ->
    request ->
    (response, [ `Msg of string ]) result

  val disconnect : t -> unit
end

module type RPC_SERVER = sig
  type request = Cstruct.t
  type response = Cstruct.t
  type address = Dns_forward_config.Address.t
  type server

  val bind :
    sw:Eio.Switch.t ->
    Eio.Net.t ->
    address ->
    (server, [ `Msg of string ]) result

  val listen :
    sw:Eio.Switch.t ->
    server ->
    (request -> (response, [ `Msg of string ]) result) ->
    (unit, [ `Msg of string ]) result

  val shutdown : server -> unit
end

module type RESOLVER = sig
  type t
  type address = Dns_forward_config.Address.t

  type message_cb =
    ?src:address -> ?dst:address -> buf:Cstruct.t -> unit -> unit

  val create :
    ?local_names_cb:(Dns.Packet.question -> Dns.Packet.rr list option) ->
    sw:Eio.Switch.t ->
    gen_transaction_id:(int -> int) ->
    ?message_cb:message_cb ->
    Dns_forward_config.t ->
    t

  val destroy : t -> unit

  val answer :
    sw:Eio.Switch.t ->
    net:Eio.Net.t ->
    mono:Eio.Time.Mono.t ->
    clock:Eio.Time.clock ->
    Cstruct.t ->
    t ->
    (Cstruct.t, [ `Msg of string ]) result
end

module type SERVER = sig
  type t
  type resolver

  val create : resolver -> t

  val serve :
    sw:Eio.Switch.t ->
    net:Eio.Net.t ->
    mono:Eio.Time.Mono.t ->
    clock:Eio.Time.clock ->
    address:Dns_forward_config.Address.t ->
    t ->
    (unit, [ `Msg of string ]) result

  val destroy : t -> unit
end

module type READERWRITER = sig
  type request = Cstruct.t
  (** Read and write DNS packets from a flow *)

  type response = Cstruct.t
  type t

  val connect : <Iflow.rw; Eio.Flow.two_way; Eio.Flow.close> -> t
  val read : t -> (request, [ `Msg of string ]) result
  val write : t -> response -> (unit, [ `Msg of string ]) result
  val close : t -> unit
end
