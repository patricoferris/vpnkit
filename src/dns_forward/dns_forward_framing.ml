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

let src =
  let src = Logs.Src.create "Dns_forward" ~doc:"DNS framing" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

module type S = Dns_forward_s.READERWRITER

module Tcp = struct
  let errorf = Dns_forward_error.errorf

  type request = Cstruct.t
  type response = Cstruct.t
  type flow = <Flow.two_way; Flow.close>
  type t = { flow : flow; buf : Eio.Buf_read.t; write_m : Eio.Mutex.t; read_m : Eio.Mutex.t }

  let connect flow =
    let write_m = Eio.Mutex.create () in
    let read_m = Eio.Mutex.create () in
    let buf = Eio.Buf_read.of_flow ~max_size:max_int flow in
    { flow; write_m; read_m; buf }

  let close t = Flow.close t.flow

  let read t =
    Eio.Mutex.use_rw ~protect:false t.read_m (fun () ->
        try
          let buf = Cstruct.create 2 in 
          Flow.read_exact t.flow buf;
          let len = Cstruct.BE.get_uint16 buf 0 in
          let data = Cstruct.create len in
          Flow.read_exact t.flow data;
          Ok data
        with
          | End_of_file -> errorf "Got EOF while reading the response header"
          | e -> errorf "Reading %a" Fmt.exn e
    )

  let write t buffer =
    Eio.Mutex.use_rw ~protect:false t.write_m (fun () ->
        (* RFC 1035 4.2.2 TCP Usage: 2 byte length field *)
        try
          let header = Cstruct.create 2 in
          Cstruct.BE.set_uint16 header 0 (Cstruct.length buffer);
          Flow.write t.flow [ header; buffer ];
          Ok ()
        with
        | e ->
            errorf "Failed to write %d bytes: %a" (Cstruct.length buffer)
              Fmt.exn e)
end

module Udp = struct
  module Error = Dns_forward_error.Infix

  let errorf = Dns_forward_error.errorf

  type request = Cstruct.t
  type response = Cstruct.t
  type flow = <Flow.two_way; Flow.close>
  type t = flow

  let connect flow = flow
  let close t = Flow.close t

  (* TODO: Is this a hack for handling datagrams as flows?! *)
  let read t =
    let buf = Cstruct.create 65507 in
    try 
      let i = Flow.single_read t buf in
      Ok (Cstruct.sub buf 0 i)
    with
    | End_of_file -> errorf "read: Eof"
    | exn -> errorf "read: %a" Exn.pp exn

  let write (t : flow) buf =
    Flow.write t [ buf ];
    Ok ()
end
