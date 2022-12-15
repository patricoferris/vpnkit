(*
 * Copyright (C) 2017 Docker Inc
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

(* A fake Time and Clock module for testing the timing without having to actually
   wait. *)
open Eio

module Clock = struct

  type t = <
        Eio.Time.clock;
        advance : float -> unit;
        reset : unit;
    >

  let make () =
    object (_self)
      inherit Eio.Time.clock

      val mutable now = 0.0
      val c = Eio.Condition.create ()

      method now = now

      method reset = now <- 0.0; Condition.broadcast c 

      method advance secs = 
        now <- now +. secs;
        Condition.broadcast c

      method sleep_until time =
          (* All sleeping is relative to the start of the program for now *)
          (* let v = 0. in *)
          let rec loop () =
            if Float.compare now time > 0 then () else (
              Condition.await_no_mutex c;
              loop ()
            ) in
          loop ()
    end

  let advance t n = t#advance n
  let reset t = t#reset
end
