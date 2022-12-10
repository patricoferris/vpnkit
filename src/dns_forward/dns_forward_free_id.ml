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

module IntSet = Set.Make (struct
  type t = int

  let compare (a : int) (b : int) = compare a b
end)

(* track the ids in use to
   - avoid accidental re-use
   - limit the total number of simultaneous upstream requests
*)
type t = {
  mutable used_ids : IntSet.t; (* used by in-progress requests *)
  max_elements : int; (* bound on the number of in-progress requests *)
  free_ids_c : Eio.Condition.t;
  g : int -> int; (* generate unpredictable id *)
}

let make ~g ?(max_elements = 512) () =
  let used_ids = IntSet.empty in
  let free_ids_c = Eio.Condition.create () in
  { max_elements; used_ids; free_ids_c; g }

let rec with_id t f =
  if IntSet.cardinal t.used_ids = t.max_elements then (
    Condition.await_no_mutex t.free_ids_c;
    with_id t f)
  else
    let rec find_free_id () =
      (* [gen n] picks a value in the interval [0, n-1]. DNS transaction
         ids are between [0, 0xffff] *)
      let id = t.g 0x10000 in
      if IntSet.mem id t.used_ids then find_free_id () else id
    in
    let free_id = find_free_id () in
    t.used_ids <- IntSet.add free_id t.used_ids;
    Fun.protect
      (fun () -> f free_id)
      ~finally:(fun () ->
        t.used_ids <- IntSet.remove free_id t.used_ids;
        Condition.broadcast t.free_ids_c)
