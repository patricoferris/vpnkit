(* VPNKIT flows which are Eio flows but with a read method
   that returns a buffer rather than fills it. *)

include Eio.Flow

class virtual r = object (_)
  method virtual read : Cstruct.t
end

class virtual rw = object (_ : <r; sink; ..>)
  inherit sink
  method virtual shutdown : shutdown_command -> unit
end

let read (rw : #rw) = rw#read
let shutdown (rw : #rw) = rw#shutdown