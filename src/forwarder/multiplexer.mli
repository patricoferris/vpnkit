open Eio
type flow

module Channel : sig
  type channel

  val connect : flow -> Frame.Destination.t -> channel

  include Mirage_flow_combinators.SHUTDOWNABLE with type flow = channel

  val read_into: channel -> Cstruct.t -> (unit Mirage_flow.or_eof, error) result

  val to_flow : channel -> <Eio.Flow.two_way; read : Cstruct.t>
end

type listen_cb = Channel.flow -> Frame.Destination.t -> unit

val connect : sw:Eio.Switch.t -> Flow.two_way -> string -> listen_cb -> flow

val is_running : flow -> bool
(** [is_running flow] is true if the dispatcher thread is still running. *)

val disconnect: flow -> unit
(** [disconnect flow] disconnects the underlying flow *)
