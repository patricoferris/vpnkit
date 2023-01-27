module Make (Netif: Mirage_net.S): sig
  type t

  val make: mono:Eio.Time.Mono.t -> configuration:Configuration.t -> Netif.t -> t
  (** Create a DHCP server. *)

  val callback: t -> Cstruct.t -> unit
end

val update_global_configuration: Configuration.Dhcp_configuration.t option -> unit
(** Update the global DHCP configuration: gateway IP, search domains etc *)