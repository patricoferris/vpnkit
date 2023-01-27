val default_etc_hosts_path: string
(** Default path where /etc/hosts should be on this machine *)

val etc_hosts: (string * Ipaddr.t) list ref
(** The current contents of the hosts file *)

val of_string: string -> (string * Ipaddr.t) list
(** Parse the contents of a hosts file *)

module Make(Files: Sig.FILES): sig

  type watch

  val watch: sw:Eio.Switch.t -> fs:Eio.Fs.dir Eio.Path.t -> ?path:string -> unit -> (watch, [ `Msg of string ]) result
  (** Start watching the hosts file, updating the [etc_hosts] binding in the
      background. The [?path] argument allows the location of the hosts file
      to be overriden. This blocks until the watch has been established. *)

  val unwatch: watch -> unit
  (** Stop watching the hosts file *)

end
