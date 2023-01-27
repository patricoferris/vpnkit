let src =
  let src =
    Logs.Src.create "/etc/hosts" ~doc:"monitor and read the /etc/hosts file"
  in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let default_etc_hosts_path =
  if Sys.os_type = "Win32"
  then "C:\\Windows\\System32\\drivers\\etc\\hosts"
  else "/etc/hosts"

let etc_hosts = ref []

let of_string txt =
  let open Astring in
  try
    let lines = String.cuts ~sep:"\n" txt in
    List.fold_left (fun acc line ->
        let line = String.trim line in
        if line = "" then acc else begin
          let line = match String.cut ~sep:"#" line with
          | None -> line
          | Some (important, _) -> important
          in
          let whitespace = function
          | ' ' | '\n' | '\011' | '\012' | '\r' | '\t' -> true
          | _ -> false
          in
          match String.fields ~empty:false ~is_sep:whitespace line with
          | addr :: names ->
            begin match Ipaddr.of_string addr with
            | Ok addr -> List.map (fun name -> (name, addr)) names @ acc
            | Error (`Msg m) ->
              Log.err (fun f ->
                  f "Failed to parse address '%s' from hosts file: %s" addr m);
              acc
            end
          | _ -> acc
        end
      ) [] lines
    |> List.rev
  with _ -> []

module Make(Files: Sig.FILES) = struct

  let m = Eio.Mutex.create ()

  let parse filename =
    Eio.Mutex.use_ro m (fun () ->
        match Files.read_file filename with
        | exception msg ->
          Log.err (fun f -> f "Failed to read %s: %a" (snd filename) Fmt.exn msg)
        | txt ->
          etc_hosts := of_string txt;
          Log.info (fun f ->
              f "%s file has bindings for %s"
                (snd filename)
                (String.concat " " @@ List.map fst !etc_hosts))
      )

  type watch = Files.watch

  let watch ~sw ~fs ?(path = default_etc_hosts_path) () =
    let path = Eio.Path.(fs / path) in
    Files.watch_file path (fun () -> Eio.Fiber.fork ~sw (fun () -> parse path))

  let unwatch = Files.unwatch

end
