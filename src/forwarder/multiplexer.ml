let src =
  let src = Logs.Src.create "multiplexer" ~doc:"multiplex flows" in
  Logs.Src.set_level src (Some Logs.Info) ;
  src

module Log = (val Logs.src_log src : Logs.LOG)

module Make (Flow : Mirage_flow.S) = struct
  module Window = struct
    type t =
      { mutable current_seq: int64
      ; (* highest sequence number read *)
        mutable allowed_seq: int64
      (* other end is allowed to write *) }

    let create () = {current_seq= 0L; allowed_seq= 0L}

    let size t = Int64.(to_int @@ sub t.allowed_seq t.current_seq)

    (* Advertise more window if there is buffer space available *)
    let advertise t max_buffer_size =
      (* The amount that we allow the remote to consume: *)
      let allowed = size t in
      (* If the amount is less than half of the max_buffer_size, recommend a window update *)
      if allowed < max_buffer_size / 2 then (
        let new_allowed_seq =
          Int64.(add t.current_seq (of_int max_buffer_size))
        in
        t.allowed_seq <- new_allowed_seq ;
        Some new_allowed_seq )
      else None

    let receive t new_allowed_seq = t.allowed_seq <- new_allowed_seq

    let advance t by = t.current_seq <- Int64.(add t.current_seq (of_int by))
  end

  module Subflow = struct
    type t =
      { read: Window.t
      ; write: Window.t
      ; mutable incoming: Cstruct.t list
      ; mutable incoming_shutdown: bool
      ; incoming_c: Eio.Condition.t
      ; write_c: Eio.Condition.t
      ; mutable close_sent: bool
      ; mutable close_received: bool
      ; mutable shutdown_sent: bool
      ; mutable ref_count: int }

    let create () =
      { read= Window.create ()
      ; write= Window.create ()
      ; incoming= []
      ; incoming_shutdown= false
      ; incoming_c= Eio.Condition.create ()
      ; write_c= Eio.Condition.create ()
      ; close_sent= false
      ; close_received= false
      ; shutdown_sent= false
      ; ref_count= 2 (* sender + receiver *) }
  end

  module C = Mirage_channel.Make (Flow)

  exception Multiplexer_failed

  type outer =
    { label: string
    ; (* for debug logging *)
      channel: C.t
    ; flow: Flow.flow
    ; m: Eio.Mutex.t
    ; (* held when writing frames *)
      subflows: (int32, Subflow.t) Hashtbl.t
    ; mutable next_subflowid: int32
    ; max_buffer_size: int
    ; mutable running: bool }

  (* When the refcount goes to 0 i.e. when both the sender and receiver side
     have sent Close, then we can mark the id as free. *)
  let decr_refcount outer id =
    if Hashtbl.mem outer.subflows id then begin
      let flow = Hashtbl.find outer.subflows id in
      if flow.ref_count = 1 then begin
        Log.debug (fun f -> f "%s: forgetting flow %ld" outer.label id) ;
        Hashtbl.remove outer.subflows id
      end else begin
        flow.ref_count <- flow.ref_count - 1
      end
    end

  let send outer frame =
    Log.debug (fun f -> f "%s: send %s" outer.label (Frame.to_string frame)) ;
    let buf = Cstruct.create @@ Frame.sizeof frame in
    let header = Frame.write frame buf in
    C.write_buffer outer.channel header

  let flush outer =
    Eio.Mutex.use_ro outer.m (fun () ->
        match C.flush outer.channel with
        | Ok () -> () | Error _ -> raise Multiplexer_failed );
    Log.debug (fun f -> f "%s: flushed" outer.label)

  module Channel = struct
    type channel = {outer: outer; id: int32; subflow: Subflow.t}

    let send_window_update channel =
      match
        Window.advertise channel.subflow.Subflow.read
          channel.outer.max_buffer_size
      with
      | None -> ()
      | Some seq ->
          send channel.outer Frame.{command= Window seq; id= channel.id};
          flush channel.outer

    let create outer id =
      let subflow = Subflow.create () in
      Hashtbl.add outer.subflows id subflow ;
      let channel = {outer; id; subflow} in
      send_window_update channel;
      channel

    let connect outer destination =
      let find_free_flowid outer =
        let rec loop from =
          if Hashtbl.mem outer.subflows from then loop (Int32.succ from)
          else from
        in
        let id = loop outer.next_subflowid in
        outer.next_subflowid <- Int32.succ id ;
        id
      in
      let id = find_free_flowid outer in
      send outer Frame.{command= Open (Multiplexed, destination); id} ;
      create outer id

    let is_read_eof channel =
      false
      || channel.subflow.Subflow.incoming_shutdown
      || channel.subflow.Subflow.close_received

    let rec read_into channel buf =
      let rec wait () =
        match channel.subflow.Subflow.incoming with
        | [] ->
            if is_read_eof channel
            then Ok `Eof
            else begin
              Eio.Condition.await_no_mutex channel.subflow.Subflow.incoming_c;
              wait ()
            end
        | first :: rest ->
            let num_from_first = min (Cstruct.length first) (Cstruct.length buf) in
            Cstruct.blit first 0 buf 0 num_from_first;
            let buf = Cstruct.shift buf num_from_first in
            let first = Cstruct.shift first num_from_first in
            Window.advance channel.subflow.Subflow.read num_from_first;
            (channel.subflow).Subflow.incoming <-
              if Cstruct.length first = 0
              then rest
              else first :: rest;
            if Cstruct.length buf = 0 then begin
              send_window_update channel;
              Ok (`Data ())
            end else read_into channel buf
      in
      wait ()

    let read channel =
      let rec wait () =
        match channel.subflow.Subflow.incoming with
        | [] ->
            if is_read_eof channel
            then Ok `Eof
            else begin
              Eio.Condition.await_no_mutex channel.subflow.Subflow.incoming_c;
              wait ()
            end
        | bufs ->
            (channel.subflow).Subflow.incoming <- [] ;
            let len = List.fold_left ( + ) 0 (List.map Cstruct.length bufs) in
            Window.advance channel.subflow.Subflow.read len ;
            send_window_update channel;
            Ok (`Data (Cstruct.concat bufs))
      in
      wait ()

    let is_write_eof channel =
      false
      || channel.subflow.Subflow.close_received
      || channel.subflow.Subflow.close_sent
      || channel.subflow.Subflow.shutdown_sent

    let writev channel bufs =
      let rec loop bufs =
        let rec wait () =
          if
            Window.size channel.subflow.Subflow.write = 0
            && not (is_write_eof channel)
          then begin
            Eio.Condition.await_no_mutex channel.subflow.Subflow.write_c;
            wait ()
          end
          else ()
        in
        wait ();
        if is_write_eof channel then `Eof
        else
          let len = Window.size channel.subflow.Subflow.write in
          let to_send, remaining =
            if Cstructs.len bufs <= len then (bufs, [])
            else (Cstructs.sub bufs 0 len, Cstructs.shift bufs len)
          in
          List.iter
            (fun buf ->
              (* Note the other end may have transmitted a Close.
                 It has to be able to cope with unexpected Data. *)
              send channel.outer
                Frame.
                  { command= Data (Int32.of_int (Cstruct.length buf))
                  ; id= channel.id } ;
              C.write_buffer channel.outer.channel buf )
            to_send ;
          flush channel.outer;
          if remaining = [] then `Ok else loop remaining
      in
      let _ = loop bufs in
      (* FIXME: consider `Eof *)
      Ok ()

    let shutdown_write channel =
      (* Avoid sending Shutdown twice or sending a shutdown after a Close *)
      if is_write_eof channel
      then ()
      else begin
        channel.subflow.Subflow.shutdown_sent <- true;
        send channel.outer Frame.{command= Shutdown; id= channel.id} ;
        flush channel.outer
      end

    let close channel =
      (* Don't send Close more than once *)
      if channel.subflow.Subflow.close_sent
      then ()
      else begin
        (channel.subflow).Subflow.close_sent <- true ;
        send channel.outer Frame.{command= Close; id= channel.id} ;
        decr_refcount channel.outer channel.id ;
        flush channel.outer
      end

    (* boilerplate: *)
    let shutdown_read _chanel = ()

    let write channel buf = writev channel [buf]

    type flow = channel

    let pp_error = Flow.pp_error

    let pp_write_error = Flow.pp_write_error

    type error = Flow.error

    type write_error = Flow.write_error
  end

  type flow = outer

  let is_running flow = flow.running

  type listen_cb = Channel.flow -> Frame.Destination.t -> unit

  let connect ~sw flow label listen_cb =
    let channel = C.create flow in
    let m = Eio.Mutex.create () in
    let subflows = Hashtbl.create 7 in
    let next_subflowid = Int32.max_int in
    let max_buffer_size = 65536 in
    let outer =
      {label; channel; flow; m; subflows; next_subflowid; max_buffer_size; running = true}
    in
    (* Process incoming data, window advertisements *)
    let handle_one () =
      match C.read_exactly ~len:2 channel with
      | Error _ ->
          Log.err (fun f -> f "%s: error while reading frame length" label) ;
          false
      | Ok `Eof ->
          Log.err (fun f -> f "%s: EOF reading frame length" label) ;
          false
      | Ok (`Data bufs) -> (
          let buf = Cstruct.concat bufs in
          let len = Cstruct.LE.get_uint16 buf 0 in
          match C.read_exactly ~len:(len - 2) channel with
          | Error _ ->
              Log.err (fun f ->
                  f "%s: error while reading frame header (length %d)" label
                    len ) ;
              false
          | Ok `Eof ->
              Log.err (fun f ->
                  f "%s: EOF reading frame header (length %d)" label len ) ;
              false
          | Ok (`Data rest) -> (
              let header = Cstruct.concat (bufs @ rest) in
              try
                let open Frame in
                let frame = read header in
                Log.debug (fun f -> f "%s: recv %s" label (to_string frame)) ;
                match frame.command with
                | Open (Dedicated, _) ->
                    failwith "dispatcher lacks support for dedicated mode"
                | Open (Multiplexed, destination) ->
                    let channel = Channel.create outer frame.id in
                    Eio.Fiber.fork ~sw (fun () -> listen_cb channel destination) ;
                    true
                | Close ->
                    let subflow = Hashtbl.find subflows frame.id in
                    subflow.Subflow.close_received <- true ;
                    (* Unblock any waiting read *)
                    Eio.Condition.signal subflow.incoming_c;
                    (* Unblock any waiting write *)
                    Eio.Condition.signal subflow.write_c;
                    decr_refcount outer frame.id ;
                    true
                | Shutdown ->
                    let subflow = Hashtbl.find subflows frame.id in
                    subflow.Subflow.incoming_shutdown <- true ;
                    (* Unblock any waiting read *)
                    Eio.Condition.signal subflow.incoming_c;
                    true
                | Data len -> (
                    let subflow = Hashtbl.find subflows frame.id in
                    let len = Int32.to_int len in
                    match C.read_exactly ~len channel with
                    | Error _ ->
                        Log.err (fun f ->
                            f "%s: error while reading payload (length %d)"
                              label len ) ;
                        false
                    | Ok `Eof ->
                        Log.err (fun f ->
                            f "%s: EOF while reading payload (length %d)" label
                              len ) ;
                        false
                    | Ok (`Data bufs) ->
                        subflow.Subflow.incoming
                        <- subflow.Subflow.incoming @ bufs ;
                        (* Unblock any waiting read *)
                        Eio.Condition.signal subflow.incoming_c;
                        true )
                | Window seq ->
                    let subflow = Hashtbl.find subflows frame.id in
                    Window.receive subflow.Subflow.write seq ;
                    (* Unblock any waiting write *)
                    Eio.Condition.signal subflow.write_c;
                    true
              with e ->
                Log.err (fun f ->
                    f "%s: error handling frame: %s" label
                      (Printexc.to_string e) ) ;
                false ) )
    in
    let rec dispatcher () =
      match handle_one () with
      | false ->
          Log.err (fun f -> f "%s: dispatcher shutting down" label) ;
          outer.running <- false
      | true -> dispatcher ()
    in
    Eio.Fiber.fork ~sw dispatcher;
    outer

  let disconnect m = Flow.close m.flow
end
