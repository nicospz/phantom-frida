		internal static async RemoteAgent start (LoaderLaunch launch, InjectSpec spec, uint pid, BootstrapResult bres,
				UnixConnection frida_ctrl, UnixConnection? agent_ctrl, Cancellable? cancellable) throws Error, IOError {
			var agent = new RemoteAgent (pid, spec, bres, frida_ctrl, agent_ctrl);

			try {
				var io_priority = Priority.DEFAULT;

				if (launch == FROM_SCRATCH)
					frida_ctrl.send_fd (spec.library_so.get_fd (), cancellable);

				if (agent.agent_ctrlfd_for_peer != null) {
					frida_ctrl.send_fd (agent.agent_ctrlfd_for_peer.handle, cancellable);
					agent.agent_ctrlfd_for_peer = null;
				} else {
					yield frida_ctrl.get_output_stream ().write_async ({ 0 }, io_priority, cancellable);
				}
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
				throw new Error.TRANSPORT ("%s", e.message);
			}

			agent.monitor.begin ();
			Future<bool> started = agent.start_request.future;
			yield started.wait_async (cancellable);
			return agent;
		}

		public void ack () {
			uint8 raw_type = HelperMessageType.ACK;
			frida_ctrl.get_output_stream ().write_all_async.begin ((uint8[]) &raw_type, Priority.DEFAULT, null);
		}

		private async void monitor () {
			Error? pending_start_error = null;
			try {
				var unload_policy = UnloadPolicy.IMMEDIATE;

				InputStream input = frida_ctrl.get_input_stream ();
				var io_priority = Priority.DEFAULT;
				size_t n;

				bool done = false;
				HelperHelloMessage? hello = null;
				HelperByeMessage? bye = null;
				do {
					uint8 raw_type = 0;
					yield input.read_all_async ((uint8[]) &raw_type, io_priority, io_cancellable, out n);
					if (n == 0)
						break;
					var type = (HelperMessageType) raw_type;

					switch (type) {
						case HELLO: {
							var m = HelperHelloMessage ();
							yield input.read_all_async ((uint8[]) &m, io_priority, io_cancellable, out n);
							if (n == 0)
								break;
							hello = m;

							break;
						}
						case READY: {
							if (start_request != null) {
								start_request.resolve (true);
								start_request = null;
							}
							break;
						}
						case BYE: {
							done = true;

							var m = HelperByeMessage ();
							yield input.read_all_async ((uint8[]) &m, io_priority, io_cancellable, out n);
							if (n == 0)
								break;
							bye = m;

							break;
						}
						case ERROR_DLOPEN:
						case ERROR_DLSYM: {
							uint16 length = 0;
							yield input.read_all_async ((uint8[]) &length, io_priority, io_cancellable, out n);
							if (n == 0)
								break;

							var data = new uint8[length + 1];
							yield input.read_all_async (data[:length], io_priority, io_cancellable, out n);
							if (n == 0)
								break;
							data[length] = 0;

							unowned string message = (string) data;

							pending_start_error = new Error.INVALID_ARGUMENT ("%s", message);

							break;
						}
						default:
							break;
					}
				} while (!done);

				if (bye != null)
					unload_policy = bye.unload_policy;

				if (hello != null) {
					string thread_path = "/proc/%u/task/%u".printf (pid, hello.thread_id);
					while (FileUtils.test (thread_path, EXISTS)) {
						var source = new TimeoutSource (50);
						source.set_callback (monitor.callback);
						source.attach (MainContext.get_thread_default ());
						yield;
					}
				}

				on_stop (unload_policy);
			} catch (GLib.Error e) {
				if (!(e is IOError.CANCELLED))
					on_stop (IMMEDIATE);
			} finally {
				if (start_request != null) {
					Error error = (pending_start_error != null)
						? pending_start_error
						: new Error.TRANSPORT ("Agent connection closed unexpectedly");
					start_request.reject (error);
					start_request = null;
				}
			}

			cancel_request.resolve (true);
		}

	protected enum HelperMessageType {
		HELLO,
		READY,
		ACK,
		BYE,
		ERROR_DLOPEN,
		ERROR_DLSYM
	}

