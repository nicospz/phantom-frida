		public async ProcessCodeSwapScope (SeizeSession session, uint8[] code, Cancellable? cancellable) throws Error, IOError {
			this.session = session;

			Gum.Linux.enumerate_ranges ((Posix.pid_t) session.pid, READ | EXECUTE, d => {
				unowned Gum.FileMapping? file = d.file;
				if (file != null && file.path.has_prefix ("memfd:"))
					return true;
				if (d.range.size >= code.length) {
					code_start = d.range.base_address + d.range.size - round_size_to_page_size (code.length);
					code_end = code_start + code.length;
				}
				return code_start == 0;
			});
			if (code_start == 0)
				throw new Error.NOT_SUPPORTED ("Unable to find suitable code pages");

			thread_suspend_scope = new ThreadSuspendScope (session.pid);
			thread_suspend_scope.exclude (session.tid);
			yield thread_suspend_scope.enable (cancellable);

			original_code = session.read_memory (code_start, code.length);
			session.write_memory (code_start, code);
			state = ACTIVE;
		}
