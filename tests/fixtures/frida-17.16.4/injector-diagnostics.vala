		private AttachState attach_state = ALREADY_ATTACHED;
		private uint _tid;
		protected GPRegs saved_regs;

		private static bool seize_supported;

		public async RemoteAgent inject (InjectSpec spec, Cancellable? cancellable) throws Error, IOError {
			try {
				write_memory (loader_base, loader_code);
				write_memory (loader_base + loader_layout.ctx_offset, (uint8[]) &loader_ctx);
				write_memory (loader_base + loader_layout.libc_api_offset, (uint8[]) &bootstrap_result.libc);
				write_memory_string (loader_base + loader_layout.agent_entrypoint_offset, spec.entrypoint);
				write_memory_string (loader_base + loader_layout.agent_data_offset, spec.data);
				write_memory_string (loader_base + loader_layout.fallback_address_offset, fallback_address);
			}
		}

		public async RemoteAgent rejuvenate (RemoteAgent old_agent, Cancellable? cancellable) throws Error, IOError {
			write_memory (loader_base + loader_layout.fallback_address_offset, fallback_address.data);
		}

		private async BootstrapResult bootstrap (size_t loader_size, Cancellable? cancellable) throws Error, IOError {
			var remote_maps = ProcMapsSnapshot.from_pid (pid);
			var remote_libc = remote_maps.find_module_by_path (local_libc.path);
			uint64 remote_mmap = 0;
			uint64 remote_munmap = 0;
#if ANDROID
			bool same_libc = remote_libc != null
					&& remote_libc.device.major == local_libc.device.major
					&& remote_libc.inode == local_libc.inode
					&& remote_libc.path == local_libc.path;
#else
			bool same_libc = remote_libc != null
					&& remote_libc.device.equals (local_libc.device)
					&& remote_libc.inode == local_libc.inode
					&& remote_libc.path == local_libc.path;
#endif
			if (same_libc) {
				remote_mmap = remote_libc.start + mmap_offset;
				remote_munmap = remote_libc.start + munmap_offset;
			}

			if (remote_mmap != 0) {
			} else {
				var bootstrap_ctx = HelperBootstrapContext ();
				bootstrap_ctx.allocation_size = allocation_size;
				write_memory (bootstrap_ctx_location, (uint8[]) &bootstrap_ctx);
			}

			try {
				write_memory (allocation_base, bootstrapper_code);
					var bootstrap_ctx = HelperBootstrapContext ();
					bootstrap_ctx.libc = (HelperLibcApi *) libc_api_location;
					write_memory (bootstrap_ctx_location, (uint8[]) &bootstrap_ctx);
					write_memory (fallback_ld_location, fallback_ld_cstr);
					write_memory (fallback_libc_location, fallback_libc_cstr);
			}
		}

		private void maybe_fixup_helper_code (uint64 base_address, uint8[] code) throws Error {
#if MIPS
			write_memory (base_address + code.length - entries_size, entries);
#endif
		}

		public async void resume_until_execution_reaches (uint64 target, Cancellable? cancellable) throws Error, IOError {
			write_memory (target_address, breakpoint_data);
			try {
				write_memory (target_address, original_code);
			} finally {
				try {
						write_memory (target_address, original_code);
				} catch (Error e) {
				}
			}
		}

		public void write_memory (uint64 address, uint8[] data) throws Error {
			if (data.length == 0)
				return;

#if X86 || X86_64
			if (process_vm_writev != null) {
				var local = Posix.iovector ();
				local.iov_base = data;
				local.iov_len = data.length;

				var remote = Posix.iovector ();
				remote.iov_base = (void *) address;
				remote.iov_len = data.length;

				ssize_t res = process_vm_writev (pid, (Posix.iovector[]) &local, (Posix.iovector[]) &remote, 0);
				if (res != -1)
					return;
				if (errno == Posix.ENOSYS)
					process_vm_writev = null;
				else if (errno != Posix.EPERM && errno != Posix.EFAULT)
					throw new Error.NOT_SUPPORTED ("Unable to write to process memory: %s", strerror (errno));
			}
#endif

			size_t offset = 0;
			size_t size = data.length;
			uint bytes_per_word = (uint) sizeof (size_t);
			while (offset != size) {
				size_t word = 0;
				size_t chunk_size = size_t.min (size - offset, bytes_per_word);
				if (chunk_size < bytes_per_word)
					word = (size_t) ptrace (PEEKDATA, tid, (void *) (address + offset));
				Memory.copy (&word, (uint8 *) data + offset, chunk_size);

				ptrace (POKEDATA, tid, (void *) (address + offset), (void *) word);

				offset += chunk_size;
			}
		}

		public void write_memory_string (uint64 address, string str) throws Error {
			unowned uint8[] data = str.data;
			write_memory (address, data[:data.length + 1]);
		}

	public async ProcessCodeSwapScope (SeizeSession session, uint8[] code, Cancellable? cancellable) throws Error, IOError {
			session.write_memory (code_start, code);
	}

	public void revert () throws Error {
				session.write_memory (code_start, original_code);
	}

		public async RemoteCallResult execute (Cancellable? cancellable) throws Error, IOError {
#if X86
				session.write_memory (regs.esp, raw_slots);
			session.write_memory (regs.esp, (uint8[]) &return_address);
#elif X86_64
			session.write_memory (regs.rsp, (uint8[]) &return_address);
#elif ARM
				session.write_memory (regs.sp, raw_slots);
#elif MIPS
				session.write_memory (regs.sp, raw_slots);
#endif
		}
