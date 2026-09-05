	public sealed class ProcMapsIter {
		private string? contents;
		private MatchInfo? info;
		private uint offset = 0;

		public uint64 start_address {
			get {
				return uint64.parse (info.fetch (1), 16);
			}
		}

		public uint64 end_address {
			get {
				return uint64.parse (info.fetch (2), 16);
			}
		}

		public string flags {
			owned get {
				return info.fetch (3);
			}
		}

		public uint64 file_offset {
			get {
				return uint64.parse (info.fetch (4), 16);
			}
		}

		public uint64 dev {
			get {
				var s = info.fetch (5);
				int colon = s.index_of_char (':');

				uint64 major = uint64.parse (s.substring (0, colon), 16);
				uint64 minor = uint64.parse (s.substring (colon + 1), 16);

				return (major << 32) | minor;
			}
		}

		public DevId device {
			get {
				var s = info.fetch (5);
				int colon = s.index_of_char (':');

				uint32 major = (uint32) uint64.parse (s.substring (0, colon), 16);
				uint32 minor = (uint32) uint64.parse (s.substring (colon + 1), 16);

				return DevId (major, minor);
			}
		}

		public uint64 inode {
			get {
				return uint64.parse (info.fetch (6));
			}
		}

		public string path {
			owned get {
				return info.fetch (7);
			}
		}

		public static ProcMapsIter for_pid (uint pid) {
			return new ProcMapsIter (pid);
		}

		private ProcMapsIter (uint pid) {
			try {
				FileUtils.get_contents ("/proc/%u/maps".printf (pid), out contents);
			} catch (FileError e) {
				return;
			}

			if (!/^([0-9a-f]+)-([0-9a-f]+) (\S{4}) ([0-9a-f]+) ([0-9a-f]{2,}:[0-9a-f]{2,}) (\d+) *([^\n]*)$/m.match (
					contents, 0, out info)) {
				assert_not_reached ();
			}
		}

		public bool next () {
			if (info == null)
				return false;

			if (offset > 0) {
				try {
					info.next ();
				} catch (RegexError e) {
					return false;
				}
			}
			offset++;

			return info.matches ();
		}
	}
}
