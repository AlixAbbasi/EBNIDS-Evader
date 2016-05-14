
[+] Unorganized mess of files to be merged into MSF at some later point
[+] For testing: merge folder structure with your local MSF copy, overwrite pre-existing files (such as x86.rb) with modified versions

[-] TODO:

	- Encoder core design
		- Automatic submodule ordering and conflict resolution
		- Automatic target-submodule coupling resolution (TODO: make 'target' an array)
		- Dynamic 'plug & play' submodule plugin support

	- Sub-modules
		- Implement following:		
			- Faithful
				- CKPE
					- hash armoring

	- Write rudimentary documentation

	========================================================================================
		- NOTES:
		    - Code is pretty ugly, still in early alpha. Code is meant to be PoC accompanying research.
		    - Not all code is meant to fully bypass all EBNIDS, code reflects code used in research

		    - Baseline encoder is currently a simple XOR-encoder, could easily be extended to other encoder types
		    - Using Rex since Encoders don't support .assembly functionality payloads have

		    - RDA is partially error-prone due to collisions in FNV hashing (fix this)
		    - Should be noted that RDA has no timeout _guarantee_ due to randomness of keys
		    - Currently only implemented RDA for timeout	
		    - Hasharmoring is currently NOT supported yet
		    - Not all EBNIDS-evasion techniques are implemented as encoders:    
				- NO non-self-contained as ROP is specific to payload & target
				- NO kernel32.dll evasions as they are part of the payload
				- Egghunting is present as encoder but is better used as part of payload

			- kernel32.dll messagebox is just a demonstration, techniques have to be integrated into every payload manually
			- egghunt is just a demonstration too
	========================================================================================

		- Extra:
			=================
			Primary
			=================
			- General:
				- set module info correctly
				- support module overriding for decoder_stub as well
				- see if Rex::Arch::X86.set() uses badchars everywhere
				- badchars support everywhere
				- max_len support everywhere
				- cleanup code / core redesign
				- armor conflict/dependency resolution
			------------------------------------------
			- Kernel32.dll
				- use Evasive getPC code in example
			------------------------------------------
			- CKPE:
				- fix obtain_key to only use CKPE_KEY if we are in CKPE armor iteration
				- encode getPC stub in CKPE with hash of key instead of key
			------------------------------------------
			- Egghunt encoder:
				- Fix egghunting encoder to allow for marker parameter
			------------------------------------------
			- Timeout:
				- implement other timeout armors
			
				- Make RDA more error-resistant
				- Make RDA have timeout guarantee by setting lowest possible key (and thus minimum nr. of loop iterations), note this does not protect against
				  heuristics which take lower bound into account when looking for possible key! (note that choosing higher key value limits keyspace, fix perhaps by choosing random start point too and relying on wraparound?)		
			
			=================
			Secondary
			=================
			- Use metasm instead of Rex where possible?
				- See: https://dev.metasploit.com/api/Msf/Payload.html#build-instance_method

			- Stronger poly-/metamorphic general encoder + decoder stub (see shikata_ga_nai & bloxor)	
			- More getPC stub types (instead of only on-stack) and stronger getPC stub poly- and metamorphism
			- support more CKPE keygen types
			- Make shellcodes less platform/version dependent (eg. egghunting hardcoded API addresses)
			- integrate some techniques into single decoder stubs (eg. combined anti-disasm + unsupported instructions)
				- eg.: when given a decoder stub for CKPE, have ability to insert some anti-disasm, etc.
				- eg.: allow for getPC reg being passed or configurable getPC methods to other stubs so they can be combined

			- additional egghunting shellcodes (other syscalls, seh-based, etc.)
			- transformation methods (eg. push code to stack, on stack do a pop (ie. put instruction into register))
