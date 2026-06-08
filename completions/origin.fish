complete -c origin -f

# Subcommands
complete -c origin -n "__fish_use_subcommand" -a hash    -d "Compute the SHA-256 hash of a file"
complete -c origin -n "__fish_use_subcommand" -a keygen  -d "Generate a new Ed25519 key pair"
complete -c origin -n "__fish_use_subcommand" -a sign    -d "Sign an artifact, producing a provenance statement"
complete -c origin -n "__fish_use_subcommand" -a verify  -d "Verify a provenance statement against an artifact"
complete -c origin -n "__fish_use_subcommand" -a audit   -d "Dump a provenance statement in human-readable form"

# Global flags
complete -c origin -s h -l help    -d "Print help"
complete -c origin -s V -l version -d "Print version"

# hash
complete -c origin -n "__fish_seen_subcommand_from hash" -s h -l help -d "Print help"
complete -c origin -n "__fish_seen_subcommand_from hash" -a "(__fish_complete_path)"

# keygen
complete -c origin -n "__fish_seen_subcommand_from keygen" -s o -l output -d "Output directory" -r -a "(__fish_complete_directories)"
complete -c origin -n "__fish_seen_subcommand_from keygen" -s h -l help   -d "Print help"

# sign
complete -c origin -n "__fish_seen_subcommand_from sign" -s k -l key    -d "Secret key file" -r -F
complete -c origin -n "__fish_seen_subcommand_from sign" -s t -l time    -d "Unix timestamp" -r
complete -c origin -n "__fish_seen_subcommand_from sign"    -l parent   -d "Parent statement" -r -F
complete -c origin -n "__fish_seen_subcommand_from sign" -s h -l help    -d "Print help"
complete -c origin -n "__fish_seen_subcommand_from sign" -a "(__fish_complete_path)"

# verify
complete -c origin -n "__fish_seen_subcommand_from verify" -s h -l help -d "Print help"
complete -c origin -n "__fish_seen_subcommand_from verify" -a "(__fish_complete_path)"

# audit
complete -c origin -n "__fish_seen_subcommand_from audit" -s h -l help -d "Print help"
complete -c origin -n "__fish_seen_subcommand_from audit" -a "(__fish_complete_path)"
