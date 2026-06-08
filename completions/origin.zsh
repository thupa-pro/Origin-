#compdef origin

_origin() {
    local -a commands

    commands=(
        'hash:Compute the SHA-256 hash of a file'
        'keygen:Generate a new Ed25519 key pair'
        'sign:Sign an artifact, producing a provenance statement'
        'verify:Verify a provenance statement against an artifact'
        'audit:Dump a provenance statement in human-readable form'
    )

    _arguments -C \
        '(-h --help)'{-h,--help}'[Print help]' \
        '(-V --version)'{-V,--version}'[Print version]' \
        "::command:->command" \
        "*::arg:->args"

    case "$state" in
        command)
            _describe "command" commands
            ;;
        args)
            case "$words[1]" in
                hash)
                    _arguments "1:file:_files"
                    ;;
                keygen)
                    _arguments \
                        '(-o --output)'{-o,--output}'[Output directory]:directory:_files -/'
                    ;;
                sign)
                    _arguments \
                        '(-k --key)'{-k,--key}'[Secret key file]:file:_files' \
                        '(-t --time)'{-t,--time}'[Unix timestamp]:timestamp' \
                        '--parent[Parent statement]:file:_files' \
                        "1:file:_files"
                    ;;
                verify)
                    _arguments \
                        "1:statement:_files -g '*.origin'" \
                        "2:artifact:_files"
                    ;;
                audit)
                    _arguments \
                        "1:statement:_files -g '*.origin'"
                    ;;
            esac
            ;;
    esac
}

_origin "$@"
