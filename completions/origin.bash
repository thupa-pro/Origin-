# shellcheck shell=bash
# Origin shell completion for Bash

_origin() {
    local i cur prev opts cmds
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd=""
    opts=""

    for i in ${COMP_WORDS[@]}; do
        case "${i}" in
            origin) cmd="origin" ;;
            hash) cmd+="__hash" ;;
            keygen) cmd+="__keygen" ;;
            sign) cmd+="__sign" ;;
            verify) cmd+="__verify" ;;
            audit) cmd+="__audit" ;;
            help) cmd+="__help" ;;
        esac
    done

    case "${cmd}" in
        origin)
            opts="-h -V --help --version hash keygen sign verify audit help"
            COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            return 0
            ;;
        origin__hash)
            opts="-h --help <path>"
            COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            [[ ${COMPREPLY} == "" ]] && COMPREPLY=($(compgen -f -- "${cur}"))
            return 0
            ;;
        origin__keygen)
            opts="-o -h --output --help"
            COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            return 0
            ;;
        origin__sign)
            opts="-k -t -h --key --time --parent --help <path>"
            COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            [[ ${COMPREPLY} == "" ]] && COMPREPLY=($(compgen -f -- "${cur}"))
            return 0
            ;;
        origin__verify)
            opts="-h --help --trusted-key --consistency-only --parent <statement> <artifact>"
            COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            [[ ${COMPREPLY} == "" ]] && COMPREPLY=($(compgen -f -- "${cur}"))
            return 0
            ;;
        origin__audit)
            opts="-h --help <statement>"
            COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            [[ ${COMPREPLY} == "" ]] && COMPREPLY=($(compgen -f -- "${cur}"))
            return 0
            ;;
        origin__help)
            opts="hash keygen sign verify audit help"
            COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            return 0
            ;;
    esac
}

complete -F _origin origin
