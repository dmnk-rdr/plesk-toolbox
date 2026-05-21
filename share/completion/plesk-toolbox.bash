# bash completion for plesk-toolbox
_plesk_toolbox() {
    local cur prev words cword
    _init_completion || return

    local verbs="audit tool mod help version"
    local audit_profiles="sec health sec/network sec/system sec/plesk sec/web health/system health/mail health/plesk"
    local mod_sub="list status enable disable"

    if (( cword == 1 )); then
        COMPREPLY=( $(compgen -W "$verbs" -- "$cur") )
        return
    fi

    case "${words[1]}" in
        audit)
            COMPREPLY=( $(compgen -W "$audit_profiles --json --list --no-color" -- "$cur") )
            ;;
        tool)
            if (( cword == 2 )); then
                local tools_dir="/opt/plesk-toolbox/tools.d"
                local groups opts=""
                if [[ -d "$tools_dir" ]]; then
                    for g in "$tools_dir"/*/; do
                        [[ -d "$g" ]] || continue
                        local gn; gn="$(basename "$g")"
                        for f in "$g"*.sh; do
                            [[ -f "$f" ]] && opts+="${gn}/$(basename "$f" .sh) "
                        done
                    done
                fi
                COMPREPLY=( $(compgen -W "$opts --list --dry-run --yes" -- "$cur") )
            fi
            ;;
        mod)
            if (( cword == 2 )); then
                COMPREPLY=( $(compgen -W "$mod_sub" -- "$cur") )
            fi
            ;;
    esac
}
complete -F _plesk_toolbox plesk-toolbox
complete -F _plesk_toolbox plesk-audit
complete -F _plesk_toolbox plesk-sec-audit
complete -F _plesk_toolbox plesk-tool
complete -F _plesk_toolbox plesk-mod
