# source: https://jonathanh.co.uk/blog/fuzzy-search-hashcat-modes.html

hashcat-fzf-completion() {
    local tokens cmd append
    setopt localoptions noshwordsplit noksh_arrays noposixbuiltins
    # http://zsh.sourceforge.net/FAQ/zshfaq03.html
    # http://zsh.sourceforge.net/Doc/Release/Expansion.html#Parameter-Expansion-Flags
    tokens=(${(z)LBUFFER})
    if [ ${#tokens} -lt 1 ]; then
        zle ${HCcomplete_default_completion:-expand-or-complete}
        return
    fi
    cmd=${tokens[1]}
    if [[ "$cmd" == "hashcat" ]]; then
        if [[ "${tokens[-1]}" == "-m" || "${tokens[-1]}" == "--hash-type" ]]; then
            append=$(hashcat --example-hashes | awk -v RS="\n\n" -F "\t" '{gsub("\n","\t",$0); print $1 "\t" $2 "\t" $3}' | sed 's/MODE: //; s/TYPE: //' | fzf -d "\t" --header="Mode   Type" --with-nth='1,2' --preview='echo {3}' --preview-window=up:1 --reverse --height=40% | awk '{print $1}')
            if [ -n "$append" ]; then
                # Make sure that we are adding a space
                if [[ "${LBUFFER[-1]}" != " " ]]; then
                    LBUFFER="${LBUFFER} "
                fi
                LBUFFER="${LBUFFER}${append}"
                zle reset-prompt
                return 0
            fi
            zle reset-prompt
        else
            zle ${HCcomplete_default_completion:-expand-or-complete}
        fi
    else
        zle ${HCcomplete_default_completion:-expand-or-complete}
    fi

}

[ -z "$HCcomplete_default_completion" ] && {
    binding=$(bindkey '^I')
    [[ $binding =~ 'undefined-key' ]] || HCcomplete_default_completion=$binding[(s: :w)2]
    unset binding
}
zle     -N   hashcat-fzf-completion
bindkey '^I' hashcat-fzf-completion
