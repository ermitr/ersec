_ersec_complete() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W '--help --version --self-test --capabilities --roadmap-audit --build-assurance --build-assurance-out --assurance-loop --assurance-loop-policy --assurance-benchmark-run --proof-dir --output --html --sarif --markdown --junit --browser --profile' -- "$cur") )
}
complete -F _ersec_complete ersec
