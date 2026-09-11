#compdef ersec
_arguments '*: :->args'
case $state in
args) _values 'ERSEC option' '--help[show help]' '--version[show version]' '--self-test[offline self-test]' '--capabilities[capability manifest]' '--roadmap-audit[roadmap coverage audit]' '--build-assurance[reproducibility assurance]' '--browser[browser discovery]' '--profile[scan profile]' ;;
esac
