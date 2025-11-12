# === AWS CLI Training Wheels wrapper ===
# Verifies caller identity before executing AWS CLI commands

#Usage: Copy content into the end of ~/.zshrc - (curl -fsSL 'https://github.com/JackMarsden/AWS_Tooling/raw/refs/heads/main/trainingWheelsAWS.zshrc' >> ~/.zshrc && unset -f aws && source ~/.zshrc)
#kali: unset -f aws
#kali: source ~/.zshrc
AWS_REAL_BIN="$(whence -p aws 2>/dev/null || command -v aws 2>/dev/null || true)"

# ANSI colours
RESET=$'\033[0m'; BOLD=$'\033[1m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'; RED=$'\033[1;31m'; CYAN=$'\033[1;36m'

# session cache for confirmed profiles
typeset -A __AWS_CONFIRMED_PROFILES 2>/dev/null || __AWS_CONFIRMED_PROFILES=()

# safe runner for the real aws binary
_run_aws_real() {
  "$AWS_REAL_BIN" "$@"
}

aws() {
  # parse --profile / --profile=NAME
  local profile=""
  local -a args=("$@")
  local i
  for ((i=0; i<${#args[@]}; i++)); do
    case "${args[i]}" in
      --profile) ((i++)); profile="${args[i]:-}"; break ;;
      --profile=*) profile="${args[i]#--profile=}"; break ;;
    esac
  done
  [[ -z "$profile" && -n "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"

  # skip recursion for sts get-caller-identity
  if [[ "$1" == "sts" && "$2" == "get-caller-identity" ]]; then
    _run_aws_real "$@"; return $?
  fi

  # print verification message
  if [[ -n "$profile" ]]; then
    printf "%b\n" "${CYAN}Verifying AWS caller identity for profile:${RESET} ${BOLD}${profile}${RESET}"
  else
    printf "%b\n" "${CYAN}Verifying AWS caller identity for the DEFAULT profile (or env creds)...${RESET}"
  fi

  local -a pf=()
  [[ -n "$profile" ]] && pf=(--profile "$profile")
  local identity_out
  if ! identity_out="$(_run_aws_real "${pf[@]}" sts get-caller-identity --output json 2>&1)"; then
    printf "%b\n" "${YELLOW}WARNING: failed to fetch caller identity:${RESET}\n%s\n" "$identity_out"
    printf "%b" "${YELLOW}Type 'yes' to continue anyway, anything else to abort: ${RESET}"
    local CONFIRM=""; read -r CONFIRM
    [[ "$CONFIRM" != "yes" ]] && { printf "%b\n" "${RED}Aborted by user.${RESET}"; return 1; }
  else
    printf "%b\n" "${GREEN}Caller identity:${RESET}"
    if command -v jq >/dev/null 2>&1; then
      echo "$identity_out" | jq .
    else
      echo "$identity_out"
    fi
    printf "%b" "${YELLOW}Type 'yes' to confirm this is the correct profile (${BOLD}${CYAN}${profile}${RESET}${YELLOW}) to run the command:${RESET}"
    local CONFIRM=""; read -r CONFIRM
    [[ "$CONFIRM" != "yes" ]] && { printf "%b\n" "${RED}Aborted by user.${RESET}"; return 1; }
  fi

  # mark profile as confirmed in this session
  [[ -n "$profile" ]] && __AWS_CONFIRMED_PROFILES[$profile]=1 || __AWS_CONFIRMED_PROFILES[__default]=1

  # run the real aws command
  _run_aws_real "$@"
  return $?
}

# refresh hash so function overrides binary
hash -r aws 2>/dev/null || true
# end wrapper
