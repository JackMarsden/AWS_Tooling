# === AWS CLI Training Wheels wrapper ===
# Verifies caller identity before executing AWS CLI commands

#Usage: Copy content into the end of ~/.zshrc
#kali: unset -f aws
#kali: source ~/.zshrc
AWS_REAL_BIN="$(command -v aws || true)"

# ANSI colours
RESET=$'\033[0m'
BOLD=$'\033[1m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
RED=$'\033[1;31m'
CYAN=$'\033[1;36m'

# per-shell-session confirmed profiles
declare -A __AWS_CONFIRMED_PROFILES 2>/dev/null || __AWS_CONFIRMED_PROFILES=()

if [[ -n "$AWS_REAL_BIN" && -x "$AWS_REAL_BIN" ]]; then
  aws() {
    local AWS_BIN="$AWS_REAL_BIN"

    # Skip wrapper if non-interactive or explicitly bypassed
    if [[ -n "${AWS_ASSUME_YES:-}" || ! -t 0 ]]; then
      "$AWS_BIN" "$@"
      return $?
    fi

    # Avoid recursion for sts get-caller-identity
    if [[ "$1" == "sts" && "$2" == "get-caller-identity" ]]; then
      "$AWS_BIN" "$@"
      return $?
    fi

    # Parse --profile
    local profile=""
    local -a args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
      case "${args[i]}" in
        --profile)
          ((i++))
          profile="${args[i]:-}"
          break
          ;;
        --profile=*)
          profile="${args[i]#--profile=}"
          break
          ;;
      esac
    done

    # fallback to AWS_PROFILE env var
    [[ -z "$profile" && -n "$AWS_PROFILE" ]] && profile="$AWS_PROFILE"

    # Skip prompt if profile already confirmed
    if [[ -n "$profile" && -n "${__AWS_CONFIRMED_PROFILES[$profile]:-}" ]]; then
      "$AWS_BIN" "$@"
      return $?
    fi
    if [[ -z "$profile" && -n "${__AWS_CONFIRMED_PROFILES[__default]:-}" ]]; then
      "$AWS_BIN" "$@"
      return $?
    fi

    # Verification message
    if [[ -n "$profile" ]]; then
      printf "%b\n" "${CYAN}Verifying AWS caller identity for profile:${RESET} ${BOLD}${profile}${RESET}"
    else
      printf "%b\n" "${CYAN}Verifying AWS caller identity for the DEFAULT profile (or env creds)...${RESET}"
    fi

    # Build profile flag
    local -a profile_flag=()
    [[ -n "$profile" ]] && profile_flag=(--profile "$profile")

    # Run sts get-caller-identity
    local identity_out
    if ! identity_out="$("$AWS_BIN" "${profile_flag[@]}" sts get-caller-identity --output json 2>&1)"; then
      # Handle errors
      if printf '%s' "$identity_out" | grep -qiE "The config profile .* could not be found|could not be found"; then
        printf "%b\n" "${RED}ERROR: The config profile '${profile}' could not be found.${RESET}"
      elif printf '%s' "$identity_out" | grep -qi "Unable to locate credentials"; then
        if [[ -n "$profile" ]]; then
          printf "%b\n" "${RED}ERROR: No credentials found for profile '${profile}'.${RESET}"
        else
          printf "%b\n" "${RED}ERROR: No credentials found for default environment. Configure credentials or set AWS_PROFILE.${RESET}"
        fi
      else
        printf "%b\n" "${YELLOW}WARNING: failed to fetch caller identity:${RESET}"
        printf "%b\n%s\n" "$identity_out"
      fi
      # prompt to continue anyway
      printf "%b" "${YELLOW}Type 'yes' to continue anyway, anything else to abort: ${RESET}"
      local CONFIRM=""
      read -r CONFIRM
      [[ "$CONFIRM" != "yes" ]] && { printf "%b\n" "${RED}Aborted by user.${RESET}"; return 1; }
    else
      printf "%b\n" "${GREEN}Caller identity:${RESET}"
      if command -v jq >/dev/null 2>&1; then
        echo "$identity_out" | jq .
      else
        echo "$identity_out"
      fi
      printf "%b" "${YELLOW}Type 'yes' to confirm this is the account to run the command '${BOLD}$*${RESET}${YELLOW}': ${RESET}"
      local CONFIRM=""
      read -r CONFIRM
      [[ "$CONFIRM" != "yes" ]] && { printf "%b\n" "${RED}Aborted by user.${RESET}"; return 1; }
    fi

    # Mark profile as confirmed
    [[ -n "$profile" ]] && __AWS_CONFIRMED_PROFILES[$profile]=1 || __AWS_CONFIRMED_PROFILES[__default]=1

    # Execute original AWS command
    "$AWS_BIN" "$@"
    return $?
  }
fi
