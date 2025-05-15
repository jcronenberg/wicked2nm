#!/bin/bash
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'
FAILED_TESTS=()
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR
MIGRATE_WICKED_BIN="$SCRIPT_DIR/../target/debug/wicked2nm"
TEST_DIRS=${TEST_DIRS:-$(ls -d */ | sed 's#/##')}
NO_CLEANUP=${NO_CLEANUP:-0}
NO_WICKED=${NO_WICKED:-0}
LOG_LEVEL=1
TEST_STDIN=true

source /etc/os-release
OS_DIR=
if [[ "$ID" == "opensuse-leap" ]]; then
    OS_DIR="$ID-$VERSION_ID"
elif [[ "$ID" == "opensuse-tumbleweed" ]]; then
    OS_DIR="$ID"
else
    echo -e "${RED}Unsupported OS${NC}"
    exit 1
fi
RES_DIR="$OS_DIR/system-connections"

error_msg() {
  log_error "Error for test $1:$2"
}

log_error() {
  [ $LOG_LEVEL -gt 0 ] && echo -e "${RED}$@${NC}"
}

log_verbose() {
    [ $LOG_LEVEL -gt 1 ] && echo -e "$@"
}

nm_cleanup() {
    for con in $(ls /etc/NetworkManager/system-connections/ | sed 's/\.nmconnection//'); do
        nmcli con delete $con
    done
}

print_help()
{
  echo "Usage:"
  echo "   ./test [ARGUMENTS] [TEST_DIRS]"
  echo ""
  echo "Arguments:"
  echo "  -v|--verbose            Be more verbose"
  echo "  --debug                 Prints out all commands executed"
  echo "  -q|--quiet              Be less verbose"
  echo "  --nm-cleanup            Cleanup current NetworkManager config before start"
  echo "  --no-cleanup            Do not cleanup NetworkManger after test"
  echo "  --no-wicked             If set, ifcfg tests do not fail when wicked isn't available"
  echo "  -h|--help               Print this help"
}

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  opt=$1;
  shift;
  case $opt in
    -v|--verbose)
      LOG_LEVEL=$((LOG_LEVEL + 1))
      ;;
    --debug)
      set -x
      ;;
    --binary)
      MIGRATE_WICKED_BIN=$1; shift
      ;;
    --no-wicked)
      NO_WICKED=1; shift
      ;;
    --nm-cleanup)
      connections=$(ls /etc/NetworkManager/system-connections/ | sed 's/\.nmconnection//')
      if [ ! -z "${connections}" ]; then
          echo -e "The following connections will be deleted:\n$connections"
      	  read -p "Do you want to continue? [y/N] " continue_cleanup
      	  if [ "$continue_cleanup" != "y" ]; then
      	      exit 1
      	  fi
      fi
      nm_cleanup
      ;;
    --no-cleanup)
      NO_CLEANUP=1
      ;;
    -q|--quiet)
      [ $LOG_LEVEL -gt 0 ] && LOG_LEVEL=$((LOG_LEVEL - 1))
      ;;
    -h|--help)
      print_help
      exit 0;
      ;;
    -*|--*)
      echo "Unknown option $opt"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$opt") # save positional arg
      ;;
  esac
done

if [ ${#POSITIONAL_ARGS[@]} -gt 0 ]; then
  TEST_STDIN=false
  TEST_DIRS=()
  for pos_arg in "${POSITIONAL_ARGS[@]}"; do
      if [[ "$pos_arg" == "stdin" ]]; then
          TEST_STDIN=true
      else
          TEST_DIRS+=("$pos_arg")
      fi
  done
fi

if [[ $(ls -A /etc/NetworkManager/system-connections/) ]]; then
    echo -e "${RED}There are already NM connections. You may be running this script on a live system, which is highly discouraged!${NC}"
    exit 1
fi

if [ ! -f $MIGRATE_WICKED_BIN ]; then
    echo -e "${RED}No wicked2nm binary found${NC}"
    exit 1
fi

for test_dir in ${TEST_DIRS}; do
    echo -e "${BOLD}Testing ${test_dir}${NC}"

    cd $SCRIPT_DIR/$test_dir

    # Apply environment variables of test
    export W2NM_CONTINUE_MIGRATION=false
    export W2NM_WITHOUT_NETCONFIG=true
    export W2NM_NETCONFIG_PATH=
    export W2NM_NETCONFIG_DHCP_PATH=
    TEST_EXPECT_FAIL=false
    if [ -f  ./ENV ]; then
       set -a && source ./ENV
       set +a
    fi

    if ls -1 ./netconfig/ifcfg-* >/dev/null 2>&1 && [ $NO_WICKED -eq 0 ]; then
        err_log="./wicked_show_config_error.log"
        cfg_out="./wicked_xml/config.xml"
        if ! command -v wicked >/dev/null ; then
            error_msg "$test_dir" "missing wicked executable"
            FAILED_TESTS+=("${test_dir}::wicked-show-config")
            continue
        fi

        wicked show-config --ifconfig compat:./netconfig \
            > "$cfg_out" \
            2> "$err_log"

        if [ $? -ne 0 ] || [ -s "$err_log" ]; then
            err_msg="'wicked show-config' failed"
            [ -s "$err_log" ] && err_msg+=" see $err_log"

            error_msg "$test_dir" "$err_msg"
            FAILED_TESTS+=("${test_dir}::wicked-show-config")
            continue
        fi

        # https://unix.stackexchange.com/a/209744
        regex_esc_test_dir="$(printf '%s' "$test_dir" | sed 's/[.[\(*^$+?{|]/\\&/g')"
        sed -i -E 's/[^:]+(\/tests\/'"$regex_esc_test_dir"')/\1/' "$cfg_out"
    fi

    log_verbose "RUN: $MIGRATE_WICKED_BIN show $test_dir/wicked_xml"
    $MIGRATE_WICKED_BIN show ./wicked_xml
    if [ $? -ne 0 ] && [ "$TEST_EXPECT_FAIL" = false ]; then
        error_msg ${test_dir} "show failed"
        FAILED_TESTS+=("${test_dir}::show")
    fi

    log_verbose "RUN: $MIGRATE_WICKED_BIN migrate $test_dir/wicked_xml"
    $MIGRATE_WICKED_BIN migrate ./wicked_xml
    if [ $? -ne 0 ] && [ "$TEST_EXPECT_FAIL" = false ]; then
        error_msg ${test_dir} "migration failed"
        FAILED_TESTS+=("${test_dir}::migrate")
        continue
    elif [ $? -ne 0 ] && [ "$TEST_EXPECT_FAIL" = true ]; then
        echo -e "${GREEN}Migration for $test_dir failed as expected${NC}"
    fi

    if [ -d "./$RES_DIR" ]; then
      for cmp_file in $(ls -1 ./$RES_DIR/); do
          a="./$RES_DIR/$cmp_file"
          b="/etc/NetworkManager/system-connections/${cmp_file}"
          diff_cmd="diff --unified=0 --color=always -I uuid -I timestamp $a $b"
          log_verbose "RUN: $diff_cmd"
          if $diff_cmd; then
              echo -e "${GREEN}Migration for connection ${cmp_file/\.nmconnection/} successful${NC}"
          else
              diff_cmd="diff  -I uuid -I timestamp -y --color=always $a $b"
              log_verbose "RUN: $diff_cmd\n$($diff_cmd)\n"
              error_msg ${test_dir} "$cmp_file didn't match"
              FAILED_TESTS+=("${test_dir}::compare_config::${cmp_file}")
          fi
      done
    fi

    [ "$NO_CLEANUP" -gt 0 ] || nm_cleanup
done

if $TEST_STDIN; then
    echo -e "${BOLD}Testing stdin show${NC}"
    cat <<EOF | $MIGRATE_WICKED_BIN show --without-netconfig - | grep "192.168.100.5" &>/dev/null
<interface>
  <ipv4:static>
    <address>
      <local>192.168.100.5/24</local>
    </address>
  </ipv4:static>
</interface>
EOF
    if [ $? -ne 0 ]; then
        error_msg "stdin" "show failed"
        FAILED_TESTS+=("stdin::show")
    else
        echo -e "${GREEN}stdin show successful${NC}"
    fi

    echo -e "${BOLD}Testing stdin migrate${NC}"
    cat <<EOF | $MIGRATE_WICKED_BIN migrate --without-netconfig --dry-run --log-level DEBUG - 2>&1 | grep "192.168.100.5" &>/dev/null
<interface>
  <ipv4:static>
    <address>
      <local>192.168.100.5/24</local>
    </address>
  </ipv4:static>
</interface>
EOF
    if [ $? -ne 0 ]; then
        error_msg "stdin" "migrate failed"
        FAILED_TESTS+=("stdin::migrate")
    else
        echo -e "${GREEN}stdin migrate successful${NC}"
    fi
fi

echo -e "\n${BOLD}Result:${NC}"

if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
    echo -e "${GREEN}All tests successful${NC}"
else
    echo -e "${RED}Failed test cases:"
    for testcase in "${FAILED_TESTS[@]}"; do
        echo "  $testcase"
    done
    echo -n -e "${NC}"
    exit 1
fi
