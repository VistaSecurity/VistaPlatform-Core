# Sourced by run-integration-db-tests.sh and integration-coverage.sh.
#
# Turns the caller's GO_TEST_FLAGS (e.g. GO_TEST_FLAGS="-run Resurface -v") into
# the argument arrays every `go test` leg uses. The flags used to be passed as
# ONE quoted word, so "-run X" reached go test as a single malformed argument and
# every leg failed with "no Go files" / "[setup failed]".
#
#   IT_ARGS   for legs that only run the integration tests: the caller's flags,
#             -count=1, and `-run Integration` unless the caller chose their own
#             -run (two -run flags would make the later one win silently).
#   ALL_ARGS  for legs whose packages are entirely DB-backed and so carry no
#             filter: the caller's flags and -count=1.
#
# Unset, both are exactly what the legs passed before: -v -count=1 [-run Integration].
# The split is plain IFS word-splitting into an array, never eval, so a flag value
# cannot be interpreted as shell; quoting inside GO_TEST_FLAGS is not supported.
read -r -a _go_test_flags <<<"${GO_TEST_FLAGS:--v}"
_go_test_has_run=0
for _f in "${_go_test_flags[@]}"; do
  case "$_f" in
    -run | -run=* | --run | --run=* | -test.run | -test.run=*) _go_test_has_run=1 ;;
  esac
done
ALL_ARGS=("${_go_test_flags[@]}" -count=1)
IT_ARGS=("${ALL_ARGS[@]}")
[ "$_go_test_has_run" -eq 1 ] || IT_ARGS+=(-run Integration)
unset _f _go_test_flags _go_test_has_run
