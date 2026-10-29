# Keep explicit fixture overrides ahead of tools added by system shell startup.
# This directory is selected through ZDOTDIR only by script test harnesses.
if [[ -n "${KEY_SCRIPT_TEST_PATH:-}" ]]; then
  export PATH="${KEY_SCRIPT_TEST_PATH}"
fi
