#!/bin/bash
#------------------------------------------------------------------
# This is the test script for runing all tests on local machine.
# Travis-CI tests are similar to this, except for multiple platforms.
#
# We can use this to reproduce Travis-CI failure locally, in case
# there's any true failure test cases.
#
# Usage:
#   ./run_tests.sh
#------------------------------------------------------------------

abort()
{
    printf >&2 "*** ABORTED ***\n"
    printf "An error occurred. Exiting...\n" >&2
    exit 1
}

trap 'abort' 0

set -e

# Add your script below....
# If an error occurs, the abort() function will be called.
#----------------------------------------------------------
# ===> Your script starts here

DIRS=(servers store chain pool p2p api keychain core util config)
for TEST_DIR in $DIRS; do 
    printf "Start testing on module: $TEST_DIR \n"
    cd $TEST_DIR && rm -rf target/tmp && cargo test --release -- --nocapture && cd - > /dev/null || exit 1
    printf "Test done for module: $TEST_DIR \n"
done
    printf "Start testing on root folder\n"
    rm -rf target/tmp && cargo test --all --release -- --nocapture || exit 1

#----------------------------------------------------------
# ===> Your script ends here
trap : 0

printf >&2 "*** TEST DONE *** \n"
