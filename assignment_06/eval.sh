#!/usr/bin/env bash

# --- CONFIGURATION ---
# Number of times to run the test. Can be overridden from the command line.
# Example: ./eval.sh 100 64
NUM_RUNS=${1:-10}
WORD_COUNT=${2:-64}
DISTANCE_THRESHOLD=16

# --- VISUALIZATION ---
# Set to 1 to always show the diff. Set to 0 to disable.
SHOW_DIFF=1
SIDE_BY_SIDE_WIDTH=120

# --- SCRIPT START ---
echo "Starting evaluation..."
echo "Configuration: ${NUM_RUNS} runs, ${WORD_COUNT}-word stories, success threshold <= ${DISTANCE_THRESHOLD} errors."

# Check for required executables
if [ ! -f ./leak-stories ] || [ ! -f ./llama2-server ]; then
    echo "Error: Missing executables. Please run 'make' to build ./leak-stories."
    exit 1
fi

# Initialize statistics
SUCCESS_COUNT=0
TOTAL_DISTANCE=0

# Main evaluation loop
for i in $(seq 1 $NUM_RUNS); do
    echo "==================== Run $i/$NUM_RUNS ===================="

    # Clean up files from previous run
    rm -f generated.out leaked.out

    # --- EXECUTION BLOCK (Mirrors assignment's test.sh flow) ---

    # 1. Start an attacker process in the background.
    #    The '&' runs it in the background. We save its PID using '$!' for cleanup.
    ./leak-stories 1>leaked.out &
    LEAKER_PID=$!

    # 2. Wait for 100ms for the attacker to initialize.
    sleep 0.1

    # 3. Start generating a story in the FOREGROUND.
    #    The script will PAUSE on this line until ./llama2-server is finished.
    ./llama2-server stories110M.bin -n $WORD_COUNT 1>generated.out 2>/dev/null

    # 4. Now that the victim is done, ensure the attacker is also terminated.
    #    This prevents old attacker processes from interfering with the next run.
    #    We wait a moment for the attacker's timeout, then kill it just in case.

    timeout -s KILL 5s  bash -c "while kill -0 $LEAKER_PID 2>/dev/null; do sleep 0.1; done"

    kill -9 $LEAKER_PID 2>/dev/null || true

    # --- EVALUATION AND OUTPUT BLOCK ---

    # Calculate the word-level edit distance
    DISTANCE=$(python3 calculate_distance.py generated.out leaked.out)
    TOTAL_DISTANCE=$((TOTAL_DISTANCE + DISTANCE))

    # Check for success
    if [ "$DISTANCE" -le $DISTANCE_THRESHOLD ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        RESULT_MSG="\033[1;32mSUCCESS\033[0m"
    else
        RESULT_MSG="\033[1;31mFAIL\033[0m"
    fi

    # Print the stories exactly as in the assignment spec
    echo ""
    echo -e "\033[1mStory generated:\033[0m"
    [ -f generated.out ] && cat generated.out || echo "<file not found>"

    echo ""
    echo -e "\033[1mStory leaked:\033[0m"
    [ -f leaked.out ] && cat leaked.out || echo "<file not found>"
    echo "" # Trailing newline for spacing

    # Print the result for this run
    echo -e "Result: Distance = $DISTANCE -> ${RESULT_MSG}"

    # Show the side-by-side diff for detailed debugging
    if [ "$SHOW_DIFF" -eq 1 ]; then
        echo "--- Diff (Generated vs. Leaked - only differences shown) ---"
        diff --side-by-side --suppress-common-lines -W $SIDE_BY_SIDE_WIDTH \
            <(tr ' ' '\n' <generated.out) \
            <(tr ' ' '\n' <leaked.out)
        echo "------------------------------------------------------------"
    fi
done

# --- FINAL SUMMARY ---
echo "============================================================"
echo "Evaluation Complete."
echo ""
SUCCESS_RATE=$(echo "scale=2; ($SUCCESS_COUNT / $NUM_RUNS) * 100" | bc)
echo "--- FINAL RESULTS ---"
echo "Success Rate:   ${SUCCESS_COUNT} / ${NUM_RUNS} (${SUCCESS_RATE}%)"
AVG_DISTANCE=$(echo "scale=2; $TOTAL_DISTANCE / $NUM_RUNS" | bc)
echo "Average Distance: ${AVG_DISTANCE}"
echo "---------------------"
