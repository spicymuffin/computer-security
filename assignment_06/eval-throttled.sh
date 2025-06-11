#!/usr/bin/env bash

# --- CONFIGURATION ---
NUM_RUNS=${1:-10}
WORD_COUNT=${2:-64}
DISTANCE_THRESHOLD=16

# --- THROTTLING CONFIGURATION ---
# Set to the desired CPU percentage (e.g., 50 for 50% of one core).
# Set to 0 to disable throttling.
THROTTLE_CPU_PERCENT=20 # <-- CHANGE THIS VALUE TO TEST

# --- VISUALIZATION ---
SHOW_DIFF=1
SIDE_BY_SIDE_WIDTH=120

# --- SCRIPT START ---
echo "Starting evaluation..."
echo "Configuration: ${NUM_RUNS} runs, ${WORD_COUNT}-word stories."
if [ "$THROTTLE_CPU_PERCENT" -gt 0 ]; then
    echo "Throttling ENABLED: ./llama2-server will be limited to ${THROTTLE_CPU_PERCENT}% CPU."
fi

# Check for required executables
if [ ! -f ./leak-stories ] || [ ! -f ./llama2-server ]; then
    echo "Error: Missing executables."
    exit 1
fi
if [ "$THROTTLE_CPU_PERCENT" -gt 0 ] && ! command -v cpulimit &>/dev/null; then
    echo "Error: 'cpulimit' is not installed. Please run 'sudo apt-get install cpulimit'."
    exit 1
fi

SUCCESS_COUNT=0
TOTAL_DISTANCE=0

for i in $(seq 1 $NUM_RUNS); do
    echo "==================== Run $i/$NUM_RUNS ===================="
    rm -f generated.out leaked.out

    # --- EXECUTION BLOCK ---
    ./leak-stories 1>leaked.out &
    LEAKER_PID=$!
    sleep 0.1

    # Start the victim server in the background so we can get its PID
    ./llama2-server stories15M.bin -n $WORD_COUNT 1>generated.out 2>/dev/null &
    VICTIM_PID=$!

    # If throttling is enabled, start cpulimit targeting the victim's PID
    THROTTLE_PID=""
    if [ "$THROTTLE_CPU_PERCENT" -gt 0 ]; then
        cpulimit --pid $VICTIM_PID --limit $THROTTLE_CPU_PERCENT --background >/dev/null 2>&1
        THROTTLE_PID=$!
    fi

    # Wait for the victim process to complete
    wait $VICTIM_PID

    # --- CLEANUP ---
    # Now that victim is done, ensure leaker and cpulimit are terminated
    wait $LEAKER_PID 2>/dev/null
    kill -9 $LEAKER_PID >/dev/null 2>&1
    # If we started a throttle process, kill it too
    if [ -n "$THROTTLE_PID" ]; then
        kill -9 $THROTTLE_PID >/dev/null 2>&1
    fi

    # --- EVALUATION AND OUTPUT BLOCK ---
    DISTANCE=$(python3 calculate_distance.py generated.out leaked.out)
    TOTAL_DISTANCE=$((TOTAL_DISTANCE + DISTANCE))
    if [ "$DISTANCE" -le $DISTANCE_THRESHOLD ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        RESULT_MSG="\033[1;32mSUCCESS\033[0m"
    else
        RESULT_MSG="\033[1;31mFAIL\033[0m"
    fi

    echo ""
    echo -e "\033[1mStory generated:\033[0m"
    cat generated.out
    echo ""
    echo -e "\033[1mStory leaked:\033[0m"
    cat leaked.out
    echo ""
    echo -e "Result: Distance = $DISTANCE -> ${RESULT_MSG}"

    if [ "$SHOW_DIFF" -eq 1 ]; then
        echo "--- Diff (Generated vs. Leaked - only differences shown) ---"
        diff --side-by-side --suppress-common-lines -W $SIDE_BY_SIDE_WIDTH <(tr ' ' '\n' <generated.out) <(tr ' ' '\n' <leaked.out)
        echo "------------------------------------------------------------"
    fi
done

# --- FINAL SUMMARY ---
# (Final summary section remains the same)
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
