#!/usr/bin/env bash

# start an attacker process in the background
./leak-stories 1> leaked.out &

sleep 0.1 # wait for 100ms

# start generating a story (token limit controlled via "-n <number of tokens>")
./llama2-server stories15M.bin 1> generated.out 2> /dev/null

# print the generated story
echo -e "\033[1mStory generated:\033[0m"
cat generated.out

# print the story as leaked through a side channel
echo -e "\033[1mStory leaked:\033[0m"
cat leaked.out
