leak-stories: leak-stories.c
	gcc -o leak-stories leak-stories.c tokenizer.c
run: leak-stories
	./leak-stories
trace: leak-stories
	./leak-stories 2> trace.txt
throttle: leak-stories
	cpulimit --limit 25 --background -- ./leak-stories 2>trace.txt
clean:
	rm -f leak-stories