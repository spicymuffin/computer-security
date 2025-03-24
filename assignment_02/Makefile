main:
	gcc -Wall dynamic_array.c mac.c -o mac
	sudo chown root:root mac
	ls -l mac
	sudo chmod 6755 mac
	ls -l mac

# create .data files (wont create files if they already exist so should be fine for grading?)
	touch top_secret.data
	touch secret.data
	touch confidential.data
	touch unclassified.data

	sudo chown root:root top_secret.data
	sudo chown root:root secret.data
	sudo chown root:root confidential.data
	sudo chown root:root unclassified.data

	sudo chmod 0640 top_secret.data
	sudo chmod 0640 secret.data
	sudo chmod 0640 confidential.data
	sudo chmod 0640 unclassified.data

	sudo chown root:root mac.policy
	sudo chmod 0640 mac.policy

clean:
	rm -f mac
	rm *.log
	rm -f *.data

# re-create the .data files
	touch top_secret.data
	touch secret.data
	touch confidential.data
	touch unclassified.data
debug:
	gcc -g dynamic_array.c mac.c -o mac
	sudo chmod 6755 mac

# create .data files
	touch top_secret.data
	touch secret.data
	touch confidential.data
	touch unclassified.data

	echo "top secret data (mmmmm nice)" > top_secret.data
	echo "just secret (noob) data" > secret.data
	echo "confidential data (very cringe)" > confidential.data
	echo "unclassified data (ew wtf)" > unclassified.data

	sudo chown root:root top_secret.data
	sudo chown root:root secret.data
	sudo chown root:root confidential.data
	sudo chown root:root unclassified.data

	sudo chmod 0640 top_secret.data
	sudo chmod 0640 secret.data
	sudo chmod 0640 confidential.data
	sudo chmod 0640 unclassified.data

	sudo chown root:root mac.policy
	sudo chmod 0640 mac.policy

