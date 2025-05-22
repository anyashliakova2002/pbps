all: PICOFoxweb

clean:
	@rm -rf *.o
	@rm -rf PICOFoxweb

PICOFoxweb: main.o httpd.o base64.o
	gcc -o PICOFoxweb $^ -lpam -lssl -lcrypto

main.o: main.c httpd.h
	gcc -c -o main.o main.c -Wall -Wextra

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c -Wall -Wextra

base64.o: base64.c httpd.h
	gcc -c -o base64.o base64.c -Wall -Wextra

install:
	sudo cp PICOFoxweb /usr/local/bin/
	sudo mkdir -p /var/log/
	sudo touch /var/log/foxweb.log
	sudo chmod 666 /var/log/foxweb.log
	sudo cp pam-config /etc/pam.d/httpd

.PHONY: all clean install
