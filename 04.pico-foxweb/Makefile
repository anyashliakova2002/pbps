CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong
LDFLAGS = -lpam -lssl -lcrypto -Wl,-z,now

all: PICOFoxweb

PICOFoxweb: main.o httpd.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

main.o: main.c httpd.h
	$(CC) $(CFLAGS) -c -o $@ $<

httpd.o: httpd.c httpd.h
	$(CC) $(CFLAGS) -c -o $@ $<

base64.o: base64.c httpd.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o PICOFoxweb

install:
	install -m 755 PICOFoxweb /usr/local/bin/
	install -d /var/log/
	touch /var/log/foxweb.log
	chown root:adm /var/log/foxweb.log
	chmod 640 /var/log/foxweb.log
	[ -f /etc/pam.d/httpd ] || install -m 644 pam-config /etc/pam.d/httpd

.PHONY: all clean install
