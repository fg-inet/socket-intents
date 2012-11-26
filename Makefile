muacsocksd: muacsocksd.c muacc.c
	gcc -g -Wall -o muacsocksd muacsocksd.c muacc.c

addrinfo: addrinfo.c muacc.c
	gcc -g -Wall -o addrinfo addrinfo.c muacc.c

.PHONY: muacsocksd addrinfo
