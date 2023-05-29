gcc -c pbkdf2-sha256.c -o lib.o
ar -rcs lib.a lib.o
del lib.o