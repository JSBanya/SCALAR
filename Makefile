all:
	gcc -Wall src/scalar.c src/log.c `pkg-config fuse3 --cflags --libs` -o scalar
