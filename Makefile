all:
	gcc -Wall src/scalar.c `pkg-config fuse3 --cflags --libs` -o scalar
