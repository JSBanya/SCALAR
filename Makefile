all: scalar

scalar:
	gcc -Wall src/scalar.c src/log.c `pkg-config fuse3 --cflags --libs` -o scalar

performance_test:
	gcc -Wall performance/main.c -o performanceTest

.PHONY: scalar performance_test
