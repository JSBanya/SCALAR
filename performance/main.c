#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>

int fd;

double test_create(char *name) {
	struct timespec tstart, tend;
    clock_gettime(CLOCK_MONOTONIC, &tstart);

	fd = open(name, O_RDWR | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    clock_gettime(CLOCK_MONOTONIC, &tend);

    if(fd < 0) {
    	printf("Unable to create file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);
}	

double test_write(char *text, size_t count) {
	struct timespec tstart, tend;
    clock_gettime(CLOCK_MONOTONIC, &tstart);

    ssize_t written = write(fd, text, count);

    clock_gettime(CLOCK_MONOTONIC, &tend);

    if(written != count) {
    	printf("Incomplete write: %s\n", strerror(errno));
    	exit(EXIT_FAILURE);
    }
    return ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec); 
}

double test_read(size_t count) {
	char buf[count];

	struct timespec tstart, tend;
    clock_gettime(CLOCK_MONOTONIC, &tstart);

    ssize_t bytes_read = read(fd, buf, count);

    clock_gettime(CLOCK_MONOTONIC, &tend);

    if(bytes_read != count) {
    	printf("Incomplete read: %s\n", strerror(errno));
    	exit(EXIT_FAILURE);
    }
    return ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec); 
}

double test_delete(char *name) {
	struct timespec tstart, tend;
    clock_gettime(CLOCK_MONOTONIC, &tstart);

	int err = unlink(name);

    clock_gettime(CLOCK_MONOTONIC, &tend);

    if(err == -1) {
    	printf("Unable to delete file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);
}

int main(int argc, char *argv[]) {
	char *name = "test.txt";
	char *text = "Code Red was a computer worm observed on the Internet on July 15, 2001. It attacked computers running Microsoft's IIS web server. The Code Red worm was first discovered and researched by eEye Digital Security employees Marc Maiffret and Ryan Permeh when it exploited a vulnerability discovered by Riley Hassell. They named it \"Code Red\" because Code Red Mountain Dew was what they were drinking at the time. Although the worm had been released on July 13, the largest group of infected computers was seen on July 19, 2001. On this day, the number of infected hosts reached 359,000.";
	size_t text_size = strlen(text);
	int trials = 100000;

	double total_tcreate, total_twrite, total_tread, total_tdelete;
	for(int i = 0; i < trials; i++) {
		double tcreate = test_create(name);
		printf("create: %.9f s\n", tcreate);
		total_tcreate += tcreate;

		double twrite = test_write(text, text_size);
		printf("write: %.9f s\n", twrite);
		total_twrite += twrite;

		lseek(fd, 0, SEEK_SET);

		double tread = test_read(text_size);
		printf("read: %.9f s\n", tread);
		total_tread += tread;

		double tdelete = test_delete(name);
		printf("delete: %.9f s\n", tdelete);
		total_tdelete += tdelete;

		close(fd);
		printf("\n");
	}
	
	printf("------------------------------\n");
	printf("Avg create: %.9f s (total: %.9f s)\n", total_tcreate / trials, total_tcreate);
	printf("Avg write: %.9f s (total: %.9f s)\n", total_twrite / trials, total_twrite);
	printf("Avg read: %.9f s (total: %.9f s)\n", total_tread / trials, total_tread);
	printf("Avg delete: %.9f s (total: %.9f s)\n", total_tdelete / trials, total_tdelete);
	
	return 0;
}