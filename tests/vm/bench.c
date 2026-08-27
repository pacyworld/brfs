/* bench.c — syscall microbench for t-overhead.sh: N open/read/close
 * cycles then N append-write cycles on PATH; prints wall time per loop. */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

static double
now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ts.tv_sec + ts.tv_nsec / 1e9);
}

int
main(int argc, char **argv)
{
	char buf[4096];
	double t0, t1, t2;
	int n, i, fd;

	if (argc != 3) {
		fprintf(stderr, "usage: bench PATH N\n");
		return (2);
	}
	n = atoi(argv[2]);
	memset(buf, 'x', sizeof(buf));

	t0 = now();
	for (i = 0; i < n; i++) {
		fd = open(argv[1], O_RDONLY);
		if (fd < 0) { perror("open"); return (1); }
		if (read(fd, buf, 1) != 1) { perror("read"); return (1); }
		close(fd);
	}
	t1 = now();
	for (i = 0; i < n; i++) {
		fd = open(argv[1], O_WRONLY | O_APPEND);
		if (fd < 0) { perror("openw"); return (1); }
		if (write(fd, buf, sizeof(buf)) != sizeof(buf)) {
			perror("write");
			return (1);
		}
		close(fd);
	}
	t2 = now();
	printf("openclose %.3f write %.3f\n", t1 - t0, t2 - t1);
	return (0);
}
