/*
 * inotify-watch.c — minimal genuine-inotify consumer, used as the
 * coexistence oracle for the brfs.ko tap: watches one directory
 * (non-recursive, like real inotify) and prints decoded events.
 *
 * usage: inotify-watch PATH
 */
#include <sys/inotify.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	char buf[64 * 1024] __attribute__((aligned(8)));
	int fd, wd;

	if (argc != 2) {
		fprintf(stderr, "usage: inotify-watch PATH\n");
		return (2);
	}
	fd = inotify_init();
	if (fd < 0) {
		fprintf(stderr, "inotify_init: %s\n", strerror(errno));
		return (1);
	}
	wd = inotify_add_watch(fd, argv[1], IN_ALL_EVENTS);
	if (wd < 0) {
		fprintf(stderr, "inotify_add_watch: %s\n", strerror(errno));
		return (1);
	}
	fprintf(stderr, "watching %s (wd=%d)\n", argv[1], wd);
	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		char *p;

		if (n <= 0) {
			fprintf(stderr, "read: %s\n", n == 0 ? "EOF" :
			    strerror(errno));
			return (1);
		}
		for (p = buf; p < buf + n; ) {
			const struct inotify_event *ev =
			    (const struct inotify_event *)p;

			printf("mask=%08x cookie=%u name=%s\n", ev->mask,
			    ev->cookie, ev->len > 0 ? ev->name : "");
			fflush(stdout);
			p += sizeof(*ev) + ev->len;
		}
	}
}
