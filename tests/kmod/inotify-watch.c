/*
 * inotify-watch.c — genuine-inotify oracle for the T11 fidelity test.
 * Watches DIR (flat — inotify is not recursive) and prints every event
 * as "OP<TAB>cookie<TAB>name" (line-buffered) until killed, in the same
 * normalized shape as `brfs-devtest dump`.
 *
 * usage: inotify-watch DIR
 */
#include <sys/param.h>
#include <sys/inotify.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *
opname(uint32_t mask)
{
	if (mask & IN_CREATE) return ("CREATE");
	if (mask & IN_MODIFY) return ("MODIFY");
	if (mask & IN_DELETE) return ("DELETE");
	if (mask & IN_MOVED_FROM) return ("MOVE_FROM");
	if (mask & IN_MOVED_TO) return ("MOVE_TO");
	if (mask & (IN_ATTRIB)) return ("ATTRIB");
	return ("OTHER");
}

int
main(int argc, char **argv)
{
	char buf[64 * (sizeof(struct inotify_event) + NAME_MAX + 1)];
	int fd, wd;

	if (argc != 2) {
		fprintf(stderr, "usage: inotify-watch DIR\n");
		return (2);
	}
	fd = inotify_init();
	if (fd < 0) {
		perror("inotify_init");
		return (1);
	}
	wd = inotify_add_watch(fd, argv[1], IN_CREATE | IN_DELETE | IN_MODIFY |
	    IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB);
	if (wd < 0) {
		perror("inotify_add_watch");
		return (1);
	}
	fprintf(stderr, "WATCH %s: wd=%d\n", argv[1], wd);
	setvbuf(stdout, NULL, _IOLBF, 0);
	for (;;) {
		ssize_t n, off;

		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			perror("read");
			return (1);
		}
		for (off = 0; off < n;) {
			struct inotify_event *ev = (struct inotify_event *)(buf + off);
			const char *op = opname(ev->mask);

			if (strcmp(op, "OTHER") != 0)
				printf("%s\t%u\t%s\n", op, ev->cookie,
				    ev->len > 0 ? ev->name : "");
			off += (ssize_t)(sizeof(*ev) + ev->len);
		}
	}
}
