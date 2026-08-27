/*
 * brfs-devtest.c — /dev/brfs ioctl exerciser for the P0.2 spike:
 * ADDROOT/DELROOT/GETSTATS against the live kmod.  The daemon owns the
 * device in normal operation (single-open); stop brfsd before running.
 *
 * usage: brfs-devtest add PATH | del PATH | stats | dump PATH
 *
 * dump PATH: ADDROOT PATH, then print every ring event as
 * "OP<TAB>cookie<TAB>name" (line-buffered) until killed.  Used by the
 * T11 fidelity test alongside a genuine inotify watcher as the oracle.
 */
#include <sys/ioctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../../kmod/brfs.h"

static const char *
opname(uint32_t op)
{
	switch (op) {
	case BRFS_OP_CREATE: return ("CREATE");
	case BRFS_OP_MODIFY: return ("MODIFY");
	case BRFS_OP_DELETE: return ("DELETE");
	case BRFS_OP_MOVE_FROM: return ("MOVE_FROM");
	case BRFS_OP_MOVE_TO: return ("MOVE_TO");
	case BRFS_OP_ATTRIB: return ("ATTRIB");
	case BRFS_OP_OVERFLOW: return ("OVERFLOW");
	default: return ("UNKNOWN");
	}
}

int
main(int argc, char **argv)
{
	struct brfs_root root;
	struct brfs_stats stats;
	int fd, error;

	if (argc < 2) {
		fprintf(stderr, "usage: brfs-devtest add PATH | del PATH |"
		    " stats | dump PATH\n");
		return (2);
	}
	if (strcmp(argv[1], "dump") == 0 && argc == 3) {
		struct brfs_event evbuf[64];
		ssize_t n;

		fd = open(BRFS_DEV_PATH, O_RDWR); /* blocking drain */
		if (fd < 0) {
			perror("open " BRFS_DEV_PATH);
			return (1);
		}
		memset(&root, 0, sizeof(root));
		strlcpy(root.br_path, argv[2], sizeof(root.br_path));
		if (ioctl(fd, BRFSIOC_ADDROOT, &root) != 0) {
			perror("ADDROOT");
			return (1);
		}
		fprintf(stderr, "DUMP %s: registered, draining\n", argv[2]);
		setvbuf(stdout, NULL, _IOLBF, 0);
		for (;;) {
			u_int i, nev;

			n = read(fd, evbuf, sizeof(evbuf));
			if (n < 0) {
				perror("read");
				return (1);
			}
			nev = (u_int)n / sizeof(evbuf[0]);
			for (i = 0; i < nev; i++)
				printf("%s\t%u\t%s\n", opname(evbuf[i].be_op),
				    evbuf[i].be_cookie, evbuf[i].be_name);
		}
	}
	fd = open(BRFS_DEV_PATH, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		perror("open " BRFS_DEV_PATH);
		return (1);
	}

	memset(&root, 0, sizeof(root));
	if (strcmp(argv[1], "add") == 0 && argc == 3) {
		strlcpy(root.br_path, argv[2], sizeof(root.br_path));
		error = ioctl(fd, BRFSIOC_ADDROOT, &root);
		if (error != 0) {
			perror("ADDROOT");
			return (1);
		}
		printf("ADDROOT %s ok\n", argv[2]);
	} else if (strcmp(argv[1], "del") == 0 && argc == 3) {
		strlcpy(root.br_path, argv[2], sizeof(root.br_path));
		error = ioctl(fd, BRFSIOC_DELROOT, &root);
		if (error != 0) {
			perror("DELROOT");
			return (1);
		}
		printf("DELROOT %s ok\n", argv[2]);
	} else if (strcmp(argv[1], "stats") == 0) {
		memset(&stats, 0, sizeof(stats));
		error = ioctl(fd, BRFSIOC_GETSTATS, &stats);
		if (error != 0) {
			perror("GETSTATS");
			return (1);
		}
		printf("events=%llu drops=%llu ring=%llu/%llu roots=%u\n",
		    (unsigned long long)stats.bs_events,
		    (unsigned long long)stats.bs_drops,
		    (unsigned long long)stats.bs_ring_count,
		    (unsigned long long)stats.bs_ring_size, stats.bs_roots);
	} else {
		fprintf(stderr, "bad args\n");
		return (2);
	}
	close(fd);
	return (0);
}
