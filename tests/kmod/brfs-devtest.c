/*
 * brfs-devtest.c — /dev/brfs ioctl exerciser for the P0.2 spike:
 * ADDROOT/DELROOT/GETSTATS against the live kmod.  The daemon owns the
 * device in normal operation (single-open); stop brfsd before running.
 *
 * usage: brfs-devtest add PATH | del PATH | stats
 */
#include <sys/ioctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../../kmod/brfs.h"

int
main(int argc, char **argv)
{
	struct brfs_root root;
	struct brfs_stats stats;
	int fd, error;

	if (argc < 2) {
		fprintf(stderr, "usage: brfs-devtest add PATH | del PATH |"
		    " stats\n");
		return (2);
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
