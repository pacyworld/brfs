/*-
 * Copyright (c) 2026, Daniel Morante
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * brfs.h — shared kernel/userspace ABI for BrFS.
 *
 * Userspace consumers: keep in sync with kmod/brfs.h.  The brfs_event
 * layout is designed to be usable as-is in a future mmap'd shared ring
 * (fixed size, no pointers, no padding surprises): do not change field
 * order or sizes without bumping BRFS_ABI_VERSION.
 */

#ifndef _BRFS_H_
#define _BRFS_H_

#include <sys/param.h>		/* NAME_MAX, MAXPATHLEN */
#include <sys/ioccom.h>
#include <sys/types.h>

#define	BRFS_ABI_VERSION	1

#define	BRFS_DEV_NAME		"brfs"
#define	BRFS_DEV_PATH		"/dev/brfs"

#define	BRFS_MAX_ROOTS		16
#define	BRFS_DEFAULT_RING_SIZE	4096	/* events; bounds safe daemon downtime */

/*
 * Event operations.  MOVE_FROM/MOVE_TO share be_cookie (the kernel's
 * inotify rename cookie) so the daemon can pair them into a rename.
 */
enum brfs_op {
	BRFS_OP_CREATE = 1,	/* new entry appeared under dir */
	BRFS_OP_MODIFY,		/* content write/extend */
	BRFS_OP_DELETE,		/* entry removed from dir */
	BRFS_OP_MOVE_FROM,	/* rename source */
	BRFS_OP_MOVE_TO,	/* rename destination */
	BRFS_OP_ATTRIB,		/* metadata-only change (mode/owner/times/flags) */
	BRFS_OP_OVERFLOW,	/* ring wrapped; daemon MUST rescan */
};

/* be_flags */
#define	BRFS_EVF_ISDIR		0x0001	/* event subject is a directory */

struct brfs_event {
	uint64_t	be_seq;		/* monotonic sequence (USN analog) */
	uint64_t	be_dir_fileid;	/* containing directory fileid */
	uint64_t	be_fileid;	/* subject fileid, 0 if unknown */
	uint32_t	be_op;		/* enum brfs_op */
	uint32_t	be_cookie;	/* rename pairing cookie, 0 if none */
	uint32_t	be_flags;	/* BRFS_EVF_* */
	uint32_t	be_abi;		/* BRFS_ABI_VERSION */
	char		be_name[NAME_MAX + 1]; /* last component; may be "" */
};

/* ioctl payloads */
struct brfs_root {
	char		br_path[MAXPATHLEN];
	uint32_t	br_mask;	/* enum brfs_op bitmask, 0 = all */
	uint32_t	br_pad;
};

struct brfs_stats {
	uint64_t	bs_events;	/* total events pushed */
	uint64_t	bs_drops;	/* events dropped on ring overflow */
	uint64_t	bs_ring_count;	/* events currently buffered */
	uint64_t	bs_ring_size;	/* ring capacity */
	uint32_t	bs_roots;	/* registered watch roots */
	uint32_t	bs_pad;
};

#define	BRFSIOC_ADDROOT		_IOW('B', 1, struct brfs_root)
#define	BRFSIOC_DELROOT		_IOW('B', 2, struct brfs_root)
#define	BRFSIOC_GETSTATS	_IOR('B', 3, struct brfs_stats)
#define	BRFSIOC_FLUSH		_IO('B', 4)

#endif /* _BRFS_H_ */
