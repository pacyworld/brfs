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
 */

/*
 * brfs.ko — BrFS kernel event tap.
 *
 * A thin C shim: taps the FreeBSD 15 VFS event notification points
 * (VOP_INOTIFY, the same post-op hooks inotify rides on) for vnodes under
 * registered watch roots, and feeds a kernel-owned ring buffer behind
 * /dev/brfs.  All replication logic lives in brfsd(8); the module contains
 * no policy and parses no file formats.
 *
 * Control surface split (one source of truth = the daemon's config):
 *   - startup:  brfsd pushes watch roots via ioctl (BRFSIOC_ADDROOT)
 *   - runtime:  knobs + observability via security.brfs.* sysctls
 *
 * The VOP_INOTIFY interposition itself is Phase 0 spike work (P0.2); this
 * file provides the complete, tested delivery machinery the tap feeds via
 * brfs_emit(), plus a sysctl-triggered synthetic event path
 * (security.brfs.test_event) used to validate ring->daemon delivery before
 * the tap exists.
 *
 * Safety invariants (learned from the mac_do_auto UAF):
 *   - the ring is MALLOC'd at MOD_LOAD and freed at MOD_UNLOAD only after
 *     asserting no open fd (MOD_QUIESCE vetoes unload while /dev/brfs is
 *     open, so no fd can outlive the cdevsw);
 *   - MOD_UNLOAD wakes any thread blocked in read(2) with ENXIO via
 *     destroy_dev()'s d_purge callback;
 *   - no allocation on the event path: fixed-size ring slots only;
 *   - never resolve paths in event context (no vn_fullpath); events carry
 *     (dir fileid, name) and userspace resolves.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/selinfo.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include "brfs.h"

MALLOC_DEFINE(M_BRFS, "brfs", "brfs event ring");

/* ----------------------------------------------------------------
 * Tunables / sysctls
 * ---------------------------------------------------------------- */

SYSCTL_NODE(_security, OID_AUTO, brfs, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "brfs event tap parameters");

static u_int	brfs_ring_size_cfg = BRFS_DEFAULT_RING_SIZE;
SYSCTL_UINT(_security_brfs, OID_AUTO, ring_size, CTLFLAG_RDTUN,
    &brfs_ring_size_cfg, BRFS_DEFAULT_RING_SIZE,
    "brfs event ring capacity in events (load-time only)");

static int	brfs_enabled = 1;
SYSCTL_INT(_security_brfs, OID_AUTO, enabled, CTLFLAG_RW,
    &brfs_enabled, 1, "brfs event tap master switch");

static int	brfs_log_events = 0;
SYSCTL_INT(_security_brfs, OID_AUTO, log_events, CTLFLAG_RW,
    &brfs_log_events, 0, "log each emitted event to the kernel console");

static uint64_t	brfs_event_count;
SYSCTL_U64(_security_brfs, OID_AUTO, event_count, CTLFLAG_RD,
    &brfs_event_count, 0, "total events pushed to the ring");

static uint64_t	brfs_ring_drops;
SYSCTL_U64(_security_brfs, OID_AUTO, ring_drops, CTLFLAG_RD,
    &brfs_ring_drops, 0, "events dropped due to ring overflow");

/* ----------------------------------------------------------------
 * Ring buffer
 * ---------------------------------------------------------------- */

static struct mtx	brfs_ring_mtx;
static struct brfs_event *brfs_ring;
static u_int		brfs_ring_size;		/* actual capacity */
static u_int		brfs_ring_head;		/* next write position */
static u_int		brfs_ring_tail;		/* next read position */
static u_int		brfs_ring_count;	/* events available */
static uint64_t		brfs_seq;		/* next sequence number */
static int		brfs_overflow_pending;	/* inject OVERFLOW next push */
static struct selinfo	brfs_sel;
static struct cdev	*brfs_cdev;
static int		brfs_dev_open;		/* single-open flag */
static int		brfs_dev_dying;		/* set when module is unloading */

/* Caller holds brfs_ring_mtx. */
static void
brfs_ring_enqueue_locked(const struct brfs_event *ev)
{

	brfs_ring[brfs_ring_head] = *ev;
	brfs_ring_head = (brfs_ring_head + 1) % brfs_ring_size;
	brfs_ring_count++;
}

/*
 * Push one event.  On overflow the event is dropped, the drop counter is
 * bumped, and an in-band BRFS_OP_OVERFLOW event is injected ahead of the
 * next event that fits: the daemon must treat that as "rescan the tree",
 * mirroring the USN-journal-wrap failure mode it replaces.
 */
static void
brfs_ring_push(struct brfs_event *ev)
{

	mtx_lock(&brfs_ring_mtx);
	if (brfs_ring == NULL) {
		mtx_unlock(&brfs_ring_mtx);
		return;
	}
	if (brfs_ring_count >= brfs_ring_size) {
		brfs_ring_drops++;
		brfs_overflow_pending = 1;
	} else {
		ev->be_seq = ++brfs_seq;
		ev->be_abi = BRFS_ABI_VERSION;
		if (brfs_overflow_pending) {
			struct brfs_event ov;

			memset(&ov, 0, sizeof(ov));
			ov.be_op = BRFS_OP_OVERFLOW;
			ov.be_seq = ++brfs_seq;
			ov.be_abi = BRFS_ABI_VERSION;
			brfs_ring_enqueue_locked(&ov);
			brfs_overflow_pending = 0;
		}
		if (brfs_ring_count < brfs_ring_size)
			brfs_ring_enqueue_locked(ev);
		else
			brfs_ring_drops++;
		brfs_event_count++;
		wakeup(&brfs_ring_count);
	}
	mtx_unlock(&brfs_ring_mtx);
	selwakeup(&brfs_sel);
	KNOTE_UNLOCKED(&brfs_sel.si_note, 0);
}

/*
 * Single entry point for the VOP_INOTIFY tap (P0.2) and the synthetic
 * test-event sysctl.  Events are fixed-size; no allocation here.
 */
static void
brfs_emit(uint32_t op, uint32_t cookie, uint32_t flags,
    uint64_t dir_fileid, uint64_t fileid, const char *name)
{
	struct brfs_event ev;

	if (!brfs_enabled)
		return;
	memset(&ev, 0, sizeof(ev));
	ev.be_op = op;
	ev.be_cookie = cookie;
	ev.be_flags = flags;
	ev.be_dir_fileid = dir_fileid;
	ev.be_fileid = fileid;
	if (name != NULL)
		strlcpy(ev.be_name, name, sizeof(ev.be_name));
	if (brfs_log_events)
		printf("brfs: op=%u dir=%llu file=%llu name=%s\n", op,
		    (unsigned long long)dir_fileid,
		    (unsigned long long)fileid, ev.be_name);
	brfs_ring_push(&ev);
}

static int
sysctl_brfs_test_event(SYSCTL_HANDLER_ARGS)
{
	int error, val;

	val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (val < 0 || val > 1000000)
		return (EINVAL);
	for (; val > 0; val--)
		brfs_emit(BRFS_OP_MODIFY, 0, 0, 0, 0, "brfs-test");
	return (0);
}
SYSCTL_PROC(_security_brfs, OID_AUTO, test_event,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_brfs_test_event, "I",
    "push N synthetic events into the ring (delivery-path validation)");

/* ----------------------------------------------------------------
 * Watch roots (pushed by brfsd via ioctl; consumed by the P0.2 tap)
 * ---------------------------------------------------------------- */

static struct sx	brfs_roots_sx;
static struct brfs_root brfs_roots[BRFS_MAX_ROOTS];
static u_int		brfs_roots_count;

/* ----------------------------------------------------------------
 * /dev/brfs character device
 * ---------------------------------------------------------------- */

static int
brfs_dev_open_f(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td __unused)
{

	/*
	 * The dying check and the open flag are set under the same lock
	 * the MOD_QUIESCE veto holds, so an open(2) cannot slip in
	 * between the veto and destroy_dev().
	 */
	mtx_lock(&brfs_ring_mtx);
	if (brfs_dev_dying) {
		mtx_unlock(&brfs_ring_mtx);
		return (ENXIO);
	}
	if (brfs_dev_open) {
		mtx_unlock(&brfs_ring_mtx);
		return (EBUSY);
	}
	brfs_dev_open = 1;
	mtx_unlock(&brfs_ring_mtx);
	return (0);
}

static int
brfs_dev_close_f(struct cdev *dev __unused, int fflag __unused,
    int devtype __unused, struct thread *td __unused)
{

	/* Serialize with the MOD_QUIESCE veto in brfs_modevent(). */
	mtx_lock(&brfs_ring_mtx);
	brfs_dev_open = 0;
	mtx_unlock(&brfs_ring_mtx);
	return (0);
}

/*
 * Called by destroy_dev() (via devfs) with devmtx held whenever threads
 * are still inside cdevsw methods during teardown.  Wake any thread
 * sleeping in read(2) so it can observe brfs_dev_dying and exit,
 * allowing destroy_dev() to drain si_threadcount and return.
 */
static void
brfs_dev_purge(struct cdev *dev __unused)
{

	mtx_lock(&brfs_ring_mtx);
	brfs_dev_dying = 1;
	wakeup(&brfs_ring_count);
	mtx_unlock(&brfs_ring_mtx);
	selwakeup(&brfs_sel);
}

static int
brfs_dev_read(struct cdev *dev __unused, struct uio *uio, int ioflag)
{
	struct brfs_event ev;
	int error;

	mtx_lock(&brfs_ring_mtx);
	while (brfs_ring_count == 0) {
		if (brfs_dev_dying) {
			mtx_unlock(&brfs_ring_mtx);
			return (ENXIO);
		}
		if ((ioflag & O_NONBLOCK) != 0) {
			mtx_unlock(&brfs_ring_mtx);
			return (EAGAIN);
		}
		error = msleep(&brfs_ring_count, &brfs_ring_mtx,
		    PCATCH, "brfs", 0);
		if (error != 0) {
			mtx_unlock(&brfs_ring_mtx);
			return (error);
		}
	}

	while (uio->uio_resid >= (ssize_t)sizeof(ev) &&
	    brfs_ring_count > 0) {
		ev = brfs_ring[brfs_ring_tail];
		brfs_ring_tail = (brfs_ring_tail + 1) % brfs_ring_size;
		brfs_ring_count--;
		mtx_unlock(&brfs_ring_mtx);

		error = uiomove(&ev, sizeof(ev), uio);
		if (error != 0)
			return (error);

		mtx_lock(&brfs_ring_mtx);
	}
	mtx_unlock(&brfs_ring_mtx);
	return (0);
}

static int
brfs_dev_poll(struct cdev *dev __unused, int events, struct thread *td)
{
	int revents = 0;

	mtx_lock(&brfs_ring_mtx);
	if (events & (POLLIN | POLLRDNORM)) {
		if (brfs_ring_count > 0)
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &brfs_sel);
	}
	if (brfs_dev_dying)
		revents |= POLLERR;
	mtx_unlock(&brfs_ring_mtx);
	return (revents);
}

static int
brfs_dev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td __unused)
{
	struct brfs_root *root;
	struct brfs_stats *stats;
	u_int i;

	switch (cmd) {
	case BRFSIOC_ADDROOT: {
		root = (struct brfs_root *)data;
		root->br_path[MAXPATHLEN - 1] = '\0';
		if (root->br_path[0] != '/')
			return (EINVAL);
		/* Strip trailing slashes (except root "/"). */
		while (strlen(root->br_path) > 1 &&
		    root->br_path[strlen(root->br_path) - 1] == '/')
			root->br_path[strlen(root->br_path) - 1] = '\0';

		sx_xlock(&brfs_roots_sx);
		if (brfs_roots_count >= BRFS_MAX_ROOTS) {
			sx_xunlock(&brfs_roots_sx);
			return (ENOSPC);
		}
		for (i = 0; i < brfs_roots_count; i++) {
			if (strcmp(brfs_roots[i].br_path, root->br_path) == 0) {
				sx_xunlock(&brfs_roots_sx);
				return (EEXIST);
			}
		}
		brfs_roots[brfs_roots_count++] = *root;
		sx_xunlock(&brfs_roots_sx);
		return (0);
	}

	case BRFSIOC_DELROOT:
		root = (struct brfs_root *)data;
		root->br_path[MAXPATHLEN - 1] = '\0';
		sx_xlock(&brfs_roots_sx);
		for (i = 0; i < brfs_roots_count; i++) {
			if (strcmp(brfs_roots[i].br_path, root->br_path) == 0) {
				brfs_roots[i] =
				    brfs_roots[--brfs_roots_count];
				memset(&brfs_roots[brfs_roots_count], 0,
				    sizeof(struct brfs_root));
				sx_xunlock(&brfs_roots_sx);
				return (0);
			}
		}
		sx_xunlock(&brfs_roots_sx);
		return (ENOENT);

	case BRFSIOC_GETSTATS:
		stats = (struct brfs_stats *)data;
		memset(stats, 0, sizeof(*stats));
		mtx_lock(&brfs_ring_mtx);
		stats->bs_events = brfs_event_count;
		stats->bs_drops = brfs_ring_drops;
		stats->bs_ring_count = brfs_ring_count;
		stats->bs_ring_size = brfs_ring_size;
		mtx_unlock(&brfs_ring_mtx);
		sx_slock(&brfs_roots_sx);
		stats->bs_roots = brfs_roots_count;
		sx_sunlock(&brfs_roots_sx);
		return (0);

	case BRFSIOC_FLUSH:
		mtx_lock(&brfs_ring_mtx);
		brfs_ring_head = 0;
		brfs_ring_tail = 0;
		brfs_ring_count = 0;
		mtx_unlock(&brfs_ring_mtx);
		return (0);

	default:
		return (ENOTTY);
	}
}

static int	brfs_kqread(struct knote *kn, long hint);
static void	brfs_kqdetach(struct knote *kn);

static const struct filterops brfs_read_filterops = {
	.f_isfd = true,
	.f_attach = NULL,
	.f_detach = brfs_kqdetach,
	.f_event = brfs_kqread,
};

static int
brfs_dev_kqfilter(struct cdev *dev __unused, struct knote *kn)
{

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &brfs_read_filterops;
		knlist_add(&brfs_sel.si_note, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static int
brfs_kqread(struct knote *kn, long hint __unused)
{

	mtx_lock(&brfs_ring_mtx);
	kn->kn_data = brfs_ring_count * sizeof(struct brfs_event);
	mtx_unlock(&brfs_ring_mtx);
	return (kn->kn_data > 0);
}

static void
brfs_kqdetach(struct knote *kn)
{

	knlist_remove(&brfs_sel.si_note, kn, 0);
}

static struct cdevsw brfs_cdevsw = {
	.d_version = D_VERSION,
	.d_open = brfs_dev_open_f,
	.d_close = brfs_dev_close_f,
	.d_read = brfs_dev_read,
	.d_poll = brfs_dev_poll,
	.d_ioctl = brfs_dev_ioctl,
	.d_kqfilter = brfs_dev_kqfilter,
	.d_purge = brfs_dev_purge,
	.d_name = BRFS_DEV_NAME,
};

/*
 * Create /dev/brfs once devfs is initialized.  Deferred via SYSINIT so a
 * loader-preloaded module does not make_dev() before devfs exists (the
 * boot panic class documented in mac_do_auto).
 */
static void
brfs_cdev_init(void *arg __unused)
{

	brfs_cdev = make_dev(&brfs_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0640, BRFS_DEV_NAME);
}
SYSINIT(brfs_cdev, SI_SUB_DEVFS, SI_ORDER_MIDDLE, brfs_cdev_init, NULL);

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

static int
brfs_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		mtx_init(&brfs_ring_mtx, "brfs ring", NULL, MTX_DEF);
		sx_init(&brfs_roots_sx, "brfs roots");
		brfs_ring_size = brfs_ring_size_cfg;
		if (brfs_ring_size == 0)
			brfs_ring_size = BRFS_DEFAULT_RING_SIZE;
		brfs_ring = malloc(sizeof(struct brfs_event) * brfs_ring_size,
		    M_BRFS, M_WAITOK | M_ZERO);
		brfs_ring_head = 0;
		brfs_ring_tail = 0;
		brfs_ring_count = 0;
		brfs_seq = 0;
		brfs_overflow_pending = 0;
		brfs_roots_count = 0;
		brfs_dev_open = 0;
		brfs_dev_dying = 0;
		knlist_init_mtx(&brfs_sel.si_note, &brfs_ring_mtx);
		return (0);

	case MOD_QUIESCE:
		/*
		 * Veto unload while /dev/brfs is open so no fd can be left
		 * pointing at a cdevsw in unloaded module text; set dying at
		 * quiesce time so an open(2) racing the unload fails instead
		 * of establishing a new fd against a device about to be
		 * destroyed.
		 */
		mtx_lock(&brfs_ring_mtx);
		error = brfs_dev_open ? EBUSY : 0;
		if (error == 0)
			brfs_dev_dying = 1;
		mtx_unlock(&brfs_ring_mtx);
		return (error);

	case MOD_UNLOAD:
		/*
		 * Reject new opens and wake any thread sleeping in read(2).
		 * destroy_dev() waits for threads inside cdevsw methods to
		 * drain, invoking brfs_dev_purge() to prod sleepers, so no
		 * thread can be executing in this module when it returns.
		 * An idle open fd cannot exist here: MOD_QUIESCE vetoes the
		 * unload while /dev/brfs is open.
		 */
		mtx_lock(&brfs_ring_mtx);
		brfs_dev_dying = 1;
		wakeup(&brfs_ring_count);
		mtx_unlock(&brfs_ring_mtx);

		if (brfs_cdev != NULL) {
			destroy_dev(brfs_cdev);
			brfs_cdev = NULL;
		}
		seldrain(&brfs_sel);
		knlist_destroy(&brfs_sel.si_note);
		mtx_lock(&brfs_ring_mtx);
		if (brfs_ring != NULL) {
			free(brfs_ring, M_BRFS);
			brfs_ring = NULL;
		}
		brfs_ring_count = 0;
		mtx_unlock(&brfs_ring_mtx);
		mtx_destroy(&brfs_ring_mtx);
		sx_destroy(&brfs_roots_sx);
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t brfs_mod = {
	BRFS_DEV_NAME,
	brfs_modevent,
	NULL
};
DECLARE_MODULE(brfs, brfs_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(brfs, 1);
