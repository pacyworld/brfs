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
 * The VOP_INOTIFY interposition (the P0.2 tap) patches the vop_inotify
 * slot of every vop_vector that serves a registered tree.  Vectors are
 * discovered lazily from vnode->v_op at ADDROOT/walk time, never by
 * symbol name: the same code covers base-kernel UFS/FFS and module ZFS
 * with no MODULE_DEPEND.  A sysctl-triggered synthetic event path
 * (security.brfs.test_event) remains for delivery-path validation.
 *
 * Safety invariants (learned from the mac_do_auto UAF):
 *   - the ring is MALLOC'd at MOD_LOAD and freed at MOD_UNLOAD only after
 *     asserting no open fd (MOD_QUIESCE vetoes unload while /dev/brfs is
 *     open, so no fd can outlive the cdevsw);
 *   - MOD_UNLOAD wakes any thread blocked in read(2) with ENXIO via
 *     destroy_dev()'s d_purge callback;
 *   - no allocation on the event path: fixed-size ring slots plus a
 *     preallocated pool for deferred subtree walks;
 *   - the tap never takes vnode or namecache locks (leaf locks only:
 *     vnode interlock via vn_irflag_set_cond, vpi_lock, ring/walk mtx);
 *   - never resolve paths in event context (no vn_fullpath); events carry
 *     (fsid, dir fileid, name) and userspace resolves;
 *   - vector patches are restored before module teardown, with a grace
 *     pause so in-flight tap calls drain before state is freed.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/inotify.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rmlock.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include "brfs.h"

MALLOC_DEFINE(M_BRFS, "brfs", "brfs event ring");

/* ----------------------------------------------------------------
 * Ring buffer state (declared early: sysctl handlers touch it)
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
static int
sysctl_brfs_enabled(SYSCTL_HANDLER_ARGS)
{
	int error, was;

	was = brfs_enabled;
	error = sysctl_handle_int(oidp, &brfs_enabled, 0, req);
	if (error == 0 && req->newptr != NULL && brfs_enabled && !was) {
		/*
		 * Re-enabling after a disabled window means events were
		 * lost: flag an overflow so the next push emits
		 * BRFS_OP_OVERFLOW and the daemon rescans.
		 */
		mtx_lock(&brfs_ring_mtx);
		brfs_overflow_pending = 1;
		mtx_unlock(&brfs_ring_mtx);
	}
	return (error);
}
SYSCTL_PROC(_security_brfs, OID_AUTO, enabled,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_brfs_enabled, "I", "brfs event tap master switch");

static int	brfs_log_events = 0;
SYSCTL_INT(_security_brfs, OID_AUTO, log_events, CTLFLAG_RW,
    &brfs_log_events, 0, "log each emitted event to the kernel console");

static uint64_t	brfs_event_count;
SYSCTL_U64(_security_brfs, OID_AUTO, event_count, CTLFLAG_RD,
    &brfs_event_count, 0, "total events pushed to the ring");

static uint64_t	brfs_ring_drops;
SYSCTL_U64(_security_brfs, OID_AUTO, ring_drops, CTLFLAG_RD,
    &brfs_ring_drops, 0, "events dropped due to ring overflow");

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
	/*
	 * Consecutive-duplicate suppression: a write(2) storm on one file
	 * collapses to the newest event per drain window instead of one
	 * slot per syscall.  Skipped while an overflow marker is pending
	 * so the marker is never starved by a dup stream.
	 */
	if (brfs_ring_count > 0 && !brfs_overflow_pending) {
		u_int last;
		struct brfs_event *le;

		last = (brfs_ring_head + brfs_ring_size - 1) % brfs_ring_size;
		le = &brfs_ring[last];
		if (le->be_op == ev->be_op && le->be_op != BRFS_OP_OVERFLOW &&
		    le->be_fileid == ev->be_fileid &&
		    le->be_dir_fileid == ev->be_dir_fileid &&
		    strcmp(le->be_name, ev->be_name) == 0) {
			mtx_unlock(&brfs_ring_mtx);
			return;
		}
	}
	if (brfs_ring_count >= brfs_ring_size) {
		brfs_ring_drops++;
		brfs_seq++;		/* leave a numeric gap for the daemon */
		brfs_overflow_pending = 1;
	} else {
		if (brfs_overflow_pending) {
			struct brfs_event ov;

			memset(&ov, 0, sizeof(ov));
			ov.be_op = BRFS_OP_OVERFLOW;
			ov.be_seq = ++brfs_seq;
			ov.be_abi = BRFS_ABI_VERSION;
			brfs_ring_enqueue_locked(&ov);
			brfs_overflow_pending = 0;
		}
		ev->be_seq = ++brfs_seq;
		ev->be_abi = BRFS_ABI_VERSION;
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
 * Single entry point for the VOP_INOTIFY tap and the synthetic test-event
 * sysctl.  Events are fixed-size; no allocation here.
 */
static void
brfs_emit(uint32_t op, uint32_t cookie, uint32_t flags, uint64_t fsid,
    uint64_t dir_fileid, uint64_t fileid, uint64_t gen, const char *name)
{
	struct brfs_event ev;

	if (!brfs_enabled)
		return;
	memset(&ev, 0, sizeof(ev));
	ev.be_op = op;
	ev.be_cookie = cookie;
	ev.be_flags = flags;
	ev.be_fsid = fsid;
	ev.be_dir_fileid = dir_fileid;
	ev.be_fileid = fileid;
	ev.be_gen = gen;
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
	/* Unique names so consecutive-dedup can't collapse the burst: this
	 * path exists to stress ring capacity and overflow handling. */
	for (; val > 0; val--) {
		char tname[32];

		snprintf(tname, sizeof(tname), "brfs-test-%llu",
		    (unsigned long long)(brfs_seq + 1));
		brfs_emit(BRFS_OP_MODIFY, 0, 0, 0, 0, 0, 0, tname);
	}
	return (0);
}
SYSCTL_PROC(_security_brfs, OID_AUTO, test_event,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_brfs_test_event, "I",
    "push N synthetic events into the ring (delivery-path validation)");

/* ----------------------------------------------------------------
 * Watch roots + VOP_INOTIFY tap
 *
 * Emit-all design (review item #13, decided): the tap performs NO
 * lineage filtering.  The VIRF gate flags themselves scope the event
 * stream to flagged trees; the only other source of flagged vnodes is
 * genuine inotify consumers, whose events the daemon discards (their
 * dir fileids are outside its registered roots).  This keeps the event
 * path free of namecache walks and their UAF/lock-order surface.
 *
 * Flag strategy (the "recursion engine"; inotify proper is not
 * recursive, so the kmod does the tree-wide flagging):
 *   - VIRF_INOTIFY on every DIRECTORY under a root: named child events
 *     (create/delete/rename) are gated on the parent dir's VIRF_INOTIFY.
 *   - VIRF_INOTIFY_PARENT on every FILE: self events (modify/attrib)
 *     are gated on the subject's VIRF_INOTIFY|VIRF_INOTIFY_PARENT.
 *   - ADDROOT flags the existing tree with a synchronous walk.
 *   - New children get VIRF_INOTIFY_PARENT from cache_enter for free
 *     (it keys on the parent dir's VIRF_INOTIFY, not on who set it).
 *   - New directories get VIRF_INOTIFY from the tap at their CREATE
 *     event, and any flagged dir whose vnode was recycled (flags die
 *     with the vnode) is re-upgraded on its next event.
 *   - A populated directory renamed INTO a tree is subtree-walked from
 *     a taskqueue (cannot walk in post-hook context: rename holds dir
 *     vnode locks).  Between the rename and the walk, coverage gaps are
 *     harmless: the daemon's announce of the directory is content-based
 *     (stat at announce time), so no state diverges.
 *   - Decay hazard: cache_vop_inotify strips VIRF_INOTIFY_PARENT when no
 *     genuinely-watched parent is found.  We never forward events to
 *     vop_stdinotify unless real inotify watches exist on vp/dvp, so the
 *     decay path never runs against our flags.
 *   - Pollinfo invariant: inotify_log() dereferences v_pollinfo with no
 *     NULL check (genuine inotify only flags watched vnodes, which
 *     always have pollinfo).  brfs_flag_dir() allocates pollinfo BEFORE
 *     setting VIRF_INOTIFY, so stale flags can never crash the genuine
 *     path — they degrade to an empty-watch no-op.  (Found the hard way:
 *     first P0.2 run panicked on open of a flagged dir in the window
 *     between kldunload's vector restore and the next ADDROOT.)
 *   - DELROOT/unload strip directory flags via an unflag walk (before
 *     vector restore); file PARENT flags self-heal via the decay path.
 *     Residual: a root rmdir'd while registered cannot be walked —
 *     leftover flags are safe (pollinfo invariant) and fade with vnode
 *     recycling.  A genuine inotify watch added inside our tree and then
 *     removed strips flags under it (inotify is oracle-only for BrFS).
 *
 * Vector patching: vfs_vector_op_register() bakes default ops into each
 * vop_vector at registration, so patching default_vnodeops would only
 * affect future registrations.  Instead we patch the vop_inotify slot of
 * each vector that serves a registered tree, discovered from vnode->v_op
 * at ADDROOT/walk time.  Only slots still holding vop_stdinotify are
 * replaced; foreign overrides (e.g. bypass vectors such as nullfs) are
 * left alone — nullfs writes still reach the tap because nullfs bypass
 * re-dispatches VOP_INOTIFY on the lower vnode, whose vector is patched.
 * (Side effect: a nullfs-alias write can yield the same event twice,
 * once per layer; the ring's consecutive-dedup absorbs it.)
 *
 * Registration is namespace-scoped: ADDROOT resolves in the caller's
 * namespace and flags the vnodes returned there.  Writes that bypass
 * the registered alias (e.g. host-side writes to a jail's nullfs tree)
 * are not covered by an alias registration; writers and the registering
 * daemon must share a mount namespace.  This matches the deployment
 * model (one brfsd per kernel, registers the path its writers use).
 * ---------------------------------------------------------------- */

static int	brfs_vop_inotify(struct vop_inotify_args *ap);
static bool	brfs_has_inotify_watches(struct vnode *vp);

#define	BRFS_MAX_VECS		32	/* distinct vop_vectors tapped */
#define	BRFS_ROOT_MAX_VECS	4	/* vectors attributable to a root */

struct brfs_vec_patch {
	struct vop_vector	*bp_vec;
	vop_inotify_t		*bp_orig;
	u_int			bp_refs;
};
static struct brfs_vec_patch	brfs_vecs[BRFS_MAX_VECS];
static u_int			brfs_vecs_count;

struct brfs_root_entry {
	struct brfs_root	cfg;		/* path + mask (ABI shape) */
	struct vnode		*vp;		/* vref'd root directory */
	uint64_t		fsid;
	uint64_t		fileid;
	struct vop_vector	*vecs[BRFS_ROOT_MAX_VECS];
	u_int			nvecs;
};

/*
 * rmlock: writers (ioctl root management) can sleep; the reader side is
 * only GETSTATS.  The tap itself never touches this table (emit-all).
 */
static struct rmlock		brfs_roots_rm;
static struct brfs_root_entry	brfs_roots[BRFS_MAX_ROOTS];
static u_int			brfs_roots_count;

/* Tap observability. */
static uint64_t	brfs_tap_seen;		/* interposer invocations */
static uint64_t	brfs_tap_emitted;	/* mutation events pushed */
static uint64_t	brfs_dirs_flagged;	/* VIRF_INOTIFY sets */
static uint64_t	brfs_files_flagged;	/* VIRF_INOTIFY_PARENT sets */
SYSCTL_U64(_security_brfs, OID_AUTO, tap_seen, CTLFLAG_RD,
    &brfs_tap_seen, 0, "vop_inotify interposer invocations");
SYSCTL_U64(_security_brfs, OID_AUTO, tap_emitted, CTLFLAG_RD,
    &brfs_tap_emitted, 0, "mutation events emitted by the tap");
SYSCTL_U64(_security_brfs, OID_AUTO, dirs_flagged, CTLFLAG_RD,
    &brfs_dirs_flagged, 0, "directories flagged VIRF_INOTIFY");
SYSCTL_U64(_security_brfs, OID_AUTO, files_flagged, CTLFLAG_RD,
    &brfs_files_flagged, 0, "files flagged VIRF_INOTIFY_PARENT");

static uint64_t
brfs_fsid(struct vnode *vp)
{
	fsid_t id;

	id = vp->v_mount->mnt_stat.f_fsid;
	return ((uint64_t)(uint32_t)id.val[0] << 32 | (uint32_t)id.val[1]);
}

/*
 * fileid/gen for an event vnode.  At most call sites the operation holds
 * the vnode locked and we use it as-is.  The rename post-hook is the
 * exception: VOP_RENAME args are WILLRELE and the filesystem has already
 * unlocked everything, so take a shared lock with NOWAIT — on contention
 * (or doom) emit 0 and let the daemon rescan rather than risk a lock
 * order surprise on the event path.
 */
static uint64_t
brfs_event_fileid(struct vnode *vp, struct ucred *cred, uint64_t *genp)
{
	struct vattr va;
	uint64_t fileid;
	int waslocked;

	waslocked = VOP_ISLOCKED(vp);
	if (waslocked == 0 && vn_lock(vp, LK_SHARED | LK_NOWAIT) != 0)
		return (0);
	fileid = 0;
	if (!VN_IS_DOOMED(vp) && VOP_GETATTR(vp, &va, cred) == 0) {
		fileid = va.va_fileid;
		*genp = va.va_gen;
	}
	if (waslocked == 0)
		VOP_UNLOCK(vp);
	return (fileid);
}

/*
 * Patch one vector's vop_inotify slot.  Single aligned pointer store:
 * concurrent dispatch either sees the old or new function, both valid.
 * Caller holds brfs_roots_rm in write mode.
 */
static void
brfs_vec_patch(struct vop_vector *vec, struct brfs_root_entry *re)
{
	u_int i;

	if (vec == NULL)
		return;
	for (i = 0; i < re->nvecs; i++)
		if (re->vecs[i] == vec)
			return;			/* already attributed */
	for (i = 0; i < brfs_vecs_count; i++) {
		if (brfs_vecs[i].bp_vec == vec) {
			brfs_vecs[i].bp_refs++;
			goto account;
		}
	}
	if (vec->vop_inotify == (vop_inotify_t *)brfs_vop_inotify)
		return;				/* ours but untracked */
	if (vec->vop_inotify != (vop_inotify_t *)vop_stdinotify)
		return;				/* foreign override/bypass */
	if (brfs_vecs_count >= nitems(brfs_vecs)) {
		printf("brfs: vector table full; cannot tap %p\n", vec);
		return;
	}
	i = brfs_vecs_count++;
	brfs_vecs[i].bp_vec = vec;
	brfs_vecs[i].bp_orig = vec->vop_inotify;
	brfs_vecs[i].bp_refs = 1;
	vec->vop_inotify = brfs_vop_inotify;
account:
	if (re->nvecs < nitems(re->vecs))
		re->vecs[re->nvecs++] = vec;
	else
		printf("brfs: root %s: vector attribution full\n",
		    re->cfg.br_path);
}

/* Caller holds brfs_roots_rm in write mode. */
static void
brfs_vec_unref(struct vop_vector *vec)
{
	u_int i;

	for (i = 0; i < brfs_vecs_count; i++) {
		if (brfs_vecs[i].bp_vec != vec)
			continue;
		if (--brfs_vecs[i].bp_refs == 0) {
			vec->vop_inotify = brfs_vecs[i].bp_orig;
			brfs_vecs[i] = brfs_vecs[--brfs_vecs_count];
			memset(&brfs_vecs[brfs_vecs_count], 0,
			    sizeof(brfs_vecs[0]));
		}
		return;
	}
}

/* ----------------------------------------------------------------
 * Subtree flag walk (ADDROOT, DELROOT, and deferred renamed-dir walk)
 * ---------------------------------------------------------------- */

#define	BRFS_WALK_MAX_DIRS	65536	/* per-walk bound */

struct brfs_walkent {
	STAILQ_ENTRY(brfs_walkent) we_link;
	struct vnode		*we_vp;		/* owned reference */
};
STAILQ_HEAD(brfs_walkq, brfs_walkent);

/*
 * Flag a directory as watched.  v_addpollinfo() runs BEFORE the flag is
 * set: the genuine inotify code (inotify_log) dereferences v_pollinfo
 * with no NULL check, relying on VIRF_INOTIFY implying a live watch,
 * which implies pollinfo.  We maintain that invariant so events that
 * reach vop_stdinotify for our flagged vnodes — possible whenever a
 * vector is restored while flags linger (DELROOT/unload windows) or the
 * tree was rmdir'd out from under the registration — find an empty
 * watch list instead of a NULL pointer.
 */
static void
brfs_flag_dir(struct vnode *vp)
{

	if ((vn_irflag_read(vp) & VIRF_INOTIFY) != 0)
		return;
	v_addpollinfo(vp);
	vn_irflag_set_cond(vp, VIRF_INOTIFY);
	brfs_dirs_flagged++;
	if (brfs_log_events) {
		uint64_t gen;
		printf("brfs: flag dir fileid=%llu\n", (unsigned long long)
		    brfs_event_fileid(vp, curthread->td_ucred, &gen));
	}
}

/*
 * Strip our watch flag from a directory.  Skipped when genuine inotify
 * watches exist (then the flag is theirs).  Files' VIRF_INOTIFY_PARENT
 * is not stripped explicitly: with no flagged dirs left, the genuine
 * decay path (cache_vop_inotify) strips it on the next access, and
 * vnode recycling clears it eventually.
 */
static void
brfs_unflag_dir(struct vnode *vp)
{

	if (brfs_has_inotify_watches(vp))
		return;
	if ((vn_irflag_read(vp) & VIRF_INOTIFY) != 0)
		vn_irflag_unset(vp, VIRF_INOTIFY);
}

/*
 * Flag every directory under startvp VIRF_INOTIFY and every non-directory
 * VIRF_INOTIFY_PARENT, mirroring vn_inotify_add_watch()'s dirent walk
 * (vfs_inotify.c) but recursive.  When re != NULL (ADDROOT), every
 * visited directory's vop vector is patched and attributed to the root.
 * With unflag set, the walk instead strips VIRF_INOTIFY from directories
 * (DELROOT/unload); files' PARENT flags are left to decay (see
 * brfs_unflag_dir).
 *
 * Sleeps (readdir, namei, malloc): ioctl or taskqueue context only,
 * never the event path.  Does not descend into mounted filesystems
 * (their vectors are not patched; document sub-mounts as unsupported
 * inside replicated roots).
 */
static int
brfs_flag_subtree(struct vnode *startvp, struct brfs_root_entry *re,
    struct thread *td, bool unflag)
{
	struct brfs_walkq queue = STAILQ_HEAD_INITIALIZER(queue);
	struct brfs_walkent *we;
	struct dirent *dp;
	struct vnode *vp;
	char *buf;
	size_t buflen;
	u_int ndirs;
	int error;

	buflen = 128 * sizeof(struct dirent);
	buf = malloc(buflen, M_TEMP, M_WAITOK);

	we = malloc(sizeof(*we), M_BRFS, M_WAITOK);
	vref(startvp);
	we->we_vp = startvp;
	STAILQ_INSERT_TAIL(&queue, we, we_link);

	error = 0;
	ndirs = 0;
	while ((we = STAILQ_FIRST(&queue)) != NULL) {
		struct nameidata nd;
		size_t len;
		off_t off;
		int eof;

		STAILQ_REMOVE_HEAD(&queue, we_link);
		vp = we->we_vp;
		free(we, M_BRFS);
		if (++ndirs > BRFS_WALK_MAX_DIRS) {
			vrele(vp);
			printf("brfs: flag walk exceeded %u dirs\n",
			    BRFS_WALK_MAX_DIRS);
			error = E2BIG;
			break;
		}

		if (unflag) {
			brfs_unflag_dir(vp);
		} else {
			if (re != NULL)
				brfs_vec_patch(__DECONST(struct vop_vector *,
				    vp->v_op), re);
			brfs_flag_dir(vp);
		}

		vn_lock(vp, LK_SHARED | LK_RETRY);
		if (VN_IS_DOOMED(vp)) {
			VOP_UNLOCK(vp);
			vrele(vp);
			continue;
		}

		len = off = eof = 0;
		for (;;) {
			struct vnode *cvp;

			error = vn_dir_next_dirent(vp, td, buf, buflen, &dp,
			    &len, &off, &eof);
			if (error != 0 || len == 0)
				break;
			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0)
				continue;

			/* namei() consumes a reference on the start dir. */
			vrefact(vp);
			VOP_UNLOCK(vp);
			NDINIT_ATVP(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE,
			    dp->d_name, vp);
			error = namei(&nd);
			vn_lock(vp, LK_SHARED | LK_RETRY);
			if (error != 0)
				break;
			NDFREE_PNBUF(&nd);
			cvp = nd.ni_vp;		/* referenced, UNLOCKED
						 * (no LOCKLEAF) */

			if (cvp->v_type == VDIR) {
				short ir;

				ir = vn_irflag_read(cvp);
				if ((ir & VIRF_MOUNTPOINT) != 0 ||
				    (!unflag && (ir & VIRF_INOTIFY) != 0) ||
				    (unflag && (ir & VIRF_INOTIFY) == 0)) {
					/* Sub-mount: no descend.  Flag walk:
					 * INOTIFY = already flagged
					 * (cycle/revisit).  Unflag walk:
					 * clear = nothing to strip. */
					vrele(cvp);
					continue;
				}
				we = malloc(sizeof(*we), M_BRFS, M_WAITOK);
				we->we_vp = cvp;	/* namei ref */
				STAILQ_INSERT_TAIL(&queue, we, we_link);
			} else if (!unflag) {
				if ((vn_irflag_read(cvp) &
				    VIRF_INOTIFY_PARENT) == 0) {
					vn_irflag_set_cond(cvp,
					    VIRF_INOTIFY_PARENT);
					brfs_files_flagged++;
				}
				vrele(cvp);
			} else {
				vrele(cvp);
			}
		}
		VOP_UNLOCK(vp);
		vrele(vp);
		if (error != 0)
			break;
	}

	while ((we = STAILQ_FIRST(&queue)) != NULL) {
		STAILQ_REMOVE_HEAD(&queue, we_link);
		vrele(we->we_vp);
		free(we, M_BRFS);
	}
	free(buf, M_TEMP);
	return (error);
}

/*
 * Deferred walk of a populated directory renamed into a watched tree.
 * Preallocated pool: the event path must not allocate.  Pool exhaustion
 * only delays subtree flagging; the daemon's content-based announce of
 * the renamed directory prevents any state divergence.
 */
#define	BRFS_WALK_POOL	8

static struct mtx	brfs_walk_mtx;
static struct brfs_walkjob {
	struct task	wj_task;
	struct vnode	*wj_vp;		/* owned reference while set */
} brfs_walkjobs[BRFS_WALK_POOL];

static void
brfs_walk_task(void *ctx, int pending __unused)
{
	struct brfs_walkjob *wj = ctx;
	struct vnode *vp = wj->wj_vp;

	(void)brfs_flag_subtree(vp, NULL, curthread, false);
	mtx_lock(&brfs_walk_mtx);
	wj->wj_vp = NULL;
	mtx_unlock(&brfs_walk_mtx);
	vrele(vp);
}

static void
brfs_walk_enqueue(struct vnode *vp)
{
	u_int i;

	mtx_lock(&brfs_walk_mtx);
	for (i = 0; i < nitems(brfs_walkjobs); i++) {
		if (brfs_walkjobs[i].wj_vp != NULL)
			continue;
		vref(vp);
		brfs_walkjobs[i].wj_vp = vp;
		taskqueue_enqueue(taskqueue_thread,
		    &brfs_walkjobs[i].wj_task);
		mtx_unlock(&brfs_walk_mtx);
		return;
	}
	mtx_unlock(&brfs_walk_mtx);
	printf("brfs: renamed-dir walk pool exhausted; subtree flags lag\n");
}

/* ----------------------------------------------------------------
 * The tap itself
 * ---------------------------------------------------------------- */

/*
 * Genuine inotify watches live on vp->v_pollinfo->vpi_inotify (public in
 * vnode.h; struct inotify_softc is opaque but this list is not).
 */
static bool
brfs_has_inotify_watches(struct vnode *vp)
{
	struct vpollinfo *vpi;
	bool has;

	vpi = vp->v_pollinfo;
	if (vpi == NULL)
		return (false);
	mtx_lock(&vpi->vpi_lock);
	has = !TAILQ_EMPTY(&vpi->vpi_inotify);
	mtx_unlock(&vpi->vpi_lock);
	return (has);
}

/*
 * VOP_INOTIFY interposer installed in patched vop vectors.
 *
 * Runs in VOP post-hook context: the operation's vnode locks are held by
 * the caller (the vnode_if.src inotify descriptor specifies no locks, but
 * every call site in vfs_subr.c/vfs_vnops.c holds them; the rename post
 * hook is the exception — its args are WILLRELE and already unlocked, so
 * brfs_event_fileid() takes a shared lock with NOWAIT).  We take only
 * leaf locks and never resolve paths.  VOP_GETATTR runs only on locked
 * vnodes; on failure a zero fileid tells the daemon to rescan.  No
 * allocation except on the rare dir-upgrade path (v_addpollinfo on
 * mkdir / rename-in / recycle recovery — never on the MODIFY hot path).
 */
static int
brfs_vop_inotify(struct vop_inotify_args *ap)
{
	struct vnode *vp, *dvp;
	struct ucred *cred;
	uint64_t dir_fileid, fileid, fsid, gen, dgen;
	uint32_t flags, op;
	const char *name;
	char namebuf[NAME_MAX + 1];
	bool mutation;

	brfs_tap_seen++;
	vp = ap->a_vp;
	dvp = ap->a_dvp;

	if (brfs_enabled && vp->v_type == VDIR) {
		if ((vn_irflag_read(vp) & VIRF_INOTIFY) == 0)
			brfs_flag_dir(vp);
		/*
		 * A directory arriving via rename may carry a populated
		 * subtree whose vnodes bear no flags: queue the deferred
		 * walk.  This must be independent of the upgrade above —
		 * the MOVE_FROM half of the same rename already upgraded
		 * the vnode, so the flag test alone would skip the import
		 * case that needs the walk.  Reaching the tap at all means
		 * the destination parent was flagged; for in-tree moves the
		 * walk degenerates to one readdir of the top directory
		 * (children are already flagged and skipped on sight).
		 */
		if (ap->a_event == IN_MOVED_TO)
			brfs_walk_enqueue(vp);
	}

	op = 0;
	mutation = true;
	switch (ap->a_event) {
	case IN_CREATE:
		op = BRFS_OP_CREATE;
		break;
	case IN_DELETE:
	case _IN_MOVE_DELETE:
		op = BRFS_OP_DELETE;
		break;
	case IN_MOVED_FROM:
		op = BRFS_OP_MOVE_FROM;
		break;
	case IN_MOVED_TO:
		op = BRFS_OP_MOVE_TO;
		break;
	case IN_MODIFY:
		op = BRFS_OP_MODIFY;
		break;
	case IN_ATTRIB:
	case _IN_ATTRIB_LINKCOUNT:
		op = BRFS_OP_ATTRIB;
		break;
	default:
		/* IN_ACCESS, IN_OPEN, IN_CLOSE_*: read-side noise. */
		mutation = false;
		break;
	}

	if (brfs_enabled && mutation) {
		flags = 0;
		if (vp->v_type == VDIR)
			flags |= BRFS_EVF_ISDIR;
		cred = ap->a_cnp != NULL ? ap->a_cnp->cn_cred :
		    curthread->td_ucred;
		fsid = brfs_fsid(vp);
		gen = 0;
		fileid = brfs_event_fileid(vp, cred, &gen);
		dir_fileid = 0;
		if (dvp != NULL)
			dir_fileid = brfs_event_fileid(dvp, cred, &dgen);
		name = NULL;
		if (ap->a_cnp != NULL) {
			size_t len;

			len = MIN(ap->a_cnp->cn_namelen, NAME_MAX);
			bcopy(ap->a_cnp->cn_nameptr, namebuf, len);
			namebuf[len] = '\0';
			name = namebuf;
		}
		brfs_tap_emitted++;
		brfs_emit(op, ap->a_cookie, flags, fsid, dir_fileid, fileid,
		    gen, name);
	}

	/*
	 * Forward to genuine inotify only when real watches exist on
	 * either vnode; otherwise vn_inotify()'s namecache fallback would
	 * strip our VIRF_INOTIFY_PARENT flags (decay hazard).
	 */
	if (brfs_has_inotify_watches(vp) ||
	    (dvp != NULL && brfs_has_inotify_watches(dvp)))
		vop_stdinotify(ap);

	return (0);
}

/* ----------------------------------------------------------------
 * /dev/brfs character device
 * ---------------------------------------------------------------- */

static int
brfs_dev_open_f(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td)
{
	int error;

	/* Single-open device: unauthorized opens also starve brfsd. */
	error = priv_check(td, PRIV_DRIVER);
	if (error != 0)
		return (error);

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

	/* Partial-record reads are a consumer bug; fail loudly. */
	if (uio->uio_resid < (ssize_t)sizeof(ev))
		return (EINVAL);

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
		/*
		 * Copy the tail event out under the lock but only advance
		 * the tail after a successful uiomove: a failed copy must
		 * not silently lose the event.  The tail slot is stable
		 * meanwhile — overflow drops discard incoming events, never
		 * the queued tail.
		 */
		ev = brfs_ring[brfs_ring_tail];
		mtx_unlock(&brfs_ring_mtx);

		error = uiomove(&ev, sizeof(ev), uio);
		if (error != 0)
			return (error);

		mtx_lock(&brfs_ring_mtx);
		brfs_ring_tail = (brfs_ring_tail + 1) % brfs_ring_size;
		brfs_ring_count--;
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
    int fflag __unused, struct thread *td)
{
	struct brfs_root *root;
	struct brfs_stats *stats;
	u_int i, j;
	int error;

	/* Watch-root management can move data structures the tap reads. */
	error = priv_check(td, PRIV_DRIVER);
	if (error != 0)
		return (error);

	switch (cmd) {
	case BRFSIOC_ADDROOT: {
		struct brfs_root_entry *re;
		struct nameidata nd;
		struct vattr va;
		struct vnode *vp;
		bool isnew;

		root = (struct brfs_root *)data;
		root->br_path[MAXPATHLEN - 1] = '\0';
		if (root->br_path[0] != '/')
			return (EINVAL);
		/* Strip trailing slashes (except root "/"). */
		while (strlen(root->br_path) > 1 &&
		    root->br_path[strlen(root->br_path) - 1] == '/')
			root->br_path[strlen(root->br_path) - 1] = '\0';

		rm_wlock(&brfs_roots_rm);

		/* Path-string match first (canonical re-register). */
		re = NULL;
		for (i = 0; i < brfs_roots_count; i++) {
			if (strcmp(brfs_roots[i].cfg.br_path,
			    root->br_path) == 0) {
				re = &brfs_roots[i];
				break;
			}
		}

		/*
		 * Resolve in the caller's namespace (jail-correct); through
		 * a nullfs alias this yields the operative vnode.  namei's
		 * reference becomes the root's long-term vref, pinning the
		 * tree's identity across daemon restarts.  LOCKLEAF so the
		 * initial GETATTR runs on a locked vnode.
		 */
		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE,
		    root->br_path);
		error = namei(&nd);
		if (error != 0) {
			rm_wunlock(&brfs_roots_rm);
			return (error);
		}
		vp = nd.ni_vp;
		NDFREE_PNBUF(&nd);
		if (vp->v_type != VDIR) {
			vput(vp);
			rm_wunlock(&brfs_roots_rm);
			return (ENOTDIR);
		}
		error = VOP_GETATTR(vp, &va, td->td_ucred);
		if (error != 0) {
			vput(vp);
			rm_wunlock(&brfs_roots_rm);
			return (error);
		}

		/* Alias match: same directory registered via another path. */
		if (re == NULL) {
			for (i = 0; i < brfs_roots_count; i++) {
				if (brfs_roots[i].fileid == va.va_fileid &&
				    brfs_roots[i].fsid == brfs_fsid(vp)) {
					re = &brfs_roots[i];
					break;
				}
			}
		}

		/*
		 * Re-register (brfsd restart, including kill -9) must not
		 * fail on the surviving registration: drop the old vnode
		 * (possibly doomed if the tree was rmdir'd meanwhile),
		 * release its vector attribution, and re-flag below.
		 */
		isnew = re == NULL;
		if (isnew) {
			if (brfs_roots_count >= BRFS_MAX_ROOTS) {
				vput(vp);
				rm_wunlock(&brfs_roots_rm);
				return (ENOSPC);
			}
			re = &brfs_roots[brfs_roots_count];
		} else {
			vrele(re->vp);
			for (j = 0; j < re->nvecs; j++)
				brfs_vec_unref(re->vecs[j]);
			re->nvecs = 0;
		}
		re->cfg = *root;
		re->vp = vp;
		re->fsid = brfs_fsid(vp);
		re->fileid = va.va_fileid;
		VOP_UNLOCK(vp);
		if (isnew)
			brfs_roots_count++;

		/*
		 * Flag the tree and patch its vectors.  A walk failure
		 * leaves the registration in place so the next brfsd start
		 * retries flagging; the error is returned so the failure
		 * is loud.
		 */
		error = brfs_flag_subtree(vp, re, td, false);
		rm_wunlock(&brfs_roots_rm);
		return (error);
	}

	case BRFSIOC_DELROOT:
		/*
		 * Unregister by path.  Strip our directory flags first
		 * (best effort — a doomed root cannot be walked; residual
		 * flags are safe thanks to the pollinfo invariant and
		 * self-heal via decay/recycling), then release the vnode
		 * and restore vectors whose refcount reaches zero.
		 */
		root = (struct brfs_root *)data;
		root->br_path[MAXPATHLEN - 1] = '\0';
		rm_wlock(&brfs_roots_rm);
		for (i = 0; i < brfs_roots_count; i++) {
			if (strcmp(brfs_roots[i].cfg.br_path,
			    root->br_path) != 0)
				continue;
			if (brfs_roots[i].vp != NULL) {
				(void)brfs_flag_subtree(brfs_roots[i].vp,
				    NULL, td, true);
				vrele(brfs_roots[i].vp);
			}
			for (j = 0; j < brfs_roots[i].nvecs; j++)
				brfs_vec_unref(brfs_roots[i].vecs[j]);
			brfs_roots[i] = brfs_roots[--brfs_roots_count];
			memset(&brfs_roots[brfs_roots_count], 0,
			    sizeof(brfs_roots[0]));
			rm_wunlock(&brfs_roots_rm);
			return (0);
		}
		rm_wunlock(&brfs_roots_rm);
		return (ENOENT);

	case BRFSIOC_GETSTATS: {
		struct rm_priotracker track;

		stats = (struct brfs_stats *)data;
		memset(stats, 0, sizeof(*stats));
		mtx_lock(&brfs_ring_mtx);
		stats->bs_events = brfs_event_count;
		stats->bs_drops = brfs_ring_drops;
		stats->bs_ring_count = brfs_ring_count;
		stats->bs_ring_size = brfs_ring_size;
		mtx_unlock(&brfs_ring_mtx);
		rm_rlock(&brfs_roots_rm, &track);
		stats->bs_roots = brfs_roots_count;
		rm_runlock(&brfs_roots_rm, &track);
		return (0);
	}

	case BRFSIOC_FLUSH:
		/*
		 * Discarding buffered events must not be silent: flag an
		 * overflow so the next push emits BRFS_OP_OVERFLOW and the
		 * daemon rescans rather than trusting a truncated stream.
		 */
		mtx_lock(&brfs_ring_mtx);
		brfs_ring_head = 0;
		brfs_ring_tail = 0;
		brfs_ring_count = 0;
		brfs_overflow_pending = 1;
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

	/*
	 * knlist_init_mtx() makes brfs_ring_mtx the knlist lock; knote()
	 * invokes f_event holding it (KNOTE_UNLOCKED acquires it first).
	 * Taking it again here would be a recursive lock of a
	 * non-recursive MTX_DEF mutex.
	 */
	mtx_assert(&brfs_ring_mtx, MA_OWNED);
	kn->kn_data = brfs_ring_count * sizeof(struct brfs_event);
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
 * /dev/brfs is created at the END of MOD_LOAD: this module registers at
 * SI_SUB_DRIVERS, which initializes after SI_SUB_DEVFS at boot, so devfs
 * is ready even for a loader-preloaded module — and the ring/mutex/dying
 * state is guaranteed initialized before the node is openable.  (A
 * separate SI_SUB_DEVFS SYSINIT would run BEFORE this module's MOD_LOAD,
 * leaving the device openable against uninitialized state.)
 *
 * Mode 0600: the device is single-open; any local user able to open it
 * can starve brfsd.  Jail exposure is via devfs ruleset at the host
 * administrator's discretion.
 */

/* ----------------------------------------------------------------
 * Module lifecycle
 * ---------------------------------------------------------------- */

static int
brfs_modevent(module_t mod __unused, int type, void *data __unused)
{
	u_int i, j;
	int error;

	switch (type) {
	case MOD_LOAD:
		mtx_init(&brfs_ring_mtx, "brfs ring", NULL, MTX_DEF);
		mtx_init(&brfs_walk_mtx, "brfs walk", NULL, MTX_DEF);
		rm_init(&brfs_roots_rm, "brfs roots");
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
		brfs_vecs_count = 0;
		brfs_tap_seen = 0;
		brfs_tap_emitted = 0;
		brfs_dirs_flagged = 0;
		brfs_files_flagged = 0;
		brfs_dev_open = 0;
		brfs_dev_dying = 0;
		for (i = 0; i < nitems(brfs_walkjobs); i++)
			TASK_INIT(&brfs_walkjobs[i].wj_task, 0,
			    brfs_walk_task, &brfs_walkjobs[i]);
		knlist_init_mtx(&brfs_sel.si_note, &brfs_ring_mtx);
		brfs_cdev = make_dev(&brfs_cdevsw, 0, UID_ROOT, GID_WHEEL,
		    0600, BRFS_DEV_NAME);
		return (brfs_cdev == NULL ? ENXIO : 0);

	case MOD_QUIESCE:
		/*
		 * Veto unload while /dev/brfs is open so no fd can be left
		 * pointing at a cdevsw in unloaded module text; set dying at
		 * quiesce time so an open(2) racing the unload fails instead
		 * of establishing a new fd against a device about to be
		 * destroyed.
		 *
		 * Note: this linker file contains exactly one module, so the
		 * only QUIESCE veto that can abort an unload after ours
		 * succeeds is ours — dying can never be left stale by
		 * another module's veto.  If this file ever grows a second
		 * module, dying must be cleared when MOD_UNLOAD reports
		 * failure.
		 */
		mtx_lock(&brfs_ring_mtx);
		error = brfs_dev_open ? EBUSY : 0;
		if (error == 0)
			brfs_dev_dying = 1;
		mtx_unlock(&brfs_ring_mtx);
		return (error);

	case MOD_UNLOAD:
		/*
		 * Stop the tap first: restore every patched vop vector so
		 * no new interposer call can start, then give in-flight
		 * calls a grace period before freeing the state they
		 * touch.  In-flight tap calls are bounded (the only sleep
		 * is a GETATTR on a caller-locked vnode); the pause covers
		 * UFS/ZFS.  A hard guarantee needs an epoch-style drain —
		 * Phase 2 hardening, noted in the P0.2 GO record.
		 */
		rm_wlock(&brfs_roots_rm);
		for (i = 0; i < brfs_roots_count; i++) {
			if (brfs_roots[i].vp != NULL) {
				(void)brfs_flag_subtree(brfs_roots[i].vp,
				    NULL, curthread, true);
				vrele(brfs_roots[i].vp);
			}
			for (j = 0; j < brfs_roots[i].nvecs; j++)
				brfs_vec_unref(brfs_roots[i].vecs[j]);
		}
		brfs_roots_count = 0;
		/* Belt & braces: restore anything still patched. */
		for (i = 0; i < brfs_vecs_count; i++)
			brfs_vecs[i].bp_vec->vop_inotify =
			    brfs_vecs[i].bp_orig;
		brfs_vecs_count = 0;
		rm_wunlock(&brfs_roots_rm);
		pause("brfsunld", hz);

		/* Tap is quiescent: drain deferred subtree walks. */
		for (i = 0; i < nitems(brfs_walkjobs); i++)
			if (brfs_walkjobs[i].wj_vp != NULL)
				taskqueue_drain(taskqueue_thread,
				    &brfs_walkjobs[i].wj_task);
		mtx_destroy(&brfs_walk_mtx);

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
		rm_destroy(&brfs_roots_rm);
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
