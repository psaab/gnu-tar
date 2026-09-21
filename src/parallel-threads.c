/* Parallel extraction engine for GNU tar.

   Copyright 2026 Free Software Foundation, Inc.

   This file is part of GNU tar.

   GNU tar is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   GNU tar is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Overview

   Ordinary extraction materializes one member at a time, so every
   create, mkdir, set-times and close is a serialized round-trip.  On a
   network filesystem that is the whole cost.  This engine keeps the
   archive parser on the main thread and fans the filesystem work out:

     main thread --jobs--> io thread --open fds--> data writers --> metadata
                           (io_uring: openat2,      (write)          pool
                            mkdirat, symlinkat,                      (futimens,
                            linkat, close)                           fchown,
                                ^                                    fchmod)
                                +---------- close requests ----------+

   The io thread issues every create and close as an asynchronous
   io_uring operation, so the kernel's worker pool keeps thousands of
   them in flight.  It enforces parent-before-child and target-before-
   hardlink ordering from local state, never by waiting on the
   filesystem.  Like fdbase() in misc.c, it resolves parent directories
   with RESOLVE_BENEATH so nothing escapes the extraction directory; a
   small cache of parent directory descriptors keeps that cheap.
   Setting times has no asynchronous form, so it runs on a pool of
   threads that grows itself while there is a backlog and each growth
   step still raises measured throughput.

   Directory permissions and times are handled by extract.c's existing
   delayed_set_stat machinery, forced into "restore at the end" mode,
   and applied depth by depth through the metadata pool.

   Members the engine does not handle (sparse files, link placeholders,
   dump directories) are extracted the ordinary way after a barrier that
   waits for the pipeline to become idle, so the two paths never race.  */

#include <system.h>

#include "common.h"

#if TAR_PARALLEL && TAR_PARALLEL_THREADS

#include <pthread.h>
#include <poll.h>
#include <sys/eventfd.h>
#ifdef __GLIBC__
# include <malloc.h>
#endif
#include <sys/resource.h>
#include <sys/vfs.h>

/* liburing's inline helpers do not survive tar's stricter warnings.  */
#if defined __GNUC__
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wcast-align"
# pragma GCC diagnostic ignored "-Wbad-function-cast"
#endif
#include <liburing.h>
#if defined __GNUC__
# pragma GCC diagnostic pop
#endif

#include <flexmember.h>
#include <hash.h>
#include <quotearg.h>
#include <xvasprintf.h>

/* True while the engine is running.  */
bool parallel_active;

enum { CHUNK_SIZE = 1 << 20 };		/* max bytes per data chunk */
enum { DATA_BUDGET = 256 << 20 };	/* bytes buffered before the writers */
enum { MAX_INFLIGHT_OPS = 4096 };	/* cap on ring operations in flight */
enum { RING_ENTRIES = 4096 };
enum { PDIR_CACHE_MAX = 256 };		/* parent directory fds kept open */
enum { MIN_NOFILE = 32 };		/* below this, extract sequentially */
enum { QUOTE_SLOT = 8 };		/* quotearg slots reserved for workers */
#define SCALER_TICK_NS 250000000L
#define SCALER_COOLDOWN_NS 2000000000L
#define SCALER_GAIN 1.10

/* ------------------------------------------------------------------ */
/* Diagnostics.  quotearg keeps per-slot buffers, so give the worker
   threads their own slots and serialize their use.  The message texts
   mirror paxlib's helpers so that output is identical to the ordinary
   extraction path.  */

static pthread_mutex_t diag_mutex = PTHREAD_MUTEX_INITIALIZER;

static char const *
q0 (char const *name)
{
  return quotearg_n_style_colon (QUOTE_SLOT, shell_escape_quoting_style, name);
}

static char const *
q1 (char const *name)
{
  return quotearg_n_style (QUOTE_SLOT + 1, shell_escape_quoting_style, name);
}

/* "NAME: Cannot CALL: strerror".  */
static void
call_error (int errnum, char const *call, char const *name)
{
  pthread_mutex_lock (&diag_mutex);
  paxerror (errnum, _("%s: Cannot %s"), q0 (name), call);
  pthread_mutex_unlock (&diag_mutex);
}

static void
link_error_p (int errnum, char const *target, char const *name)
{
  pthread_mutex_lock (&diag_mutex);
  paxerror (errnum, _("%s: Cannot hard link to %s"), q0 (name), q1 (target));
  pthread_mutex_unlock (&diag_mutex);
}

static void
symlink_error_p (int errnum, char const *contents, char const *name)
{
  pthread_mutex_lock (&diag_mutex);
  paxerror (errnum, _("%s: Cannot create symlink to %s"),
	    q0 (name), q1 (contents));
  pthread_mutex_unlock (&diag_mutex);
}

static void
chmod_error_p (int errnum, char const *name, mode_t mode)
{
  char buf[10];
  pax_decode_mode (mode, buf);
  pthread_mutex_lock (&diag_mutex);
  paxerror (errnum, _("%s: Cannot change mode to %s"), q0 (name), buf);
  pthread_mutex_unlock (&diag_mutex);
}

static void
chown_error_p (int errnum, char const *name, uid_t uid, gid_t gid)
{
  pthread_mutex_lock (&diag_mutex);
  paxerror (errnum, _("%s: Cannot change ownership to uid %ju, gid %ju"),
	    q0 (name), (uintmax_t) uid, (uintmax_t) gid);
  pthread_mutex_unlock (&diag_mutex);
}

static void
write_error_p (char const *name, idx_t status, idx_t size)
{
  pthread_mutex_lock (&diag_mutex);
  if (status == 0)
    paxerror (errno, _("%s: Cannot write"), q0 (name));
  else
    paxerror (0, ngettext ("%s: Wrote only %td of %td byte",
			   "%s: Wrote only %td of %td bytes", size),
	      q0 (name), (ptrdiff_t) status, (ptrdiff_t) size);
  pthread_mutex_unlock (&diag_mutex);
}

static void
skip_existing_warn (char const *name)
{
  pthread_mutex_lock (&diag_mutex);
  warnopt (WARN_EXISTING_FILE, 0, _("%s: skipping existing file"),
	   q0 (name));
  pthread_mutex_unlock (&diag_mutex);
}

static void
plain_error (int errnum, char const *msg)
{
  pthread_mutex_lock (&diag_mutex);
  paxerror (errnum, "%s", msg);
  pthread_mutex_unlock (&diag_mutex);
}

/* ------------------------------------------------------------------ */
/* Data chunks and the byte budget that back-pressures the parser.  */

struct chunk
{
  struct chunk *next;
  idx_t len;			/* bytes filled */
  idx_t cap;			/* bytes reserved from the budget */
  char data[FLEXIBLE_ARRAY_MEMBER];
};

static pthread_mutex_t budget_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t budget_cond = PTHREAD_COND_INITIALIZER;
static idx_t budget_used;
static idx_t budget_max = DATA_BUDGET;	/* less under an address-space limit */

static void
budget_acquire (idx_t n)
{
  pthread_mutex_lock (&budget_mutex);
  while (! (budget_used + n <= budget_max
	    || (budget_used == 0 && n > budget_max)))
    pthread_cond_wait (&budget_cond, &budget_mutex);
  budget_used += n;
  pthread_mutex_unlock (&budget_mutex);
}

static void
budget_release (idx_t n)
{
  pthread_mutex_lock (&budget_mutex);
  budget_used -= n;
  pthread_cond_broadcast (&budget_cond);
  pthread_mutex_unlock (&budget_mutex);
}

static void
chunk_free (struct chunk *c)
{
  budget_release (c->cap);
  free (c);
}

/* ------------------------------------------------------------------ */
/* Jobs.  */

enum job_kind { JOB_DIR, JOB_FILE, JOB_SYMLINK, JOB_LINK, JOB_NODE, JOB_FIFO,
		JOB_TASK };

/* Where a job is in its life on the io thread.  */
enum job_stage { STAGE_PARENT, STAGE_OPENING, STAGE_OP };

struct pdir;
struct node;

/* A job waiting to learn whether a parent is plain; one record per
   parent, since a hard link waits on two.  */
struct class_sub
{
  struct job *job;
  struct class_sub *next;
};

struct job
{
  struct job *next;		/* queue link */
  enum job_kind kind;
  enum job_stage stage;
  char *name;			/* file name, relative to WDFD */
  char *key;			/* "<dir index>\1<normalized NAME>" */
  char *link;			/* symlink contents or hard link target name */
  char *link_key;		/* LINK keyed like KEY (hard links only) */
  int wdfd;			/* directory fd for the member's -C dir */
  idx_t change_dir;		/* index of that dir, for delay_set_stat */
  char typeflag;
  bool implicit;		/* directory not mentioned in the archive */
  bool replaced;		/* an existing entry was removed already */
  bool removed_dir;		/* discard its delayed directory metadata */
  bool has_slot;		/* holds one of the descriptor slots */
  bool orphaned;		/* io thread is done with a job the parser
				   is still feeding; the parser frees it */
  bool aliased;			/* its path crosses a symlink or a mount:
				   run alone, resolving the path plainly */
  bool class_pending;		/* in the unclassified list */
  int class_wait;		/* parents whose kind is still unknown */
  bool tparent_probe;		/* the target's parent is only known once
				   opened (the archive never makes it) */
  int retries;			/* attempts after EMFILE or ENFILE */
  idx_t seq;			/* archive order, from 1 */
  struct job *ord_prev, *ord_next;	/* all unfinished jobs, by SEQ */
  struct job *uc_prev, *uc_next;	/* unclassified jobs, by SEQ */
  struct job *al_prev, *al_next;	/* unfinished aliased jobs, by SEQ */
  struct node *parent_node;	/* nearest ancestor's occurrence */
  struct node *tparent_node;	/* same for a hard link's target */
  struct node *node;		/* this occurrence of the member */
  struct node *previous;		/* preceding occurrence of this name */
  struct node **parents;		/* preceding occurrences of ancestors */
  idx_t nparents;
  struct node *target;		/* hard link: the target's node, held
				   (PENDING) until the link is made */
  mode_t create_mode;		/* mode passed to open/mkdir/mknod */
  struct stat st;		/* archive metadata */
  struct timespec atime, mtime;
  off_t size;
  int fd;			/* open descriptor once created */
  mode_t current_mode, current_mode_mask;

  /* Parent directory of NAME (and of LINK for hard links), resolved
     beneath WDFD.  PFD is WDFD itself when NAME has no slash.  */
  struct pdir *pdir, *tpdir;
  int pfd, tpfd;
  char const *base, *tbase;

  /* openat2 arguments; must stay valid until the operation completes,
     which is why they live in the (heap-allocated, stable) job.  */
  struct open_how how;

  /* Data chunks, produced by the parser, consumed by a writer.  */
  pthread_mutex_t data_mutex;
  pthread_cond_t data_cond;
  struct chunk *chunk_head, *chunk_tail;
  bool data_done;
};

/* Generic tasks (directory metadata at the end) travel through the
   metadata pool wrapped in a job of kind JOB_TASK.  */
struct task_job
{
  struct job job;		/* must be first */
  void (*fn) (void *);
  void *arg;
};

static struct job *
job_new (enum job_kind kind, char const *name)
{
  struct job *j = xzalloc (sizeof *j);
  j->kind = kind;
  j->name = xstrdup (name);
  j->fd = -1;
  j->pfd = j->tpfd = -1;
  pthread_mutex_init (&j->data_mutex, NULL);
  pthread_cond_init (&j->data_cond, NULL);
  return j;
}

static void
job_free (struct job *j)
{
  if (! j)
    return;
  for (struct chunk *c = j->chunk_head; c; )
    {
      struct chunk *n = c->next;
      chunk_free (c);
      c = n;
    }
  if (0 <= j->fd)
    close (j->fd);
  pthread_mutex_destroy (&j->data_mutex);
  pthread_cond_destroy (&j->data_cond);
  free (j->name);
  free (j->key);
  free (j->link);
  free (j->link_key);
  free (j->parents);
  free (j);
}

/* Release J from the io thread's point of view.  A regular-file job
   that the parser is still streaming into must survive until the
   parser is done with it (it frees the job then); see push_chunk.  */
static void
job_release (struct job *j)
{
  if (j->kind == JOB_FILE)
    {
      struct chunk *discard = NULL;
      pthread_mutex_lock (&j->data_mutex);
      bool streaming = ! j->data_done;
      if (streaming)
	{
	  j->orphaned = true;
	  discard = j->chunk_head;
	  j->chunk_head = j->chunk_tail = NULL;
	}
      pthread_mutex_unlock (&j->data_mutex);
      if (streaming)
	{
	  /* The parser may be waiting for this buffer budget before it
	     can finish.  It may also free J as soon as the mutex is
	     unlocked, so only use the detached chunks from here on.  */
	  while (discard)
	    {
	      struct chunk *next = discard->next;
	      chunk_free (discard);
	      discard = next;
	    }
	  return;
	}
    }
  job_free (j);
}

/* Normalize NAME for map lookups: drop "./" prefixes, empty and "."
   components, and a trailing slash.  Preserve a leading slash, which
   --strip-components can expose after safer_name_suffix has run, so
   parent paths derived from the key remain absolute.  Leave ".."
   components unchanged.  */
static char *
normalize_key (char const *name)
{
  char *out = xmalloc (strlen (name) + 2);
  char *o = out;
  if (*name == '/')
    *o++ = '/';
  char *start = o;
  char const *p = name;
  while (*p)
    {
      while (*p == '/')
	p++;
      char const *e = strchr (p, '/');
      idx_t len = e ? e - p : (idx_t) strlen (p);
      if (len == 0)
	break;
      if (! (len == 1 && p[0] == '.'))
	{
	  if (o != start)
	    *o++ = '/';
	  memcpy (o, p, len);
	  o += len;
	}
      p += len;
    }
  *o = '\0';
  return out;
}

/* The first '/' of a key's name that separates components; the leading
   slash of an absolute name is not one.  */
static char *
first_separator (char *name)
{
  return strchr (name + (*name == '/'), '/');
}

/* Ordering keys: the -C directory index, a \1 separator, and the
   normalized name, so that equal names under different destinations
   are different entries.  */
static char *
make_key (idx_t change_dir, char const *normalized)
{
  return xasprintf ("%jd\1%s", (intmax_t) change_dir, normalized);
}

static char const *
key_name (char const *key)
{
  return strchr (key, '\1') + 1;
}

/* Key of KEY's parent directory, or NULL for a top-level name.  */
static char *
parent_key (char const *key)
{
  char const *name = key_name (key);
  char const *slash = strrchr (name, '/');
  return slash ? ximemdup0 (key, slash - key) : NULL;
}

/* ------------------------------------------------------------------ */
/* Simple intrusive FIFO queues protected by a mutex.  */

struct jobq
{
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  struct job *head, *tail;
  idx_t len;
  bool closed;
  bool wakes_io;		/* consumed by the io thread; see io_wake */
};

static void io_wake (void);

static void
jobq_init (struct jobq *q)
{
  pthread_mutex_init (&q->mutex, NULL);
  pthread_cond_init (&q->cond, NULL);
  q->head = q->tail = NULL;
  q->len = 0;
  q->closed = false;
  q->wakes_io = false;
}

static void
jobq_push (struct jobq *q, struct job *j)
{
  j->next = NULL;
  pthread_mutex_lock (&q->mutex);
  if (q->tail)
    q->tail->next = j;
  else
    q->head = j;
  q->tail = j;
  q->len++;
  pthread_cond_signal (&q->cond);
  pthread_mutex_unlock (&q->mutex);
  if (q->wakes_io)
    io_wake ();
}

static bool
jobq_empty (struct jobq *q)
{
  pthread_mutex_lock (&q->mutex);
  bool empty = ! q->head;
  pthread_mutex_unlock (&q->mutex);
  return empty;
}

/* Pop one job, blocking; NULL once the queue is closed and empty.  */
static struct job *
jobq_pop (struct jobq *q)
{
  pthread_mutex_lock (&q->mutex);
  while (! q->head && ! q->closed)
    pthread_cond_wait (&q->cond, &q->mutex);
  struct job *j = q->head;
  if (j)
    {
      q->head = j->next;
      if (! q->head)
	q->tail = NULL;
      q->len--;
    }
  pthread_mutex_unlock (&q->mutex);
  return j;
}

/* Detach the whole queue contents without blocking.  */
static struct job *
jobq_drain (struct jobq *q)
{
  pthread_mutex_lock (&q->mutex);
  struct job *j = q->head;
  q->head = q->tail = NULL;
  q->len = 0;
  pthread_mutex_unlock (&q->mutex);
  return j;
}

/* Put a chain back at the front (after a partial drain).  */
static void
jobq_unshift (struct jobq *q, struct job *chain)
{
  if (! chain)
    return;
  struct job *tail = chain;
  idx_t n = 1;
  while (tail->next)
    {
      tail = tail->next;
      n++;
    }
  pthread_mutex_lock (&q->mutex);
  tail->next = q->head;
  q->head = chain;
  if (! q->tail)
    q->tail = tail;
  q->len += n;
  pthread_mutex_unlock (&q->mutex);
}

static void
jobq_close (struct jobq *q)
{
  pthread_mutex_lock (&q->mutex);
  q->closed = true;
  pthread_cond_broadcast (&q->cond);
  pthread_mutex_unlock (&q->mutex);
}

/* ------------------------------------------------------------------ */
/* Pipeline state.  */

static struct jobq in_q;	/* main -> io thread */
static struct jobq close_q;	/* metadata pool -> io thread (fds to close) */
static struct jobq done_q;	/* metadata pool -> io thread (finished jobs) */
static struct jobq write_q;	/* io thread -> data writers */
static struct jobq meta_q;	/* -> metadata pool */

/* The io thread sleeps in the ring's wait; other threads wake it
   through an eventfd that it polls with the ring.  IO_SLEEPING is set
   by the io thread just before it re-checks its queues and sleeps, so
   a push that finds it set knows the io thread has not seen the job
   and must be woken.  */
static int wake_fd = -1;
static pthread_mutex_t wake_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool io_sleeping;

static void
io_wake (void)
{
  if (wake_fd < 0)
    return;
  pthread_mutex_lock (&wake_mutex);
  bool sleeping = io_sleeping;
  io_sleeping = false;
  pthread_mutex_unlock (&wake_mutex);
  if (sleeping)
    {
      uint64_t one = 1;
      if (write (wake_fd, &one, sizeof one) < 0)
	{
	  /* EAGAIN: already signaled.  */
	}
    }
}

/* Jobs dispatched but not finished; the barrier waits for zero.  */
static pthread_mutex_t inflight_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t inflight_cond = PTHREAD_COND_INITIALIZER;
static idx_t inflight;

static void
track_dispatch (void)
{
  pthread_mutex_lock (&inflight_mutex);
  inflight++;
  pthread_mutex_unlock (&inflight_mutex);
}

static void
job_done (void)
{
  pthread_mutex_lock (&inflight_mutex);
  if (--inflight == 0)
    pthread_cond_broadcast (&inflight_cond);
  pthread_mutex_unlock (&inflight_mutex);
}

/* Wait until every dispatched job has finished.  */
void
parallel_barrier (void)
{
  if (! parallel_active)
    return;
  pthread_mutex_lock (&inflight_mutex);
  while (inflight > 0)
    pthread_cond_wait (&inflight_cond, &inflight_mutex);
  pthread_mutex_unlock (&inflight_mutex);
  /* Worker namespace changes bypass the ordinary extractor's cache
     invalidation.  Do not reuse its parent descriptors across a barrier.  */
  fdbase_clear ();
}

/* Tasks finished by the metadata pool; drives the auto-scaler.  */
static pthread_mutex_t meta_done_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long meta_completed;

static void
meta_completed_add (void)
{
  pthread_mutex_lock (&meta_done_mutex);
  meta_completed++;
  pthread_mutex_unlock (&meta_done_mutex);
}

static unsigned long long
meta_completed_get (void)
{
  pthread_mutex_lock (&meta_done_mutex);
  unsigned long long n = meta_completed;
  pthread_mutex_unlock (&meta_done_mutex);
  return n;
}

static idx_t meta_threads;		/* current pool size */
static idx_t meta_threads_max;
static pthread_t *meta_tids;
static idx_t meta_tids_alloc;
static pthread_t io_tid;
static pthread_t *writer_tids;
static idx_t writer_count;
static pthread_t main_tid;

/* A fatal error on a worker thread (xalloc_die, say) reaches the
   fatal-exit hook on that thread.  It must not wait for the engine:
   just let the hook clean up the ordinary way and exit.  */
static bool
on_main_thread (void)
{
  if (pthread_equal (pthread_self (), main_tid))
    return true;
  parallel_active = false;
  return false;
}

/* One working-directory descriptor, shared until a -C boundary.  Only
   the main thread changes it, after draining all jobs that use it.  */
static int wd_fd = -1;
static idx_t wd_change_dir;

/* Directories whose creation has been dispatched; main thread, valid
   only in the current -C context.  */
static Hash_table *dispatched_dirs;

/* Descriptor budget, all on the io thread: SLOTS_MAX descriptors held
   by regular files and symlinks between creation and close, and up to
   PDIR_MAX cached parent directories.  The metadata pool's transient
   descriptors are bounded by its thread count.  */
static idx_t slots_max, slots_used;
static idx_t pdir_max;
static bool is_network_fs;

/* ------------------------------------------------------------------ */
/* Metadata application (shared by files, symlinks, directories).
   Mirrors set_stat in extract.c; everything goes through descriptors
   so it is safe off the main thread.  */

/* Set the times of the object open on FD.  FD may be an O_PATH
   descriptor (symlinks, unreadable directories), which futimens
   rejects; use AT_EMPTY_PATH then, and as a last resort the path
   BASE relative to DFD.  */
static void
apply_times (int fd, int dfd, char const *base, char const *name,
	     struct timespec atime, struct timespec mtime, char typeflag)
{
  if (touch_option)
    return;
  struct timespec ts[2];
  if (incremental_option)
    ts[0] = atime;
  else
    ts[0].tv_nsec = UTIME_OMIT;
  ts[1] = mtime;
  int r = futimens (fd, ts);
  if (r < 0 && errno == EBADF)
    r = utimensat (fd, "", ts, AT_EMPTY_PATH);
  if (r < 0 && (errno == EBADF || errno == EINVAL || errno == ENOENT))
    r = utimensat (dfd, base, ts, AT_SYMLINK_NOFOLLOW);
  if (r < 0 && (typeflag != SYMTYPE || errno != ENOSYS))
    call_error (errno, "utime", name);
}

static void
apply_owner (int fd, char const *name, uid_t uid, gid_t gid, char typeflag,
	     mode_t *current_mode, mode_t *current_mode_mask)
{
  if (! (0 < same_owner_option))
    return;
  int r = fchown (fd, uid, gid);
  if (r < 0 && errno == EBADF)
    r = fchownat (fd, "", uid, gid, AT_EMPTY_PATH);
  if (r == 0)
    {
      /* Changing the owner can clear st_mode bits in some cases.  */
      if ((*current_mode | ~ *current_mode_mask) & S_IXUGO)
	*current_mode_mask &= ~ (*current_mode & (S_ISUID | S_ISGID));
    }
  else if (typeflag != SYMTYPE || errno != ENOSYS)
    chown_error_p (errno, name, uid, gid);
}

/* Set the mode of FD (a non-symlink) to MODE, considering the bits in
   MODE_MASK, given what is known about the current mode.  If FD is an
   O_PATH descriptor, fall back to BASE relative to DFD.  */
static void
apply_mode (int fd, int dfd, char const *base, char const *name,
	    mode_t mode, mode_t mode_mask,
	    mode_t current_mode, mode_t current_mode_mask)
{
  if (((current_mode ^ mode) | ~ current_mode_mask) & mode_mask)
    {
      if (MODE_ALL & ~ (mode_mask & current_mode_mask))
	{
	  struct stat st;
	  if (fstat (fd, &st) < 0)
	    {
	      call_error (errno, "stat", name);
	      return;
	    }
	  current_mode = st.st_mode;
	}
      current_mode &= MODE_ALL;
      mode = (current_mode & ~ mode_mask) | (mode & mode_mask);
      if (current_mode != mode)
	{
	  int r = fchmod (fd, mode);
	  if (r < 0 && errno == EBADF)
	    r = fchmodat (dfd, base, mode, 0);
	  if (r < 0)
	    chmod_error_p (errno, name, mode);
	}
    }
}

static void
apply_stat (struct job *j)
{
  mode_t cur = j->current_mode, mask = j->current_mode_mask;
  apply_times (j->fd, j->wdfd, j->name, j->name, j->atime, j->mtime,
	       j->typeflag);
  apply_owner (j->fd, j->name, j->st.st_uid, j->st.st_gid, j->typeflag,
	       &cur, &mask);
  if (j->typeflag != SYMTYPE)
    apply_mode (j->fd, j->wdfd, j->name, j->name,
		j->st.st_mode & ~ parallel_current_umask (),
		0 < same_permissions_option ? MODE_ALL : MODE_RWX, cur, mask);
}

/* ------------------------------------------------------------------ */
/* Data writers.  */

static void *
writer_main (MAYBE_UNUSED void *arg)
{
  for (struct job *j; (j = jobq_pop (&write_q)); )
    {
      off_t written = 0;
      bool ok = true;
      for (;;)
	{
	  pthread_mutex_lock (&j->data_mutex);
	  while (! j->chunk_head && ! j->data_done)
	    pthread_cond_wait (&j->data_cond, &j->data_mutex);
	  struct chunk *c = j->chunk_head;
	  if (c)
	    {
	      j->chunk_head = c->next;
	      if (! j->chunk_head)
		j->chunk_tail = NULL;
	    }
	  pthread_mutex_unlock (&j->data_mutex);
	  if (! c)
	    break;
	  if (ok)
	    {
	      errno = 0;
	      idx_t n = blocking_write (j->fd, c->data, c->len);
	      if (n != c->len)
		{
		  write_error_p (j->name, n, c->len);
		  ok = false;
		}
	      written += n;
	    }
	  chunk_free (c);
	}
      (void) written;
      jobq_push (&meta_q, j);
    }
  return NULL;
}

/* ------------------------------------------------------------------ */
/* Metadata pool.  */

/* Open the parent directory of NAME (relative to WDFD) beneath WDFD,
   for synchronous use.  Return the fd (WDFD itself if NAME has no
   slash; then *BASE = NAME) or -1 with errno set.  */
static int
open_parent_sync (int wdfd, char const *name, char const **base, bool *owned)
{
  char const *slash = strrchr (name, '/');
  *owned = false;
  if (! slash)
    {
      *base = name;
      return wdfd;
    }
  /* Keep the trailing slash: it makes a final symlink to a directory
     acceptable despite O_NOFOLLOW, exactly as fdbase does.  */
  char *parent = ximemdup0 (name, slash + 1 - name);
  struct open_how how;
  memset (&how, 0, sizeof how);
  how.flags = O_PATH | O_DIRECTORY | O_CLOEXEC
	      | (dereference_option ? 0 : O_NOFOLLOW);
  how.resolve = RESOLVE_BENEATH;
  int fd = openat2 (wdfd, parent, &how, sizeof how);
  free (parent);
  if (fd < 0)
    return -1;
  *base = slash + 1;
  *owned = true;
  return fd;
}

/* Remove whatever is at BASE relative to DFD so that creation can be
   retried.  Mirrors remove_any_file (…, ORDINARY_REMOVE_OPTION).  */
static bool
remove_existing_at (struct job *j, int dfd, char const *base)
{
  if (unlinkat (dfd, base, 0) == 0)
    return true;
  if (errno == EISDIR || errno == EPERM)
    {
      if (unlinkat (dfd, base, AT_REMOVEDIR) == 0)
	{
	  j->removed_dir = true;
	  return true;
	}
    }
  return false;
}

static void
make_special (struct job *j)
{
  char const *base;
  bool owned;
  int pfd = open_parent_sync (j->wdfd, j->name, &base, &owned);
  if (pfd < 0)
    {
      call_error (errno, j->kind == JOB_FIFO ? "mkfifo" : "mknod", j->name);
      return;
    }
  int r;
  for (;;)
    {
      r = (j->kind == JOB_FIFO
	   ? mkfifoat (pfd, base, j->create_mode)
	   : mknodat (pfd, base, j->create_mode, j->st.st_rdev));
      if (r == 0 || errno != EEXIST || j->replaced)
	break;
      if (old_files_option == SKIP_OLD_FILES)
	{
	  skip_existing_warn (j->name);
	  goto out;
	}
      if (old_files_option == KEEP_OLD_FILES
	  || old_files_option == KEEP_NEWER_FILES
	  || ! remove_existing_at (j, pfd, base))
	{
	  errno = EEXIST;
	  break;
	}
      j->replaced = true;
    }
  if (r < 0)
    {
      call_error (errno, j->kind == JOB_FIFO ? "mkfifo" : "mknod", j->name);
      goto out;
    }
  j->current_mode = j->create_mode & ~ parallel_current_umask ();
  j->current_mode_mask = MODE_RWX;
  j->fd = openat (pfd, base, O_PATH | O_NOFOLLOW | O_CLOEXEC);
  if (0 <= j->fd)
    {
      mode_t cur = j->current_mode, mask = j->current_mode_mask;
      apply_times (j->fd, pfd, base, j->name, j->atime, j->mtime, j->typeflag);
      apply_owner (j->fd, j->name, j->st.st_uid, j->st.st_gid,
		   j->typeflag, &cur, &mask);
      apply_mode (j->fd, pfd, base, j->name,
		  j->st.st_mode & ~ parallel_current_umask (),
		  0 < same_permissions_option ? MODE_ALL : MODE_RWX, cur, mask);
    }
 out:
  if (owned)
    close (pfd);
}

static void
close_via_io_thread (struct job *j)
{
  jobq_push (&close_q, j);
}

static void *
meta_main (MAYBE_UNUSED void *arg)
{
  for (struct job *j; (j = jobq_pop (&meta_q)); )
    {
      switch (j->kind)
	{
	case JOB_FILE:
	case JOB_SYMLINK:
	  apply_stat (j);
	  close_via_io_thread (j);
	  break;

	case JOB_NODE:
	case JOB_FIFO:
	  make_special (j);
	  jobq_push (&done_q, j);	/* the io thread finishes it */
	  break;

	case JOB_TASK:
	  {
	    struct task_job *t = (struct task_job *) j;
	    t->fn (t->arg);
	    job_done ();
	    free (t);
	  }
	  break;

	case JOB_DIR:
	case JOB_LINK:
	  unreachable ();
	}
      meta_completed_add ();
    }
  return NULL;
}

/* Start a worker thread with a modest stack: the workers need little,
   and there may be many of them under a tight address-space limit.
   Return 0 or an error number.  */
enum { THREAD_STACK_SIZE = 512 * 1024 };

static int
start_thread (pthread_t *tid, void *(*fn) (void *))
{
  pthread_attr_t attr;
  int r = pthread_attr_init (&attr);
  if (r != 0)
    return r;
  size_t size = THREAD_STACK_SIZE;
#ifdef PTHREAD_STACK_MIN
  if (size < (size_t) PTHREAD_STACK_MIN)
    size = PTHREAD_STACK_MIN;
#endif
  pthread_attr_setstacksize (&attr, size);
  r = pthread_create (tid, &attr, fn, NULL);
  pthread_attr_destroy (&attr);
  return r;
}

static void
spawn_meta_threads (idx_t n)
{
  for (idx_t i = 0; i < n && meta_threads < meta_threads_max; i++)
    {
      if (meta_tids_alloc <= meta_threads)
	meta_tids = xpalloc (meta_tids, &meta_tids_alloc, 1, -1,
			     sizeof *meta_tids);
      if (start_thread (&meta_tids[meta_threads], meta_main) != 0)
	{
	  meta_threads_max = meta_threads ? meta_threads : 1;
	  break;
	}
      meta_threads++;
    }
}

/* Auto-scaler: grow the pool while work is queued and the previous
   growth step raised throughput.  */
struct scaler
{
  struct timespec next_tick, last_time, cooldown_until;
  unsigned long long last_completed;
  double probing_rate;
  bool probing;
};
static struct scaler scaler;

static long long
ts_diff_ns (struct timespec a, struct timespec b)
{
  return (a.tv_sec - b.tv_sec) * 1000000000LL + (a.tv_nsec - b.tv_nsec);
}

static struct timespec
ts_add_ns (struct timespec a, long long ns)
{
  a.tv_sec += ns / 1000000000LL;
  a.tv_nsec += ns % 1000000000LL;
  if (a.tv_nsec >= 1000000000L)
    {
      a.tv_sec++;
      a.tv_nsec -= 1000000000L;
    }
  return a;
}

static void
scaler_tick (void)
{
  struct timespec now;
  clock_gettime (CLOCK_MONOTONIC, &now);
  if (ts_diff_ns (now, scaler.next_tick) < 0)
    return;
  scaler.next_tick = ts_add_ns (now, SCALER_TICK_NS);
  unsigned long long completed = meta_completed_get ();
  double dt = ts_diff_ns (now, scaler.last_time) / 1e9;
  if (dt < 1e-3)
    dt = 1e-3;
  double rate = (completed - scaler.last_completed) / dt;
  scaler.last_completed = completed;
  scaler.last_time = now;

  if (scaler.probing)
    {
      scaler.probing = false;
      if (rate < scaler.probing_rate * SCALER_GAIN)
	{
	  /* More threads did not buy more throughput: saturated.  */
	  scaler.cooldown_until = ts_add_ns (now, SCALER_COOLDOWN_NS);
	  return;
	}
    }
  pthread_mutex_lock (&meta_q.mutex);
  idx_t backlog = meta_q.len;
  pthread_mutex_unlock (&meta_q.mutex);
  if (backlog <= meta_threads / 2 || meta_threads >= meta_threads_max
      || ts_diff_ns (now, scaler.cooldown_until) < 0)
    return;
  idx_t step = backlog > meta_threads * 8 ? meta_threads : meta_threads / 2;
  if (step < 4)
    step = 4;
  if (step > meta_threads_max - meta_threads)
    step = meta_threads_max - meta_threads;
  scaler.probing = true;
  scaler.probing_rate = rate;
  spawn_meta_threads (step);
}

/* ------------------------------------------------------------------ */
/* The io thread.  Everything below runs on it, unless noted.  */

/* A list of parked jobs, released in the order they arrived so that
   archive order is kept.  */
struct jlist
{
  struct job *head, *tail;
};

/* One node per member occurrence.  ENTRIES names the latest occurrence,
   including members still waiting to start.  Earlier occurrences stay
   alive while jobs refer to them.  CREATED releases children and hard
   links; FINISHED together with PENDING releases replacements.  */
struct node
{
  char *key;
  bool created;
  bool finished;
  bool initial;			/* destination state before the archive */
  bool is_dir;			/* a directory member's occurrence */
  bool alias;			/* not a plain directory: a symlink, or a
				   pre-existing one; children of it may
				   alias other names */
  bool alias_known;		/* ALIAS has been determined */
  struct node *successor;	/* later directory member for the same
				   directory, which finds what we found */
  struct class_sub *class_waiters;	/* jobs waiting for ALIAS_KNOWN */
  idx_t refs;			/* map and job references */
  idx_t pending;		/* jobs using this path or linking to it */
  struct jlist wait_created;	/* hard links parked until CREATED */
  struct jlist wait_done;	/* same-name jobs parked until done */
};

static bool
node_done (struct node const *n)
{
  return n->finished && n->pending == 0;
}

static size_t
node_hash (void const *entry, size_t n)
{
  return hash_string (((struct node const *) entry)->key, n);
}

static bool
node_compare (void const *a, void const *b)
{
  return streq (((struct node const *) a)->key,
		((struct node const *) b)->key);
}

static void node_unref (void *entry);

static void
node_free (void *entry)
{
  struct node *n = entry;
  if (n->successor)
    node_unref (n->successor);
  free (n->key);
  free (n);
}

static Hash_table *entries;

static struct node *
node_lookup (Hash_table *t, char const *key)
{
  struct node probe;
  probe.key = (char *) key;
  return hash_lookup (t, &probe);
}

static struct node *
node_ref (struct node *n)
{
  n->refs++;
  return n;
}

static void
node_unref (void *entry)
{
  struct node *n = entry;
  if (--n->refs == 0)
    node_free (n);
}

/* A path used before its first archive member still has an initial
   namespace state.  Pin that state too, so a later member cannot
   overtake a hard link to a pre-existing (or missing) target.  */
static struct node *
node_current (char const *key)
{
  struct node *n = node_lookup (entries, key);
  if (! n)
    {
      n = xzalloc (sizeof *n);
      n->key = xstrdup (key);
      n->created = n->finished = true;
      n->initial = true;
      n->alias_known = true;	/* as a parent; a link's target parent is
				   probed instead, see register_job */
      n->refs = 1;		/* the map */
      if (! hash_insert (entries, n))
	xalloc_die ();
    }
  return n;
}

static void release_list (struct jlist *list);

static void
node_settle (struct node *n)
{
  if (node_done (n))
    release_list (&n->wait_done);
}

/* Parent directory descriptors, opened beneath the -C directory with
   RESOLVE_BENEATH and cached with reference counts.  */
struct pdir
{
  char *key;			/* same key as the directory's node */
  char *name;			/* parent name relative to WDFD, with "/" */
  int wdfd;
  int fd;			/* -1 while opening */
  int refs;			/* jobs currently using FD */
  bool opening;
  bool aliased;			/* opened plainly, for an aliased job */
  struct jlist waiters;		/* jobs to resume once FD is known */
  struct open_how how;
};

static Hash_table *pdirs;
static idx_t pdirs_count;
static struct jlist pdir_waiters;	/* jobs waiting for a cache slot */

static size_t
pdir_hash (void const *entry, size_t n)
{
  return hash_string (((struct pdir const *) entry)->key, n);
}

static bool
pdir_compare (void const *a, void const *b)
{
  return streq (((struct pdir const *) a)->key,
		((struct pdir const *) b)->key);
}

static void continue_job (struct job *j);

/* Wake the jobs waiting for a parent-cache slot.  */
static void
wake_pdir_waiters (void)
{
  struct job *w = pdir_waiters.head;
  pdir_waiters.head = pdir_waiters.tail = NULL;
  while (w)
    {
      struct job *next = w->next;
      continue_job (w);
      w = next;
    }
}

static void pdir_destroy (struct pdir *p);
static void submit_close_fd (int fd, struct job *j);

static void
pdir_release (struct pdir *p)
{
  if (! p)
    return;
  if (--p->refs == 0)
    {
      /* Share opens among concurrent jobs, but do not retain an idle
	 descriptor across replacement of this path or one of its
	 ancestors, including replacements by the ordinary extractor.  */
      pdir_destroy (p);
      if (pdir_waiters.head)
	wake_pdir_waiters ();
    }
}

static void
pdir_acquire (struct pdir *p)
{
  p->refs++;
}

static void
pdir_destroy (struct pdir *p)
{
  hash_remove (pdirs, p);
  pdirs_count--;
  if (0 <= p->fd)
    submit_close_fd (p->fd, NULL);
  free (p->key);
  free (p->name);
  free (p);
}

/* Reserve space for all of a job's parent directories at once.  */
static bool
pdirs_make_room (idx_t n)
{
  return pdirs_count + n <= pdir_max;
}

enum op_kind
  { OP_OPEN, OP_MKDIR, OP_SYMLINK, OP_LINK, OP_CLOSE, OP_OPENPARENT };

struct op
{
  enum op_kind kind;
  struct job *job;
  struct pdir *pdir;		/* OP_OPENPARENT */
  int close_fd;			/* OP_CLOSE */
  bool used;
};

static struct io_uring ring;
static bool ring_ready;
static struct op *ops;
static idx_t ops_alloc, ops_inflight;
static idx_t *free_ops, free_ops_count;
static struct job *slot_waiters_head, *slot_waiters_tail;
static bool jobs_open = true;
static unsigned io_resource_failures;

/* A failed submission or wait does not cancel requests or remove
   queued SQEs, so the job and parent-directory storage they refer to
   must survive until real completions arrive.  Retry resource
   shortages for a bounded number of attempts; other errors cannot be
   recovered from here.

   The main thread may be blocked reading the archive, where nothing
   can wake it, so exit from here.  With the engine marked inactive
   first, the fatal-exit hook (extract_finish) does not wait for this
   thread; it restores what directory metadata it can the ordinary way,
   and stdio is flushed as on any fatal error.  */
static _Noreturn void
io_fatal (int errnum, char const *message)
{
  plain_error (errnum, message);
  parallel_active = false;
  fatal_exit ();
}

static void
check_io_result (int result, char const *message)
{
  if (result == -EAGAIN || result == -ENOMEM)
    {
      if (++io_resource_failures < 100)
	{
	  struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000 };
	  nanosleep (&delay, NULL);
	  return;
	}
    }
  else if (result == -EINTR)
    return;
  else if (0 <= result || result == -ETIME)
    {
      io_resource_failures = 0;
      return;
    }
  io_fatal (-result, message);
}

static idx_t
op_alloc (enum op_kind kind, struct job *job)
{
  idx_t i;
  if (free_ops_count)
    i = free_ops[--free_ops_count];
  else
    {
      if (ops_alloc <= ops_inflight)
	{
	  idx_t old = ops_alloc;
	  ops = xpalloc (ops, &ops_alloc, 1, -1, sizeof *ops);
	  free_ops = xreallocarray (free_ops, ops_alloc, sizeof *free_ops);
	  for (idx_t k = old; k < ops_alloc; k++)
	    ops[k].used = false;
	}
      for (i = 0; ops[i].used; i++)
	continue;
    }
  ops[i].kind = kind;
  ops[i].job = job;
  ops[i].pdir = NULL;
  ops[i].used = true;
  ops_inflight++;
  return i;
}

static struct op *
op_take (idx_t i)
{
  ops[i].used = false;
  free_ops[free_ops_count++] = i;
  ops_inflight--;
  return &ops[i];
}

static struct io_uring_sqe *
get_sqe (void)
{
  struct io_uring_sqe *sqe = io_uring_get_sqe (&ring);
  while (! sqe)
    {
      int result = io_uring_submit (&ring);
      sqe = io_uring_get_sqe (&ring);
      /* Zero without room is another resource shortage, not progress.  */
      check_io_result (result == 0 && ! sqe ? -EAGAIN : result,
		       _("io_uring submission failed"));
    }
  return sqe;
}

static void fail_job (struct job *j, int errnum);
static void finish_job (struct job *j);

/* Aliases.  Ordering by pathname assumes that different names are
   different objects.  A symbolic link on the way breaks that: "l/f"
   and "d/f" are the same file when l -> d.  Directories the engine
   creates itself are plain; a directory member that finds something
   pre-existing, and any symbolic link, is not, and every member below
   such a parent is ALIASED.  An aliased member runs alone: after all
   earlier members have finished, before any later one starts, exactly
   as it would sequentially.  Later members must therefore also wait
   while an earlier directory's kind is still unknown (its mkdir is in
   flight), and while a hard link to a target under a directory the
   archive never mentions finds out what that directory is.

   Three lists in archive order drive this: all unfinished jobs, the
   unclassified ones, and the unfinished aliased ones.  The gate lets a
   job proceed to its operation when nothing earlier stands in the way;
   jobs it stops wait in GATE_WAITERS, also in archive order.  */
static struct job *unfinished_head, *unfinished_tail;
static struct job *unclassified_head, *unclassified_tail;
static struct job *aliased_head, *aliased_tail;
static struct jlist gate_waiters;
static idx_t job_seq;
/* Written by the I/O thread, read after it has been joined.  */
static bool aliases_seen;

static uint64_t
plain_resolve (bool aliased)
{
  return (RESOLVE_BENEATH
	  | (aliased ? 0 : RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV));
}

static bool
alias_errno (int errnum)
{
  return errnum == ELOOP || errnum == EXDEV;
}

static void
unfinished_add (struct job *j)
{
  j->ord_prev = unfinished_tail;
  j->ord_next = NULL;
  if (unfinished_tail)
    unfinished_tail->ord_next = j;
  else
    unfinished_head = j;
  unfinished_tail = j;
}

static void
unfinished_remove (struct job *j)
{
  if (j->ord_prev)
    j->ord_prev->ord_next = j->ord_next;
  else
    unfinished_head = j->ord_next;
  if (j->ord_next)
    j->ord_next->ord_prev = j->ord_prev;
  else
    unfinished_tail = j->ord_prev;
  j->ord_prev = j->ord_next = NULL;
}

static void
unclassified_add (struct job *j)
{
  j->uc_prev = unclassified_tail;
  j->uc_next = NULL;
  if (unclassified_tail)
    unclassified_tail->uc_next = j;
  else
    unclassified_head = j;
  unclassified_tail = j;
  j->class_pending = true;
}

static void
unclassified_remove (struct job *j)
{
  if (! j->class_pending)
    return;
  if (j->uc_prev)
    j->uc_prev->uc_next = j->uc_next;
  else
    unclassified_head = j->uc_next;
  if (j->uc_next)
    j->uc_next->uc_prev = j->uc_prev;
  else
    unclassified_tail = j->uc_prev;
  j->uc_prev = j->uc_next = NULL;
  j->class_pending = false;
}

/* J is aliased (discovered in archive order, so it usually goes at
   the end; keep the list sorted regardless).  */
static void
mark_aliased (struct job *j)
{
  if (j->aliased)
    return;
  j->aliased = true;
  aliases_seen = true;
  struct job *after = aliased_tail;
  while (after && after->seq > j->seq)
    after = after->al_prev;
  j->al_prev = after;
  j->al_next = after ? after->al_next : aliased_head;
  if (j->al_next)
    j->al_next->al_prev = j;
  else
    aliased_tail = j;
  if (after)
    after->al_next = j;
  else
    aliased_head = j;
}

static void
aliased_remove (struct job *j)
{
  if (! j->aliased)
    return;
  if (j->al_prev)
    j->al_prev->al_next = j->al_next;
  else
    aliased_head = j->al_next;
  if (j->al_next)
    j->al_next->al_prev = j->al_prev;
  else
    aliased_tail = j->al_prev;
  j->al_prev = j->al_next = NULL;
}

static void release_gate (void);

/* One of J's parents got classified.  */
static void
job_classified (struct job *j)
{
  if (--j->class_wait == 0)
    {
      unclassified_remove (j);
      release_gate ();
    }
}

/* N is known to be plain or not; tell the jobs waiting to hear it, and
   any later directory member for the same directory.  */
static void
node_set_known (struct node *n, bool alias)
{
  if (n->alias_known)
    return;
  n->alias = alias;
  n->alias_known = true;
  struct class_sub *w = n->class_waiters;
  n->class_waiters = NULL;
  while (w)
    {
      struct class_sub *next = w->next;
      if (alias)
	mark_aliased (w->job);
      job_classified (w->job);
      free (w);
      w = next;
    }
  if (n->successor)
    node_set_known (n->successor, alias);
}

/* Classify J against parent P, or wait for P's kind.  */
static void
classify_against (struct job *j, struct node *p)
{
  if (! p)
    return;
  if (p->alias_known)
    {
      if (p->alias)
	mark_aliased (j);
      return;
    }
  j->class_wait++;
  struct class_sub *sub = xmalloc (sizeof *sub);
  sub->job = j;
  sub->next = p->class_waiters;
  p->class_waiters = sub;
}

/* May J perform its operation now?  */
static bool
gate_open (struct job const *j)
{
  if (j->aliased)
    return unfinished_head == j;
  if (aliased_head && aliased_head->seq < j->seq)
    return false;
  /* A directory can be made while an earlier directory's kind is still
     unknown: the mkdir of an alias is harmless.  Anything else waits.  */
  return (j->kind == JOB_DIR
	  || ! unclassified_head || unclassified_head->seq > j->seq);
}

static void release_slot (struct job *j);

/* Park J at the gate, keeping archive order.  It gives up what it
   holds meanwhile, so that jobs ahead of it cannot starve; it takes
   parents and a descriptor again when resumed.  */
static void
gate_park (struct job *j)
{
  pdir_release (j->pdir);
  pdir_release (j->tpdir);
  j->pdir = j->tpdir = NULL;
  j->stage = STAGE_PARENT;
  release_slot (j);
  struct jlist *g = &gate_waiters;
  if (! g->tail || g->tail->seq < j->seq)
    {
      j->next = NULL;
      if (g->tail)
	g->tail->next = j;
      else
	g->head = j;
      g->tail = j;
      return;
    }
  struct job **link = &g->head;
  while (*link && (*link)->seq < j->seq)
    link = &(*link)->next;
  j->next = *link;
  *link = j;
}

static void handle_job (struct job *j);
static void continue_job (struct job *j);

static void
resume_job (struct job *j)
{
  if (j->kind == JOB_DIR || j->kind == JOB_SYMLINK || j->kind == JOB_LINK)
    continue_job (j);
  else
    handle_job (j);
}

/* Something finished or got classified: let waiting jobs through in
   order, up to the first that must still wait.  */
static void
release_gate (void)
{
  static bool releasing;
  if (releasing)
    return;
  releasing = true;
  while (gate_waiters.head && gate_open (gate_waiters.head))
    {
      struct job *j = gate_waiters.head;
      gate_waiters.head = j->next;
      if (! gate_waiters.head)
	gate_waiters.tail = NULL;
      resume_job (j);
    }
  releasing = false;
}

static void pdir_release (struct pdir *p);

/* The process ran out of descriptors although the budget said there
   was room: something else holds some.  Shrink the budget to what is
   in use and try J again later, a bounded number of times.  */
static bool retry_pending;

static bool
descriptor_errno (int errnum)
{
  return errnum == EMFILE || errnum == ENFILE;
}

static void
retry_later (struct job *j, int errnum)
{
  if (slots_max > slots_used && slots_used > 0)
    slots_max = slots_used;
  if (slots_max > 1)
    slots_max--;
  if (pdir_max > 2 && pdirs_count > 0 && pdir_max > pdirs_count)
    pdir_max = pdirs_count;
  if (++j->retries > 64)
    {
      fail_job (j, errnum);
      return;
    }
  gate_park (j);
  retry_pending = true;
}

/* J's path turned out to cross a symlink or a mount after all (the
   parent was believed plain): from now on it is aliased and resolves
   its path plainly; its parents are dropped so that they are reopened
   that way.  */
static void
serialize_job (struct job *j)
{
  mark_aliased (j);
  gate_park (j);
  release_gate ();
}

/* Close FD through the ring, so that a slow close never stalls the io
   thread.  J, if not null, is finished when the close completes.  */
static void
submit_close_fd (int fd, struct job *j)
{
  idx_t i = op_alloc (OP_CLOSE, j);
  ops[i].close_fd = fd;
  struct io_uring_sqe *sqe = get_sqe ();
  io_uring_prep_close (sqe, fd);
  io_uring_sqe_set_data64 (sqe, i);
}

static void
submit_open (struct job *j)
{
  idx_t i = op_alloc (OP_OPEN, j);
  memset (&j->how, 0, sizeof j->how);
  if (j->kind == JOB_FILE)
    {
      /* Same flags as open_output_file.  O_NONBLOCK keeps an existing
	 FIFO from blocking the open.  */
      bool overwriting = old_files_option == OVERWRITE_OLD_FILES;
      j->how.flags = (O_WRONLY | O_BINARY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK
		      | O_CREAT
		      | (overwriting
			 ? O_TRUNC | (dereference_option ? 0 : O_NOFOLLOW)
			 : O_EXCL));
      j->how.mode = j->create_mode;
    }
  else /* JOB_SYMLINK: open the link itself for metadata */
    j->how.flags = O_PATH | O_NOFOLLOW | O_CLOEXEC;
  j->how.resolve = plain_resolve (j->aliased);
  struct io_uring_sqe *sqe = get_sqe ();
  io_uring_prep_openat2 (sqe, j->wdfd, j->name, &j->how);
  io_uring_sqe_set_data64 (sqe, i);
}

static void
submit_mkdir (struct job *j)
{
  idx_t i = op_alloc (OP_MKDIR, j);
  struct io_uring_sqe *sqe = get_sqe ();
  io_uring_prep_mkdirat (sqe, j->pfd, j->base, j->create_mode);
  io_uring_sqe_set_data64 (sqe, i);
}

static void
submit_symlink (struct job *j)
{
  idx_t i = op_alloc (OP_SYMLINK, j);
  struct io_uring_sqe *sqe = get_sqe ();
  io_uring_prep_symlinkat (sqe, j->link, j->pfd, j->base);
  io_uring_sqe_set_data64 (sqe, i);
}

static void
submit_link (struct job *j)
{
  idx_t i = op_alloc (OP_LINK, j);
  struct io_uring_sqe *sqe = get_sqe ();
  io_uring_prep_linkat (sqe, j->tpfd, j->tbase, j->pfd, j->base, 0);
  io_uring_sqe_set_data64 (sqe, i);
}

static void
submit_close (struct job *j)
{
  int fd = j->fd;
  j->fd = -1;
  submit_close_fd (fd, j);
}

static void
submit_openparent (struct pdir *p)
{
  idx_t i = op_alloc (OP_OPENPARENT, NULL);
  ops[i].pdir = p;
  memset (&p->how, 0, sizeof p->how);
  p->how.flags = O_PATH | O_DIRECTORY | O_CLOEXEC
		 | (dereference_option ? 0 : O_NOFOLLOW);
  p->how.resolve = plain_resolve (p->aliased);
  struct io_uring_sqe *sqe = get_sqe ();
  io_uring_prep_openat2 (sqe, p->wdfd, p->name, &p->how);
  io_uring_sqe_set_data64 (sqe, i);
}

/* Poll the wake-up eventfd; its completion has this user data rather
   than an ops index, and is not counted among the operations in
   flight.  */
enum { WAKE_USER_DATA = UINT64_MAX };

static void
submit_wake_poll (void)
{
  struct io_uring_sqe *sqe = get_sqe ();
  io_uring_prep_poll_add (sqe, wake_fd, POLLIN);
  io_uring_sqe_set_data64 (sqe, WAKE_USER_DATA);
}

static void handle_job (struct job *j);

static void
release_list (struct jlist *list)
{
  struct job *w = list->head;
  list->head = list->tail = NULL;
  while (w)
    {
      struct job *next = w->next;
      handle_job (w);
      w = next;
    }
}

static void
park (struct jlist *list, struct job *j)
{
  j->next = NULL;
  if (list->tail)
    list->tail->next = j;
  else
    list->head = j;
  list->tail = j;
}

/* Descriptor slots for files and symlinks.  */
static bool
acquire_slot (struct job *j)
{
  if (j->has_slot)
    return true;
  if (slots_used >= slots_max)
    return false;
  slots_used++;
  j->has_slot = true;
  return true;
}

static void
release_slot (struct job *j)
{
  if (! j->has_slot)
    return;
  slots_used--;
  j->has_slot = false;
  /* A woken job may park elsewhere instead of taking the slot; keep
     offering it while it is free.  */
  while (slots_used < slots_max && slot_waiters_head)
    {
      struct job *w = slot_waiters_head;
      slot_waiters_head = w->next;
      if (! slot_waiters_head)
	slot_waiters_tail = NULL;
      handle_job (w);
    }
}

/* J's inode now exists: hard links may be made to it and, for a
   directory, children may be created in it.  */
static void
mark_created (struct job *j)
{
  struct node *n = j->node;
  if (! n || n->created)
    return;
  n->created = true;
  release_list (&n->wait_created);
}

/* Release J's resources, mark its node created and finished so that
   dependants stop waiting, and count it done.  */
static void
unsubscribe_class (struct node *p, struct job *j)
{
  if (! p)
    return;
  for (struct class_sub **link = &p->class_waiters; *link; )
    if ((*link)->job == j)
      {
	struct class_sub *sub = *link;
	*link = sub->next;
	free (sub);
      }
    else
      link = &(*link)->next;
}

static void
finish_job (struct job *j)
{
  unfinished_remove (j);
  if (j->class_wait)
    {
      unsubscribe_class (j->parent_node, j);
      unsubscribe_class (j->tparent_node, j);
      j->class_wait = 0;
    }
  unclassified_remove (j);
  aliased_remove (j);
  if (j->removed_dir && j->kind != JOB_DIR)
    parallel_forget_directory (j->name, j->change_dir);
  pdir_release (j->pdir);
  pdir_release (j->tpdir);
  j->pdir = j->tpdir = NULL;
  struct node *n = j->node;
  if (n)
    {
      if (! n->alias_known)
	node_set_known (n, j->parent_node && j->parent_node->alias);
      mark_created (j);
      n->finished = true;
      node_settle (n);
    }
  for (idx_t i = 0; i < j->nparents; i++)
    {
      struct node *p = j->parents[i];
      p->pending--;
      node_settle (p);
      node_unref (p);
    }
  if (j->target)
    {
      /* The target may be replaced now.  */
      j->target->pending--;
      node_settle (j->target);
      node_unref (j->target);
      j->target = NULL;
    }
  if (n)
    node_unref (n);
  release_slot (j);
  job_done ();
  job_release (j);
  release_gate ();
}

/* The verb for J's creation, for "%s: Cannot VERB" diagnostics.  */
static char const *
job_verb (struct job const *j)
{
  switch (j->kind)
    {
    case JOB_DIR: return "mkdir";
    case JOB_FILE: return "open";
    case JOB_SYMLINK: return "symlink";
    case JOB_LINK: return "link";
    case JOB_NODE: return "mknod";
    case JOB_FIFO: return "mkfifo";
    default: return "extract";
    }
}

static void
fail_job (struct job *j, int errnum)
{
  switch (j->kind)
    {
    case JOB_SYMLINK:
      symlink_error_p (errnum, j->link, j->name);
      break;
    case JOB_LINK:
      link_error_p (errnum, j->link, j->name);
      break;
    default:
      call_error (errnum, job_verb (j), j->name);
      break;
    }
  finish_job (j);
}

enum eexist { EEXIST_RETRY, EEXIST_SKIP, EEXIST_FAILED };

/* An existing entry is in the way of J at BASE under DFD.  Decide per
   old_files_option: remove it and retry, skip the member, or fail.  */
static enum eexist
handle_eexist (struct job *j, int dfd, char const *base)
{
  switch (old_files_option)
    {
    case SKIP_OLD_FILES:
      skip_existing_warn (j->name);
      return EEXIST_SKIP;
    case KEEP_OLD_FILES:
    case KEEP_NEWER_FILES:
      fail_job (j, EEXIST);
      return EEXIST_FAILED;
    default:
      if (! j->replaced && remove_existing_at (j, dfd, base))
	{
	  j->replaced = true;
	  return EEXIST_RETRY;
	}
      /* Like maybe_recoverable, report the original problem.  */
      fail_job (j, EEXIST);
      return EEXIST_FAILED;
    }
}

/* Something that is not a regular file is in the way of file J (or
   O_EXCL found it): apply the policy, retrying the open if allowed.  */
static void
handle_open_conflict (struct job *j)
{
  switch (old_files_option)
    {
    case SKIP_OLD_FILES:
      skip_existing_warn (j->name);
      finish_job (j);
      return;
    case KEEP_OLD_FILES:
    case KEEP_NEWER_FILES:
      fail_job (j, EEXIST);
      return;
    default:
      break;
    }
  if (j->replaced)
    {
      fail_job (j, EEXIST);
      return;
    }
  char const *base;
  bool owned;
  int dfd = open_parent_sync (j->wdfd, j->name, &base, &owned);
  if (dfd < 0)
    {
      fail_job (j, errno);
      return;
    }
  bool removed = remove_existing_at (j, dfd, base);
  if (owned)
    close (dfd);
  if (removed)
    {
      j->replaced = true;
      submit_open (j);
    }
  else
    fail_job (j, EEXIST);
}

/* The key of the parent directory of KEY, or NULL for a top-level
   name; also where the base name starts.  */
static char *
split_key (char const *key, char const **base)
{
  char const *name = key_name (key);
  char const *slash = strrchr (name, '/');
  if (! slash)
    {
      *base = name;
      return NULL;
    }
  *base = slash + 1;
  return ximemdup0 (key, slash - key);
}

/* How many new cache entries the parent of KEY needs: 0 or 1.  */
static idx_t
pdir_needed (char const *key)
{
  char const *base;
  char *pkey = split_key (key, &base);
  if (! pkey)
    return 0;
  struct pdir probe;
  probe.key = pkey;
  bool cached = hash_lookup (pdirs, &probe) != NULL;
  free (pkey);
  return ! cached;
}

/* Take a reference on the cache entry for the parent of KEY, creating
   it and starting its open if it is not cached; the caller has made
   room.  Return NULL, with *PFD set to WDFD, for a top-level name.  */
static struct pdir *
pdir_take (struct job *j, char const *key, int *pfd, char const **base)
{
  char *pkey = split_key (key, base);
  if (! pkey)
    {
      *pfd = j->wdfd;
      return NULL;
    }
  struct pdir probe;
  probe.key = pkey;
  struct pdir *p = hash_lookup (pdirs, &probe);
  if (p)
    free (pkey);
  else
    {
      char const *name = key_name (key);
      p = xzalloc (sizeof *p);
      p->key = pkey;
      /* Keep the trailing slash: it makes a final symlink to a
	 directory acceptable despite O_NOFOLLOW, as fdbase does.  */
      p->name = ximemdup0 (name, *base - name);
      p->wdfd = j->wdfd;
      p->fd = -1;
      p->opening = true;
      p->aliased = j->aliased;
      if (! hash_insert (pdirs, p))
	xalloc_die ();
      pdirs_count++;
      submit_openparent (p);
    }
  pdir_acquire (p);
  return p;
}

/* Continue J from its current stage; called initially and whenever a
   parent it waited for becomes available.  A job takes references on
   every parent it needs at once, after making sure they all fit in
   the cache, so that a job waiting for room never holds anything and
   a job holding something only waits for opens, which always end.  */
static void
continue_job (struct job *j)
{
  if (j->stage == STAGE_PARENT)
    {
      bool link = j->kind == JOB_LINK;
      idx_t need = pdir_needed (j->key);
      if (link)
	{
	  char const *b1, *b2;
	  char *k1 = split_key (j->key, &b1);
	  char *k2 = split_key (j->link_key, &b2);
	  if (! (k1 && k2 && streq (k1, k2)))
	    need += pdir_needed (j->link_key);
	  free (k1);
	  free (k2);
	}
      if (! pdirs_make_room (need))
	{
	  park (&pdir_waiters, j);
	  return;
	}
      j->pdir = pdir_take (j, j->key, &j->pfd, &j->base);
      if (link)
	j->tpdir = pdir_take (j, j->link_key, &j->tpfd, &j->tbase);
      j->stage = STAGE_OPENING;
    }
  if (j->stage == STAGE_OPENING)
    {
      if (j->pdir && j->pdir->opening)
	{
	  park (&j->pdir->waiters, j);
	  return;
	}
      if (j->tpdir && j->tpdir->opening)
	{
	  park (&j->tpdir->waiters, j);
	  return;
	}
      int perr = (j->pdir && j->pdir->fd < 0 ? -j->pdir->fd
		  : j->tpdir && j->tpdir->fd < 0 ? -j->tpdir->fd : 0);
      bool was_aliased = j->aliased;
      if (j->tparent_probe)
	{
	  /* Opening the target's parent told what it is.  */
	  j->tparent_probe = false;
	  if (j->tpdir && alias_errno (-j->tpdir->fd))
	    mark_aliased (j);
	  job_classified (j);
	}
      if (perr)
	{
	  /* A plain resolution that met a symlink or a mount: resolve
	     again, alone and the ordinary way.  */
	  if (alias_errno (perr) && ! was_aliased)
	    serialize_job (j);
	  else if (descriptor_errno (perr))
	    retry_later (j, perr);
	  else
	    fail_job (j, perr);
	  return;
	}
      if (j->pdir)
	j->pfd = j->pdir->fd;
      if (j->tpdir)
	j->tpfd = j->tpdir->fd;
      j->stage = STAGE_OP;
      if (! gate_open (j))
	{
	  gate_park (j);
	  return;
	}
    }
  switch (j->kind)
    {
    case JOB_DIR:
      submit_mkdir (j);
      break;
    case JOB_SYMLINK:
      submit_symlink (j);
      break;
    case JOB_LINK:
      submit_link (j);
      break;
    default:
      unreachable ();
    }
}

/* Pin the ancestors that this occurrence will use.  Pin every ancestor,
   not just its parent: replacing a directory must also wait for jobs
   beneath a child directory that has already finished its own mkdir.  */
static struct node *
hold_parents (struct job *j, char const *key)
{
  struct node *nearest = NULL;
  char *copy = xstrdup (key);
  char *name = copy + (key_name (key) - key);
  for (char *p = first_separator (name); p; p = strchr (p + 1, '/'))
    {
      *p = '\0';
      /* Reading a hard-link source beneath the destination must not
	 pin the occurrence that this very job is waiting to replace.
	 Such a replacement cannot remove a nonempty directory, so
	 let the filesystem diagnose it without a dependency cycle.  */
      if (! streq (copy, j->key))
	{
	  struct node *n = node_current (copy);
	  j->parents = xireallocarray (j->parents, j->nparents + 1,
				      sizeof *j->parents);
	  j->parents[j->nparents++] = node_ref (n);
	  n->pending++;
	  nearest = n;
	}
      *p = '/';
    }
  free (copy);
  return nearest;
}

/* Register in archive order before waiting for anything.  A hard link
   must see the latest preceding occurrence even if that occurrence is
   itself waiting to replace an older one.  */
static void
register_job (struct job *j)
{
  j->seq = ++job_seq;
  unfinished_add (j);
  struct node *previous = node_lookup (entries, j->key);
  if (previous)
    j->previous = node_ref (previous);
  j->parent_node = hold_parents (j, j->key);
  if (j->kind == JOB_LINK && ! streq (j->link_key, j->key))
    {
      struct node *t = node_current (j->link_key);
      j->target = node_ref (t);
      t->pending++;
      j->tparent_node = hold_parents (j, j->link_key);
    }
  struct node *n = xzalloc (sizeof *n);
  n->key = xstrdup (j->key);
  n->refs = 2;			/* the map and this job */
  /* A symbolic link is never a plain directory; a hard link may be one
     to a symbolic link.  A directory's kind is known once made.  */
  n->is_dir = j->kind == JOB_DIR;
  /* A link is never a plain directory; a hard link may be one to a
     symlink.  A directory member for a directory that an earlier
     member (an intermediate one, or the same member repeated) already
     made finds what that member found.  Any other directory is known
     once its mkdir completes; anything else is not a directory.  */
  if (j->kind == JOB_SYMLINK || j->kind == JOB_LINK)
    {
      n->alias = true;
      n->alias_known = true;
    }
  else if (j->kind == JOB_DIR)
    {
      if (previous && previous->is_dir)
	{
	  previous->successor = node_ref (n);
	  if (previous->alias_known)
	    {
	      n->alias = previous->alias;
	      n->alias_known = true;
	    }
	}
    }
  else
    n->alias_known = true;
  if (previous)
    {
      hash_remove (entries, previous);
      node_unref (previous);
    }
  if (! hash_insert (entries, n))
    xalloc_die ();
  j->node = n;

  /* Is J aliased?  Its parent's kind may not be known yet; then J is
     unclassified, and later members wait, until it is.  The parent of
     a hard link's target may be a directory the archive never creates,
     which opening it tells (continue_job).  */
  classify_against (j, j->parent_node);
  if (j->tparent_node)
    {
      if (j->tparent_node->initial)
	{
	  j->tparent_probe = true;
	  j->class_wait++;
	}
      else
	classify_against (j, j->tparent_node);
    }
  if (j->class_wait)
    unclassified_add (j);
}

/* Start, or restart after a wait, the work for J.  Dependencies refer
   to occurrences captured at registration, never to a mutable latest
   entry that a later member could have replaced in the meantime.  */
static void
handle_job (struct job *j)
{
  if (! j->node)
    register_job (j);
  if (j->previous)
    {
      if (! node_done (j->previous))
	{
	  park (&j->previous->wait_done, j);
	  return;
	}
      node_unref (j->previous);
      j->previous = NULL;
    }
  for (idx_t i = 0; i < j->nparents; i++)
    if (! j->parents[i]->created)
      {
	park (&j->parents[i]->wait_created, j);
	return;
      }
  if (j->target && ! j->target->created)
    {
      park (&j->target->wait_created, j);
      return;
    }
  /* Files and special files act on the filesystem right here; the
     others do so from continue_job, which has its own gate.  */
  if (j->kind == JOB_FILE || j->kind == JOB_NODE || j->kind == JOB_FIFO)
    if (! gate_open (j))
      {
	gate_park (j);
	return;
      }

  /* Files and symlinks hold a descriptor until closed.  */
  if ((j->kind == JOB_FILE || j->kind == JOB_SYMLINK) && ! acquire_slot (j))
    {
      j->next = NULL;
      if (slot_waiters_tail)
	slot_waiters_tail->next = j;
      else
	slot_waiters_head = j;
      slot_waiters_tail = j;
      return;
    }

  switch (j->kind)
    {
    case JOB_FILE:
      submit_open (j);
      break;

    case JOB_LINK:
    case JOB_DIR:
    case JOB_SYMLINK:
      j->stage = STAGE_PARENT;
      continue_job (j);
      break;

    case JOB_NODE:
    case JOB_FIFO:
      jobq_push (&meta_q, j);
      break;

    case JOB_TASK:
      unreachable ();
    }
}

/* A directory creation completed with RES (0 or -errno).  */
static void
finish_dir_created (struct job *j, int res)
{
  bool record = false;
  struct stat real_st;
  bool have_real_st = false;
  bool alias = j->parent_node && j->parent_node->alias;
  if (res == 0)
    {
      j->current_mode = j->create_mode & ~ parallel_current_umask ();
      j->current_mode_mask = MODE_RWX;
      record = true;
    }
  else if (res == -EEXIST)
    {
      /* Something pre-existing is in the way.  Children of a symlink
	 to a directory would alias the directory's own children.  */
      struct stat obstacle;
      if (fstatat (j->pfd, j->base, &obstacle, AT_SYMLINK_NOFOLLOW) == 0
	  && S_ISLNK (obstacle.st_mode))
	alias = true;
      if (j->implicit)
	{
	  /* Something is there already.  Sequentially, make_directories
	     runs only after a child failed with ENOENT, so the obstacle
	     is diagnosed when it leads nowhere (a dangling symlink); a
	     file in the way is reported by the children as ENOTDIR.  */
	  char *slashed = xasprintf ("%s/", j->base);
	  if (faccessat (j->pfd, slashed, F_OK, AT_EACCESS) < 0
	      && errno == ENOENT)
	    call_error (EEXIST, "mkdir", j->name);
	  free (slashed);
	}
      else
	{
	  struct stat st;
	  if (fstatat (j->pfd, j->base, &st, fstatat_flags) < 0)
	    {
	      if (errno == ENOENT && ! j->replaced)
		{
		  /* Whatever was in the way is gone; try again.  */
		  j->replaced = true;
		  submit_mkdir (j);
		  return;
		}
	      call_error (errno, "stat", j->name);
	    }
	  else if (S_ISDIR (st.st_mode))
	    {
	      struct stat lst;
	      if (keep_directory_symlink_option && ! fstatat_flags
		  && fstatat (j->pfd, j->base, &lst, AT_SYMLINK_NOFOLLOW) == 0
		  && S_ISLNK (lst.st_mode))
		;			/* keep the symlink */
	      else
		{
		  j->current_mode = st.st_mode;
		  j->current_mode_mask = ~ (mode_t) 0;
		  real_st = st;
		  have_real_st = true;
		  /* Like extract_dir: an intermediate directory we made
		     earlier takes the archive's metadata regardless of
		     the overwrite policy; a pre-existing one only when
		     overwriting is allowed.  */
		  record = (old_files_option == DEFAULT_OLD_FILES
			    || old_files_option == OVERWRITE_OLD_FILES
			    || parallel_dir_is_interdir (j->name,
						 j->change_dir));
		}
	    }
	  else
	    {
	      struct stat dirst;
	      if (S_ISLNK (st.st_mode) && keep_directory_symlink_option
		  && fstatat (j->pfd, j->base, &dirst, 0) == 0
		  && S_ISDIR (dirst.st_mode))
		;			/* keep the symlink */
	      else
		{
		  errno = 0;
		  switch (handle_eexist (j, j->pfd, j->base))
		    {
		    case EEXIST_RETRY:
		      submit_mkdir (j);
		      return;
		    case EEXIST_SKIP:
		      break;
		    case EEXIST_FAILED:
		      return;	/* finish_job already ran */
		    }
		}
	    }
	}
    }
  else
    call_error (-res, "mkdir", j->name);

  if (record && ! have_real_st && ! j->implicit
      && parallel_dir_is_interdir (j->name, j->change_dir))
    {
      /* delay_set_stat needs the directory's identity to replace the
	 intermediate entry, and cannot stat it from this thread.  */
      if (fstatat (j->pfd, j->base, &real_st, AT_SYMLINK_NOFOLLOW) == 0)
	have_real_st = true;
      else
	{
	  call_error (errno, "stat", j->name);
	  record = false;
	}
    }
  if (record)
    {
      parallel_record_directory (j->name, j->implicit ? NULL : &j->st,
				 j->atime, j->mtime, j->current_mode,
				 j->current_mode_mask,
				 j->implicit ? (MODE_RWX & ~ parallel_newdir_umask ())
				 : j->st.st_mode,
				 AT_SYMLINK_NOFOLLOW, j->change_dir,
				 have_real_st ? &real_st : NULL);
    }
  node_set_known (j->node, alias);
  finish_job (j);
}

static void
handle_cqe (struct io_uring_cqe *cqe)
{
  if (io_uring_cqe_get_data64 (cqe) == WAKE_USER_DATA)
    {
      if (cqe->res < 0)
	io_fatal (-cqe->res, _("io_uring wake-up failed"));
      uint64_t count;
      if (read (wake_fd, &count, sizeof count) < 0)
	{
	  /* EAGAIN: nothing to drain.  */
	}
      submit_wake_poll ();
      return;
    }
  struct op *op = op_take (io_uring_cqe_get_data64 (cqe));
  int res = cqe->res;
  struct job *j = op->job;

  switch (op->kind)
    {
    case OP_OPENPARENT:
      {
	struct pdir *p = op->pdir;
	p->opening = false;
	p->fd = res;		/* a descriptor, or -errno; the waiters
				   fail themselves on a negative one */
	struct job *w = p->waiters.head;
	p->waiters.head = p->waiters.tail = NULL;
	while (w)
	  {
	    struct job *next = w->next;
	    continue_job (w);
	    w = next;
	  }
	return;
      }

    case OP_OPEN:
      if (res < 0)
	{
	  if (alias_errno (-res) && ! j->aliased)
	    serialize_job (j);
	  else if (descriptor_errno (-res))
	    retry_later (j, -res);
	  /* As in maybe_recoverable: something is in the way when
	     O_EXCL says so, or when O_NOFOLLOW hit a symlink while
	     overwriting; anything else is a plain failure.  */
	  else if (j->kind == JOB_FILE
		   && (res == -EEXIST
		       || (res == -ELOOP
			   && old_files_option == OVERWRITE_OLD_FILES)))
	    handle_open_conflict (j);
	  else
	    fail_job (j, -res);
	  return;
	}
      j->fd = res;
      if (j->kind == JOB_FILE)
	{
	  if (old_files_option == OVERWRITE_OLD_FILES)
	    {
	      struct stat st;
	      if (fstat (j->fd, &st) == 0 && S_ISREG (st.st_mode))
		{
		  j->current_mode = st.st_mode;
		  j->current_mode_mask = ~ (mode_t) 0;
		}
	      else
		{
		  /* Not a regular file: same as open_output_file
		     returning EEXIST.  */
		  close (j->fd);
		  j->fd = -1;
		  handle_open_conflict (j);
		  return;
		}
	    }
	  else
	    {
	      j->current_mode = j->create_mode & ~ parallel_current_umask ();
	      j->current_mode_mask = MODE_RWX;
	    }
	  mark_created (j);
	  jobq_push (j->size > 0 ? &write_q : &meta_q, j);
	}
      else
	{
	  j->current_mode = 0;
	  j->current_mode_mask = 0;
	  jobq_push (&meta_q, j);
	}
      return;

    case OP_MKDIR:
      finish_dir_created (j, res);
      return;

    case OP_SYMLINK:
      if (res < 0)
	{
	  if (res == -EEXIST)
	    switch (handle_eexist (j, j->pfd, j->base))
	      {
	      case EEXIST_RETRY:
		submit_symlink (j);
		return;
	      case EEXIST_SKIP:
		finish_job (j);
		return;
	      case EEXIST_FAILED:
		return;
	      }
	  fail_job (j, -res);
	  return;
	}
      /* The link exists; drop the parent and open the link itself for
	 times and ownership.  */
      mark_created (j);
      pdir_release (j->pdir);
      j->pdir = NULL;
      submit_open (j);
      return;

    case OP_LINK:
      if (res < 0)
	{
	  if (res == -EEXIST)
	    {
	      /* Linking to a name that already shares the inode is fine.  */
	      struct stat st, st1;
	      if (fstatat (j->tpfd, j->tbase, &st1, AT_SYMLINK_NOFOLLOW) == 0
		  && fstatat (j->pfd, j->base, &st, AT_SYMLINK_NOFOLLOW) == 0
		  && st.st_dev == st1.st_dev && st.st_ino == st1.st_ino)
		{
		  finish_job (j);
		  return;
		}
	      switch (handle_eexist (j, j->pfd, j->base))
		{
		case EEXIST_RETRY:
		  submit_link (j);
		  return;
		case EEXIST_SKIP:
		  finish_job (j);
		  return;
		case EEXIST_FAILED:
		  return;
		}
	    }
	  if (! (res == -EEXIST && incremental_option))
	    link_error_p (-res, j->link, j->name);
	}
      finish_job (j);
      return;

    case OP_CLOSE:
      if (! j)
	return;			/* a parent directory descriptor */
      if (res < 0)
	call_error (-res, "close", j->name);
      finish_job (j);
      return;
    }
}

static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
static int init_result = 1;	/* 1 pending, 0 ok, <0 -errno */

/* Set up the ring.  Must run on the thread that will use it, because
   of IORING_SETUP_SINGLE_ISSUER.  Return 0 or a negative errno.  */
static int
ring_setup (void)
{
  unsigned ring_entries = RING_ENTRIES;
  bool single_issuer = true;
  for (;;)
    {
      struct io_uring_params params;
      memset (&params, 0, sizeof params);
      params.flags = IORING_SETUP_CQSIZE;
      if (single_issuer)
	params.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN;
      params.cq_entries = ring_entries * 2;
      int r = io_uring_queue_init_params (ring_entries, &ring, &params);
      if (r == 0)
	break;
      if (single_issuer)
	single_issuer = false;
      else if (ring_entries > 256)
	ring_entries /= 4;
      else
	return r;
    }
  /* A ring can exist on kernels that lack the operations used here;
     refuse those so that extraction falls back to the ordinary path.  */
  {
    static int const needed[] = { IORING_OP_OPENAT2, IORING_OP_MKDIRAT,
				  IORING_OP_SYMLINKAT, IORING_OP_LINKAT,
				  IORING_OP_CLOSE, IORING_OP_POLL_ADD };
    struct io_uring_probe *probe = io_uring_get_probe_ring (&ring);
    bool ok = probe != NULL;
    for (size_t i = 0; ok && i < sizeof needed / sizeof *needed; i++)
      ok = io_uring_opcode_supported (probe, needed[i]);
    if (probe)
      io_uring_free_probe (probe);
    if (! ok)
      {
	io_uring_queue_exit (&ring);
	return -EOPNOTSUPP;
      }
  }
  /* io_uring runs blocking file operations on its own worker threads;
     the default cap of 4 x CPUs is far too low for a slow filesystem.  */
  unsigned workers[2];
  workers[0] = workers[1] = (slots_max < 64 ? 64
			     : slots_max > 8192 ? 8192 : slots_max);
  io_uring_register_iowq_max_workers (&ring, workers);
  return 0;
}

static void *
io_main (MAYBE_UNUSED void *arg)
{
  int r = ring_setup ();
  pthread_mutex_lock (&init_mutex);
  init_result = r;
  pthread_cond_broadcast (&init_cond);
  pthread_mutex_unlock (&init_mutex);
  if (r < 0)
    return NULL;
  ring_ready = true;
  if (0 <= wake_fd)
    submit_wake_poll ();

  for (;;)
    {
      /* Finished special files, and close requests (which free
	 descriptor slots), first.  */
      for (struct job *j = jobq_drain (&done_q); j; )
	{
	  struct job *next = j->next;
	  finish_job (j);
	  j = next;
	}
      for (struct job *j = jobq_drain (&close_q); j; )
	{
	  struct job *next = j->next;
	  submit_close (j);
	  j = next;
	}
      if (jobs_open)
	{
	  struct job *j = jobq_drain (&in_q);
	  while (j && ops_inflight < MAX_INFLIGHT_OPS)
	    {
	      struct job *next = j->next;
	      handle_job (j);
	      j = next;
	    }
	  jobq_unshift (&in_q, j);
	  pthread_mutex_lock (&in_q.mutex);
	  bool closed = in_q.closed && ! in_q.head;
	  pthread_mutex_unlock (&in_q.mutex);
	  if (closed)
	    jobs_open = false;
	}

      if (! jobs_open && ops_inflight == 0)
	{
	  /* Stay until every job is finished: files still being written
	     will come back here to be closed.  */
	  pthread_mutex_lock (&inflight_mutex);
	  bool done = inflight == 0;
	  pthread_mutex_unlock (&inflight_mutex);
	  if (done)
	    break;
	}

      /* Sleep until a completion arrives or another thread pushes work,
	 re-checking the queues after announcing the sleep so that no
	 push is missed; the timeout only keeps the scaler ticking.  */
      struct __kernel_timespec wait = { .tv_sec = 0, .tv_nsec = 1000000 };
      if (0 <= wake_fd)
	{
	  pthread_mutex_lock (&wake_mutex);
	  io_sleeping = true;
	  pthread_mutex_unlock (&wake_mutex);
	  if (! jobq_empty (&in_q) || ! jobq_empty (&close_q)
	      || ! jobq_empty (&done_q))
	    {
	      pthread_mutex_lock (&wake_mutex);
	      io_sleeping = false;
	      pthread_mutex_unlock (&wake_mutex);
	      wait.tv_nsec = 0;
	    }
	  else
	    wait.tv_nsec = SCALER_TICK_NS;
	}
      struct io_uring_cqe *cqe;
      int w = io_uring_submit_and_wait_timeout (&ring, &cqe, 1, &wait, NULL);
      if (0 <= wake_fd)
	{
	  pthread_mutex_lock (&wake_mutex);
	  io_sleeping = false;
	  pthread_mutex_unlock (&wake_mutex);
	}
      check_io_result (w, _("io_uring wait failed"));
      unsigned head, count = 0;
      io_uring_for_each_cqe (&ring, head, cqe)
	{
	  count++;
	  handle_cqe (cqe);
	}
      io_uring_cq_advance (&ring, count);
      if (retry_pending)
	{
	  retry_pending = false;
	  release_gate ();
	}
      scaler_tick ();
    }
  return NULL;
}

/* ------------------------------------------------------------------ */
/* Working-directory descriptors (main thread).  */

static int
wd_fd_for (idx_t change_dir)
{
  if (wd_fd < 0 || wd_change_dir != change_dir)
    {
      /* Distinct -C options can name the same directory, or overlapping
	 trees.  Complete the previous context before looking up this one;
	 the option index alone cannot establish filesystem independence.  */
      parallel_barrier ();
      if (0 <= wd_fd)
	close (wd_fd);
      wd_fd = -1;
      if (dispatched_dirs)
	hash_clear (dispatched_dirs);
      int fd = chdir_fd_of (change_dir);
      int dup = (fd == AT_FDCWD
		 ? open (".", O_PATH | O_DIRECTORY | O_CLOEXEC)
		 : fd < 0 ? -1 : fcntl (fd, F_DUPFD_CLOEXEC, 0));
      if (dup < 0)
	{
	  if (fd < 0)
	    errno = EBADF;
	  open_fatal (".");
	}
      wd_fd = dup;
      wd_change_dir = change_dir;
    }
  return wd_fd;
}

/* ------------------------------------------------------------------ */
/* Public API used by extract.c.  */

/* Decide whether the engine can run for this invocation and start it.  */
void
parallel_init (void)
{
  parallel_active = false;
  if (parallel_option == 0)
    return;
  /* In-place overwrites can modify the same inode through different
     names, including hard links already in the destination.  Ordering
     pathname occurrences alone cannot serialize those writes.
     With --absolute-names, absolute and relative names can also alias,
     and their depths cannot order directory metadata restoration.
     Use the ordinary extractor for the whole run, preserving its
     directory cache and extraction-time metadata restoration.  */
  bool compatible = (! to_stdout_option && ! to_command_option
		     && ! backup_option && ! interactive_option
		     && ! incremental_option && ! listed_incremental_option
		     && ! xattrs_option && acls_option <= 0
		     && selinux_context_option <= 0
		     && ! dereference_option && ! multi_volume_option
		     && ! absolute_names_option
		     && ! recursive_unlink_option
		     && ! one_top_level_dir
		     && old_files_option != UNLINK_FIRST_OLD_FILES
		     && old_files_option != OVERWRITE_OLD_FILES
		     && old_files_option != KEEP_NEWER_FILES);
  if (! compatible)
    {
      if (parallel_option == 1)
	paxwarn (0, _("parallel extraction is not compatible with the given"
		      " options; extracting sequentially"));
      return;
    }

  /* Descriptor budget, from the soft limit as it stands: tar's own
     descriptors and the data writers first, then the metadata pool's
     transient descriptors (two per thread), a cache of parent
     directories, and the rest for files and symlinks in flight.  */
  struct rlimit rl;
  rlim_t nofile = getrlimit (RLIMIT_NOFILE, &rl) == 0 ? rl.rlim_cur : 1024;
  /* Descriptors inherited or already open (the archive, for one) are
     not available to the engine.  */
  {
    rlim_t open_now = 0;
    DIR *d = opendir ("/proc/self/fd");
    if (d)
      {
	for (struct dirent *e; (e = readdir (d)); )
	  open_now += e->d_name[0] != '.';
	closedir (d);
	if (open_now)
	  open_now--;		/* the directory stream itself */
      }
    else
      open_now = 8;
    nofile = open_now < nofile ? nofile - open_now : 0;
  }
  long ncpu = sysconf (_SC_NPROCESSORS_ONLN);
  writer_count = ncpu > 0 ? ncpu / 2 : 2;
  if (writer_count < 2)
    writer_count = 2;
  if (writer_count > 8)
    writer_count = 8;
  idx_t reserved = 16 + writer_count;
  if (nofile < (rlim_t) (reserved + MIN_NOFILE))
    {
      if (parallel_option == 1)
	paxwarn (0, _("too few file descriptors for parallel extraction;"
		      " extracting sequentially"));
      return;
    }
  idx_t budget = nofile - reserved;
  meta_threads_max = (parallel_max_meta_threads_option
		      ? parallel_max_meta_threads_option : 1024);
  if (meta_threads_max > budget / 8)
    meta_threads_max = budget / 8;
  if (meta_threads_max < 1)
    meta_threads_max = 1;
  budget -= 2 * meta_threads_max;
  pdir_max = budget / 8;
  if (pdir_max > PDIR_CACHE_MAX)
    pdir_max = PDIR_CACHE_MAX;
  if (pdir_max < 2)
    pdir_max = 2;
  budget -= pdir_max;
  slots_max = parallel_open_files_option ? parallel_open_files_option : budget;
  if (slots_max > budget)
    slots_max = budget;
  if (slots_max > 16384)
    slots_max = 16384;

  /* Under an address-space limit, buffer less data and keep fewer
     threads, each of which needs a stack.  */
  {
    rlim_t space = RLIM_INFINITY;
    if (getrlimit (RLIMIT_AS, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
      space = rl.rlim_cur;
    if (getrlimit (RLIMIT_DATA, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY
	&& rl.rlim_cur < space)
      space = rl.rlim_cur;
    if (space != RLIM_INFINITY)
      {
	idx_t share = space / 8;
	if (budget_max > share)
	  budget_max = share < CHUNK_SIZE ? CHUNK_SIZE : share;
	idx_t threads = share / THREAD_STACK_SIZE;
	if (threads < 1)
	  threads = 1;
	if (meta_threads_max > threads)
	  meta_threads_max = threads;
	if (writer_count > threads)
	  writer_count = threads;
#ifdef M_ARENA_MAX
	/* glibc reserves tens of megabytes of address space for each
	   thread's malloc arena; the workers allocate too little for
	   that to matter, and it would not fit.  */
	mallopt (M_ARENA_MAX, 1);
#endif
      }
  }
  main_tid = pthread_self ();

  /* Is the destination a network filesystem?  */
  {
    struct statfs sf;
    int fd = chdir_current_fd ();
    int r = fd == AT_FDCWD || fd < 0 ? statfs (".", &sf) : fstatfs (fd, &sf);
    if (r == 0)
      switch ((unsigned long) sf.f_type)
	{
	case 0x6969:		/* NFS */
	case 0x517B:		/* SMB */
	case 0xFF534D42:	/* CIFS */
	case 0xFE534D42:	/* SMB2 */
	case 0x65735546:	/* FUSE */
	case 0x00C36400:	/* Ceph */
	case 0x01021997:	/* 9p */
	case 0x5346414F:	/* AFS */
	  is_network_fs = true;
	  break;
	default:
	  break;
	}
  }

  jobq_init (&in_q);
  jobq_init (&close_q);
  jobq_init (&done_q);
  jobq_init (&write_q);
  jobq_init (&meta_q);
  in_q.wakes_io = close_q.wakes_io = done_q.wakes_io = true;
  wake_fd = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);
  entries = hash_initialize (0, NULL, node_hash, node_compare, node_unref);
  pdirs = hash_initialize (0, NULL, pdir_hash, pdir_compare, NULL);
  if (! entries || ! pdirs)
    xalloc_die ();

  /* Reserve the quotearg slots the workers use, so the main thread
     never has to grow quotearg's slot table concurrently.  */
  quotearg_n_style (QUOTE_SLOT + 1, shell_escape_quoting_style, "");

  idx_t initial = parallel_meta_threads_option ? parallel_meta_threads_option
		  : is_network_fs ? 32 : 4;
  if (initial > meta_threads_max)
    initial = meta_threads_max;
  clock_gettime (CLOCK_MONOTONIC, &scaler.last_time);
  scaler.next_tick = ts_add_ns (scaler.last_time, SCALER_TICK_NS);
  scaler.cooldown_until = scaler.last_time;
  spawn_meta_threads (initial);

  /* From here on, anything that fails unwinds what has been started
     and leaves extraction sequential.  */
  int r = meta_threads ? 0 : EAGAIN;
  idx_t writers_started = 0;
  if (r == 0)
    {
      writer_tids = xcalloc (writer_count, sizeof *writer_tids);
      for (; writers_started < writer_count; writers_started++)
	{
	  r = start_thread (&writer_tids[writers_started], writer_main);
	  if (r != 0)
	    break;
	}
    }
  bool io_started = false;
  if (r == 0)
    {
      r = start_thread (&io_tid, io_main);
      if (r == 0)
	{
	  io_started = true;
	  pthread_mutex_lock (&init_mutex);
	  while (init_result == 1)
	    pthread_cond_wait (&init_cond, &init_mutex);
	  r = -init_result;
	  pthread_mutex_unlock (&init_mutex);
	}
    }
  if (r != 0)
    {
      if (io_started)
	pthread_join (io_tid, NULL);
      jobq_close (&write_q);
      for (idx_t i = 0; i < writers_started; i++)
	pthread_join (writer_tids[i], NULL);
      jobq_close (&meta_q);
      for (idx_t i = 0; i < meta_threads; i++)
	pthread_join (meta_tids[i], NULL);
      if (0 <= wake_fd)
	close (wake_fd);
      wake_fd = -1;
      if (parallel_option == 1)
	paxwarn (r, _("cannot start parallel extraction;"
		      " extracting sequentially"));
      return;
    }

  /* Directory metadata must wait until every child exists.  */
  delay_directory_restore_option = true;
  parallel_active = true;
}

static void
dispatch_job (struct job *j)
{
  track_dispatch ();
  jobq_push (&in_q, j);
}

static void
note_path (Hash_table *table, char const *key)
{
  struct node *n = xzalloc (sizeof *n);
  n->key = xstrdup (key);
  if (! hash_insert (table, n))
    xalloc_die ();
}

/* Dispatch missing ancestor directories of KEY (a key made by
   make_key), outermost first.  */
static void
ensure_parents (char const *key, int wdfd, idx_t change_dir)
{
  char *pkey = parent_key (key);
  if (! pkey)
    return;
  bool known = node_lookup (dispatched_dirs, pkey) != NULL;
  free (pkey);
  if (known)
    return;
  char *kcopy = xstrdup (key);
  char *name = kcopy + (key_name (key) - key);
  for (char *p = first_separator (name); p; p = strchr (p + 1, '/'))
    {
      *p = '\0';
      if (! node_lookup (dispatched_dirs, kcopy))
	{
	  note_path (dispatched_dirs, kcopy);
	  struct job *j = job_new (JOB_DIR, name);
	  j->key = xstrdup (kcopy);
	  j->implicit = true;
	  j->wdfd = wdfd;
	  j->change_dir = change_dir;
	  j->typeflag = DIRTYPE;
	  mode_t desired = MODE_RWX & ~ parallel_newdir_umask ();
	  j->create_mode = desired | (parallel_we_are_root () ? 0 : MODE_WXUSR);
	  dispatch_job (j);
	}
      *p = '/';
    }
  free (kcopy);
}

static void
push_chunk (struct job *j, struct chunk *c)
{
  c->next = NULL;
  pthread_mutex_lock (&j->data_mutex);
  if (j->orphaned)
    {
      /* Nobody will write this; drop it right away.  */
      pthread_mutex_unlock (&j->data_mutex);
      chunk_free (c);
      return;
    }
  if (j->chunk_tail)
    j->chunk_tail->next = c;
  else
    j->chunk_head = c;
  j->chunk_tail = c;
  pthread_cond_signal (&j->data_cond);
  pthread_mutex_unlock (&j->data_mutex);
}

/* The regular file whose data the parser is streaming right now, if
   any.  A fatal error while streaming (a read error in the archive)
   must not leave its writer waiting for data that will never come.  */
static struct job *streaming_job;

/* The parser has streamed everything for J.  If the io thread has
   already let go of the job, free it here.  */
static void
data_finished (struct job *j)
{
  streaming_job = NULL;
  pthread_mutex_lock (&j->data_mutex);
  j->data_done = true;
  bool orphaned = j->orphaned;
  pthread_cond_broadcast (&j->data_cond);
  pthread_mutex_unlock (&j->data_mutex);
  if (orphaned)
    job_free (j);
}

/* The ordinary extractor can change parents that the parser has already
   checked.  Discard those checks after draining the pipeline; subsequent
   members must resolve the namespace left by the ordinary extraction.  */
static bool
ordinary_member (void)
{
  parallel_barrier ();
  if (dispatched_dirs)
    hash_clear (dispatched_dirs);
  return false;
}

/* Try to extract the current member through the engine.  Return true
   if it was taken (its data consumed); false if the caller must
   extract it the ordinary way.  */
bool
parallel_extract_member (char *file_name, char typeflag)
{
  if (! parallel_active)
    return false;
  struct tar_stat_info *st = &current_stat_info;

  enum job_kind kind;
  switch (typeflag)
    {
    case AREGTYPE: case REGTYPE: case CONTTYPE:
      if (st->is_sparse)
	return ordinary_member ();
      kind = st->had_trailing_slash ? JOB_DIR : JOB_FILE;
      break;
    case DIRTYPE:
      if (st->is_dumpdir)
	return ordinary_member ();
      kind = JOB_DIR;
      break;
    case SYMTYPE:
      kind = JOB_SYMLINK;
      break;
    case LNKTYPE:
      kind = JOB_LINK;
      break;
    case CHRTYPE: case BLKTYPE:
      kind = JOB_NODE;
      break;
    case FIFOTYPE:
      kind = JOB_FIFO;
      break;
    default:
      return ordinary_member ();
    }

  if (! dispatched_dirs)
    {
      dispatched_dirs = hash_initialize (0, NULL, node_hash, node_compare,
					 node_free);
      if (! dispatched_dirs)
	xalloc_die ();
    }

  int wdfd = wd_fd_for (chdir_current);
  char *normalized = normalize_key (file_name);
  if (! *normalized || streq (normalized, "/"))
    {
      /* The working directory (".") or filesystem root ("/"): only
	 metadata.  Let extract_dir record it for the final sequential
	 pass, once the pipeline is idle.  */
      free (normalized);
      return ordinary_member ();
    }
  char *key = make_key (chdir_current, normalized);
  free (normalized);

  /* set_stat would warn about implausible times when applying them;
     do it now, on this thread, where the diagnostic is safe.  */
  if (! touch_option && kind != JOB_LINK)
    parallel_check_time (file_name, st->mtime);

  ensure_parents (key, wdfd, chdir_current);

  struct job *j = job_new (kind, file_name);
  j->key = key;
  j->wdfd = wdfd;
  j->change_dir = chdir_current;
  j->typeflag = typeflag;
  j->st = st->stat;
  j->atime = st->atime;
  j->mtime = st->mtime;
  j->size = st->stat.st_size;

  switch (kind)
    {
    case JOB_DIR:
      if (! node_lookup (dispatched_dirs, key))
	note_path (dispatched_dirs, key);
      j->create_mode = parallel_safe_dir_mode (&st->stat);
      j->size = 0;
      break;
    case JOB_FILE:
      j->create_mode = (st->stat.st_mode & MODE_RWX
			& ~ (0 < same_owner_option ? S_IRWXG | S_IRWXO : 0));
      break;
    case JOB_SYMLINK:
      j->link = xstrdup (st->link_name);
      j->size = 0;
      break;
    case JOB_LINK:
      j->link = xstrdup (st->link_name);
      {
	char *n = normalize_key (st->link_name);
	j->link_key = make_key (chdir_current, n);
	free (n);
      }
      break;
    case JOB_NODE:
      j->create_mode = (st->stat.st_mode & (MODE_RWX | S_IFBLK | S_IFCHR)
			& ~ (0 < same_owner_option ? S_IRWXG | S_IRWXO : 0));
      j->size = 0;
      break;
    case JOB_FIFO:
      j->create_mode = (st->stat.st_mode & MODE_RWX
			& ~ (0 < same_owner_option ? S_IRWXG | S_IRWXO : 0));
      j->size = 0;
      break;
    case JOB_TASK:
      unreachable ();
    }

  if (kind == JOB_FILE)
    streaming_job = j;
  dispatch_job (j);

  if (kind == JOB_FILE && j->size > 0)
    {
      /* Stream the member's data into chunks.  J stays valid: the writer
	 only frees it after data_done.  */
      off_t size = j->size;
      struct chunk *c = NULL;
      while (size > 0)
	{
	  union block *data_block = find_next_block ();
	  if (! data_block)
	    {
	      plain_error (0, _("Unexpected EOF in archive"));
	      break;
	    }
	  idx_t avail = available_space_after (data_block);
	  if (avail > size)
	    avail = size;
	  if (! c)
	    {
	      idx_t want = size < CHUNK_SIZE ? size : CHUNK_SIZE;
	      budget_acquire (want);
	      c = xmalloc (FLEXSIZEOF (struct chunk, data, want));
	      c->next = NULL;
	      c->len = 0;
	      c->cap = want;
	    }
	  idx_t take = avail < c->cap - c->len ? avail : c->cap - c->len;
	  memcpy (c->data + c->len, data_block, take);
	  c->len += take;
	  size -= take;
	  set_next_block_after ((char *) data_block + take - 1);
	  if (c->len == c->cap)
	    {
	      push_chunk (j, c);
	      c = NULL;
	    }
	}
      if (c)
	push_chunk (j, c);
      data_finished (j);
      if (size > 0)
	skim_file (size, false);
    }
  else if (kind == JOB_FILE)
    data_finished (j);
  current_stat_info.skipped = true;
  return true;
}

/* Run FN (ARG) on the metadata pool, counted for parallel_barrier.  */
static void
parallel_run_task (void (*fn) (void *), void *arg)
{
  struct task_job *t = xzalloc (sizeof *t);
  t->job.kind = JOB_TASK;
  t->job.fd = -1;
  t->fn = fn;
  t->arg = arg;
  track_dispatch ();
  jobq_push (&meta_q, &t->job);
}

/* Drain the pipeline and stop the io thread and writers.  Called from
   extract_finish before directory metadata is applied.  */
void
parallel_finish (void)
{
  if (! parallel_active || ! on_main_thread ())
    return;
  /* Reached through fatal_exit_hook while a member was being streamed:
     let its writer finish with what it has.  */
  if (streaming_job)
    data_finished (streaming_job);
  jobq_close (&in_q);
  parallel_barrier ();
  pthread_join (io_tid, NULL);
  jobq_close (&write_q);
  for (idx_t i = 0; i < writer_count; i++)
    pthread_join (writer_tids[i], NULL);
  /* The metadata pool stays up for parallel_apply_dirstats.  */
}

/* Stop the metadata pool.  */
void
parallel_shutdown (void)
{
  if (! parallel_active || ! on_main_thread ())
    return;
  jobq_close (&meta_q);
  for (idx_t i = 0; i < meta_threads; i++)
    pthread_join (meta_tids[i], NULL);
  if (ring_ready)
    io_uring_queue_exit (&ring);
  if (0 <= wake_fd)
    close (wake_fd);
  if (0 <= wd_fd)
    close (wd_fd);
  wd_fd = -1;
  parallel_active = false;
}

/* ------------------------------------------------------------------ */
/* Directory metadata at the end of extraction.  extract.c collects the
   delayed directory stats; we apply them through the pool, deepest
   directories first so that restrictive parent modes never get in the
   way, all directories of one depth in flight at once.  */

static int
depth_of (char const *name)
{
  /* Count separators as normalize_key would, without allocating a
     normalized name for each comparison during the final sort.  */
  int d = *name == '/';
  bool component = false;
  for (char const *p = name; *p; )
    {
      while (*p == '/')
	p++;
      char const *end = strchr (p, '/');
      idx_t len = end ? end - p : (idx_t) strlen (p);
      if (len && ! (len == 1 && *p == '.'))
	{
	  d += component;
	  component = true;
	}
      p += len;
    }
  return d;
}

static int
dirstat_cmp (void const *a, void const *b)
{
  struct parallel_dirstat const *x = a, *y = b;
  int dx = depth_of (x->name), dy = depth_of (y->name);
  return dx < dy ? 1 : dx > dy ? -1 : strcmp (y->name, x->name);
}

static idx_t
compact_dirstats (struct parallel_dirstat *arr, idx_t n)
{
  idx_t kept = 0;
  for (idx_t i = 0; i < n; i++)
    if (arr[i].name)
      arr[kept++] = arr[i];
  return kept;
}

/* Lexical aliases need no filesystem lookup.  Keep temporary normalized
   keys separate from ARR's borrowed names, which retain their original
   spelling for extraction and diagnostics.  */
struct dirstat_path
{
  char *name;
  idx_t change_dir;
  idx_t index;
};

static size_t
dirstat_path_hash (void const *entry, size_t table_size)
{
  struct dirstat_path const *d = entry;
  return (hash_string (d->name, table_size)
	  ^ (size_t) d->change_dir) % table_size;
}

static bool
dirstat_path_compare (void const *a, void const *b)
{
  struct dirstat_path const *x = a, *y = b;
  return x->change_dir == y->change_dir && streq (x->name, y->name);
}

static void
dirstat_path_free (void *entry)
{
  struct dirstat_path *d = entry;
  free (d->name);
  free (d);
}

static idx_t
unique_dirstat_paths (struct parallel_dirstat *arr, idx_t n)
{
  Hash_table *paths = hash_initialize (0, NULL, dirstat_path_hash,
				     dirstat_path_compare, dirstat_path_free);
  if (! paths)
    xalloc_die ();
  for (idx_t i = 0; i < n; i++)
    {
      struct dirstat_path key = { .name = normalize_key (arr[i].name),
	.change_dir = arr[i].change_dir, .index = i };
      struct dirstat_path *d = hash_lookup (paths, &key);
      if (d)
	{
	  if (arr[d->index].order < arr[i].order)
	    {
	      arr[d->index].name = NULL;
	      d->index = i;
	    }
	  else
	    arr[i].name = NULL;
	  free (key.name);
	}
      else if (! hash_insert (paths, xmemdup (&key, sizeof key)))
	xalloc_die ();
    }
  hash_free (paths);
  return compact_dirstats (arr, n);
}

/* Different -C contexts or symlinked parents can name the same directory.
   Keep its most recent metadata regardless of the final depth sort.  */
struct dirstat_identity
{
  dev_t st_dev;
  ino_t st_ino;
  idx_t index;
};

static size_t
dirstat_hash (void const *entry, size_t table_size)
{
  struct dirstat_identity const *d = entry;
  uintmax_t n = d->st_dev;
  int nshift = TYPE_WIDTH (n) - TYPE_WIDTH (d->st_dev);
  if (0 < nshift)
    n <<= nshift;
  n ^= d->st_ino;
  return n % table_size;
}

static bool
dirstat_compare (void const *a, void const *b)
{
  struct dirstat_identity const *x = a, *y = b;
  return x->st_dev == y->st_dev && x->st_ino == y->st_ino;
}

/* Resolve directory identities on the main thread, with only one -C
   descriptor retained at a time.  The extra stat prevents older
   attributes under one spelling from overwriting newer attributes
   under an alias.  Leave lookup failures for dirstat_apply to diagnose.  */
static idx_t
unique_dirstats (struct parallel_dirstat *arr, idx_t n)
{
  Hash_table *identities = hash_initialize (0, NULL, dirstat_hash,
					  dirstat_compare, free);
  if (! identities)
    xalloc_die ();
  for (idx_t i = 0; i < n; i++)
    {
      int fd = wd_fd_for (arr[i].change_dir);
      struct stat st;
      if (fstatat (fd, arr[i].name, &st, arr[i].atflag) == 0
	  && S_ISDIR (st.st_mode))
	{
	  struct dirstat_identity key = { .st_dev = st.st_dev,
	    .st_ino = st.st_ino, .index = i };
	  struct dirstat_identity *d = hash_lookup (identities, &key);
	  if (d)
	    {
	      if (arr[d->index].order < arr[i].order)
		{
		  arr[d->index].name = NULL;
		  d->index = i;
		}
	      else
		arr[i].name = NULL;
	    }
	  else if (! hash_insert (identities, xmemdup (&key, sizeof key)))
	    xalloc_die ();
	}
    }
  hash_free (identities);
  return compact_dirstats (arr, n);
}

static void
dirstat_apply (void *arg)
{
  struct parallel_dirstat *d = arg;
  int wdfd = d->wdfd;
  struct open_how how;
  memset (&how, 0, sizeof how);
  how.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC
	      | (d->atflag & AT_SYMLINK_NOFOLLOW ? O_NOFOLLOW : 0);
  how.resolve = RESOLVE_BENEATH;
  int fd = openat2 (wdfd, d->name, &how, sizeof how);
  if (fd < 0 && errno == EACCES)
    {
      /* Not readable by us: O_PATH still allows times and ownership, and
	 the mode goes through the path.  */
      how.flags = O_PATH | O_DIRECTORY | O_CLOEXEC
		  | (d->atflag & AT_SYMLINK_NOFOLLOW ? O_NOFOLLOW : 0);
      fd = openat2 (wdfd, d->name, &how, sizeof how);
    }
  if (fd < 0)
    {
      call_error (errno, "open", d->name);
      return;
    }
  mode_t cur = d->current_mode, mask = d->current_mode_mask;
  if (! d->interdir)
    {
      apply_times (fd, wdfd, d->name, d->name, d->atime, d->mtime, DIRTYPE);
      apply_owner (fd, d->name, d->uid, d->gid, DIRTYPE, &cur, &mask);
    }
  apply_mode (fd, wdfd, d->name, d->name,
	      d->mode & ~ parallel_current_umask (),
	      0 < same_permissions_option && ! d->interdir ? MODE_ALL : MODE_RWX,
	      cur, mask);
  close (fd);
}

void
parallel_apply_dirstats (struct parallel_dirstat *arr, idx_t n)
{
  if (n == 0)
    return;
  /* Even a single destination can have lexical aliases such as d and
     ./d.  Remove those without a stat per directory, then resolve inode
     identities only if symlinks or overlapping destinations need it.  */
  n = unique_dirstat_paths (arr, n);
  bool may_alias = aliases_seen;
  for (idx_t i = 1; i < n && ! may_alias; i++)
    may_alias = arr[i].change_dir != arr[0].change_dir;
  if (may_alias)
    n = unique_dirstats (arr, n);
  qsort (arr, n, sizeof *arr, dirstat_cmp);
  idx_t i = 0;
  while (i < n)
    {
      int depth = depth_of (arr[i].name);
      idx_t k = i;
      while (k < n && depth_of (arr[k].name) == depth)
	{
	  /* Changing destinations drains the previous batch before reusing
	     its descriptor, just as during member extraction.  */
	  arr[k].wdfd = wd_fd_for (arr[k].change_dir);
	  parallel_run_task (dirstat_apply, &arr[k]);
	  k++;
	}
      parallel_barrier ();
      i = k;
    }
}

#endif /* TAR_PARALLEL && TAR_PARALLEL_THREADS */
