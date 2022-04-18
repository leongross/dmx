/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * dm-mintegrity Author: Jan Kasiak <j.kasiak@gmail.com>
 * Based on dm-verity driver by: Mikulas Patocka <mpatocka@redhat.com>
 * Based on Chromium dm-verity driver (C) 2011 The Chromium OS Authors
 *
 * This file is released under the GPLv2.
 *
 * In the file "/sys/module/dm_mintegrity/parameters/prefetch_cluster" you can
 * set default prefetch value. Data are read in "prefetch_cluster" chunks from
 * the hash device. Setting this greatly improves performance when data and hash
 * are on the same disk on different partitions on devices with poor random
 * access behavior.
 */

#include <crypto/hash.h>
#include <linux/device-mapper.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/rwsem.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/rbtree_augmented.h>
#include <linux/radix-tree.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include <asm/smp.h>
#include <asm/page.h>

#include "../../../linux/lib/rust.h"

/*
 * To use the Rust modules no further includes to `rust.h` are needed.
 * The Rust source code will reside in rust/kernel/.
 * To export the functions add the crate to lib.rs and expose the C function
 * signature in lib/rust.h Since the code is linked against lib/, no further
 * includes are necessary. At this state of development where code may reside in
 * different branches, make sure to select the correct branch. Use the Makefile
 * seated in qemu/ to generate a correct build.
 *
 * If compiled manually, make sure to select the correct build target.
 * 	all: build against currently booted kernel
 * 	rust: build against the Rust kernel in the project structure (use LLVM=1
 * as well)
 *
 */

#define USE_RADIX 1  /* if USE_RADIX is 0, the kernel will crash */
#define CHECKPOINT 0 /* periodic journal checkpointing */
#define DEBUG 0
#undef DEBUG
#define TRICK 1
#define COARSE_LOCK 0

#define RUST 1

#define FEATURE_PREFETCH 0
#define FEATURE_EVICTOR 1

#define DM_MSG_PREFIX "dmx"

#define DM_MINTEGRITY_DEFAULT_PREFETCH_SIZE 524288
#define DM_MINTEGRITY_DEFAULT_REQUEST_LIMIT 262144
#define DM_MINTEGRITY_MAX_LEVELS 63
#define DM_MINTEGRITY_BLOCK_TOKENS 131072

static unsigned dm_mintegrity_prefetch_cluster =
    DM_MINTEGRITY_DEFAULT_PREFETCH_SIZE;
module_param_named(prefetch_cluster, dm_mintegrity_prefetch_cluster, uint,
                   S_IRUGO | S_IWUSR);

#define MJ_MAGIC 0x594c494c
/* Mint Journal Nothing Block */
#define TYPE_MJNB 0
/* Mint Journal Super Block */
#define TYPE_MJSB 1
/* Mint Journal Descriptor Block */
#define TYPE_MJDB 2
/* Mint Journal Commit Block */
#define TYPE_MJCB 3

/* Tag and transaction revoked */
#define J_TAG_REVOKE 1
/* Last tag */
#define J_TAG_LAST 2

#define J_PAGE_ORDER_SIZE 4
#define J_PAGE_CHUNK_SIZE (1 << J_PAGE_ORDER_SIZE)

#define BLOCK_READ (1 << 0)
#define BLOCK_ALLOC (1 << 1)
#define BLOCK_PREFETCH (1 << 2)
#define BLOCK_MEMORY (1 << 3)
#define BLOCK_DATA (1 << 4)

#define TYPE_EMPTY 0
#define TYPE_HASH 1
#define TYPE_DATA 2
#define TYPE_JOURNAL 3

#if FEATURE_EVICTOR
#define EVICT_H_THRLD 8
#define EVICT_L_THRLD 4
#endif

#if DEBUG
// static int dump_once = 0;
static uint64_t search_counter = 0;
static uint64_t search_hash_counter = 0;
static uint64_t search_data_counter = 0;
static uint64_t search_hash_missing_counter = 0;
static uint64_t search_data_missing_counter = 0;
static uint64_t search_found_counter = 0;
static uint64_t tree_insert_counter = 0;
static uint64_t clean_counter = 0;
static uint64_t data_dirty_counter = 0;
static uint64_t hash_dirty_counter = 0;
static uint64_t bio_add_page_counter = 0;
static uint64_t block_get_counter = 0;
static uint64_t tree_delete_counter = 0;
static uint64_t compute_hash_counter = 0;
static uint64_t compute_hmac_counter = 0;
static uint64_t journal_release_counter = 0;
static uint64_t journal_write_complete_counter = 0;
static uint64_t journal_commit_counter = 0;
static uint64_t journal_checkpoint_counter = 0;
static uint64_t verify_level_counter = 0;
static uint64_t tree_delete_empty_counter = 0;
static uint64_t tree_delete_hash_counter = 0;
static uint64_t tree_delete_data_counter = 0;
static uint64_t tree_delete_journal_counter = 0;
static uint64_t bio_add_page_read_counter = 0;
static uint64_t bio_add_page_write_counter = 0;
static uint64_t tree_insert_empty_counter = 0;
static uint64_t tree_insert_hash_counter = 0;
static uint64_t tree_insert_data_counter = 0;
static uint64_t tree_insert_journal_counter = 0;
static uint64_t total_tree_nodes = 0;
static uint64_t hash_reuse = 0;
static uint64_t prefetch_reuse = 0;
static uint64_t prefetch_useful = 0;
static uint64_t prefetch_counter = 0;
static uint64_t wait_completion_counter = 0;
static uint64_t journal_full = 0;
static uint64_t total_requests = 0;
static uint64_t pending_write = 0;
static uint64_t pending_prefetch = 0;
#endif
static uint64_t token_counter = 0;
static uint64_t checkpoint_work_counter = 0;
static uint64_t wait_counter = 0;

struct mint_journal_header
{
  uint32_t magic;    /* 0x594c494c */
  uint32_t type;     /* Super/Descriptor/Commit Block */
  uint32_t sequence; /* Sequence number */
  uint32_t options;  /* Options */
};

struct mint_journal_block_tag
{
  uint32_t low;    /* Destination sector low */
  uint32_t high;   /* Destination sector high */
  uint8_t options; /* Last or bits for escaped blocks */
} __attribute__((packed));

struct mint_journal_superblock
{
  struct mint_journal_header header;
  uint32_t tail; /* Circular buffer tail position */
  char state;    /* Clean, Dirty */
                 // Previous hmac
                 // Next hmac
};

struct journal_block
{
  struct dm_mintegrity *v;
  struct completion *event;
  uint8_t *data;

  struct bio bio;
  struct bio_vec bio_vec[J_PAGE_CHUNK_SIZE];

  atomic_t available;
  atomic_t finished;

  int size;
  bool hasExtra;

} __attribute__((aligned(8)));

struct data_block
{
  struct dm_mintegrity *v;

  struct list_head list;
#if !USE_RADIX
  struct rb_node node;
#endif
  uint8_t *data;
  sector_t sector;

  struct bio bio;
  struct bio_vec bio_vec;
  struct completion event;

  struct rw_semaphore lock;
  atomic_t writers;
  atomic_t ref_count;

  int type;
  bool dirty;
  bool verified;
  bool completion_initialized;
  bool is_prefetch;
};

struct dm_mintegrity
{
  // Block device
  struct dm_dev *dev;
  struct dm_dev *data_dev;
  struct dm_target *ti;

  // Hash
  char *alg_name;      /* Hash algorithm name */
  char *hmac_alg_name; /* HMAC hash algorithm name */

  uint32_t salt_size;   /* Size of salt */
  uint32_t secret_size; /* Size of HMAC secret */

  uint8_t *zero_digest; /* Hash digest of a zero block */
  uint8_t *root_digest; /* Hash digest of the root block */

  uint8_t *salt;        /* salt: its size is salt_size */
  uint8_t *secret;      /* HMAC secret: its size is secret_size */
  uint8_t *hmac_digest; /* HMAC digest */

  struct crypto_shash *tfm;      /* Hash algorithm */
  struct crypto_shash *hmac_tfm; /* HMAC hash algorithm */
  struct shash_desc *hmac_desc;  /* HMAC shash object */

  uint32_t digest_size;      /* hash digest size */
  uint32_t hmac_digest_size; /* HMAC hash digest size */

  uint32_t shash_descsize; /* crypto temp space size */

  // State
  int hash_failed; /* set to 1 if hash of any block failed */
  int created;

  // Sector numbers
  sector_t hash_start;       /* Hash start in blocks */
  sector_t journal_start;    /* Journal start in blocks */
  sector_t data_start;       /* Data start in blocks */
  sector_t data_start_shift; /* Data offset in 512-byte sectors */

  sector_t hash_blocks;    /* Number of hash blocks */
  sector_t journal_blocks; /* Number of journal blocks */
  sector_t data_blocks;    /* Number of data blocks */

  // Block size numbers
  uint8_t dev_block_bits;      /* log2(blocksize) */
  uint8_t hash_per_block_bits; /* log2(hashes in hash block) */
  uint32_t dev_block_bytes;    /* Number of bytes in a device block */

  unsigned char levels; /* Number of tree levels */

  // https://lwn.net/Articles/22909/ search for Mempool
  // "The purpose of mempools is to help out in situations where a memory
  // allocation must succeed, but sleeping is not an option"
  mempool_t *journal_page_mempool;
  mempool_t *journal_block_mempool;

  // Work queues
  struct workqueue_struct *workqueue; /* Workqueue for processing reads */
  struct workqueue_struct
      *prefetch_workqueue;                         /* Eorkqueue for processing prefetch */
  struct workqueue_struct *verify_level_workqueue; /* Verify levels for write */
  struct workqueue_struct *update_hash_workqueue;  /* Calculate hash for write */
  struct workqueue_struct *write_back_workqueue;   /* update the tree for write */

  // Locks
  struct rw_semaphore j_lock; /* Global journal read/write lock */

  // Journal
  struct mint_journal_superblock j_sb_header; /* Current journal header */

  struct journal_block *j_ds_buffer; /* Journal descriptor buffer */

  struct semaphore request_limit;
  atomic_t
      j_fill; /* Number of blocks in journal - need atomic due to writeback */

#if TRICK
  atomic_t j_pending_commit;
  struct completion j_pending_event;
#else
  atomic_t j_commit_outstanding;
#endif

  uint32_t j_ds_fill; /* Number of tags in current descriptor buffer */
  uint32_t j_ds_max;  /* Max number of tags in descriptor buffer */

  struct journal_block *jbs;
  atomic_t jbs_available;
  atomic_t jbs_finished;

  /* Starting blocks for each tree level. 0 is the lowest level. */
  sector_t hash_level_block[DM_MINTEGRITY_MAX_LEVELS];

// Block cache data structures
// https://lwn.net/Articles/175432/ RADIX TREES
#if USE_RADIX
  struct radix_tree_root block_tree_root;
  struct radix_tree_root hash_block_tree_root;
#else
  struct rb_root block_tree_root;
  struct rb_root hash_block_tree_root;
#endif

  struct list_head block_list_clean;
  struct list_head block_list_clean_hash;
  struct list_head block_list_prefetch;
  struct list_head block_list_hash_dirty;
  struct list_head block_list_data_dirty;

  // Locks for block cache
  struct mutex block_tree_lock;
  struct mutex block_list_clean_lock;
  struct mutex block_list_clean_hash_lock;
  struct mutex block_list_prefetch_lock;
  struct mutex block_list_hash_dirty_lock;
  struct mutex block_list_data_dirty_lock;

  // Number of available tokens
  atomic_t block_tokens;

  struct kmem_cache *kmem_cache_data_block;

  int num_hash_nodes;
  bool two_disks;
  bool full_journal;

#if CHECKPOINT
  struct delayed_work
      delayed_work; /* Work instance for commit and checkpointing */
  struct workqueue_struct
      *delayed_workqueue; /* workqueue for processing writes */
#endif

#if FEATURE_EVICTOR
  struct task_struct *evict_task;
  struct completion evict_wait;
#endif
};

struct dm_mintegrity_io
{
  struct dm_mintegrity *v; /* dm-mintegrity instance info */
  struct bvec_iter iter;
  sector_t block; /* Start of block IO */

  uint32_t n_blocks; /* Number of blocks in IO */

  /* Work instance for read/write queue */
  /*	struct work_struct verify_level_work;
          struct work_struct update_hash_work;
          struct work_struct write_back_work;
          int which;
          int tokens;
          sector_t sector;
          uint8_t *tag;
          int r;
          u8 *result;
          u8 *data;
          unsigned todo;
  */
  struct work_struct work;
  bio_end_io_t *orig_bi_end_io;
  void *orig_bi_private;
  u8 *previous_hash;

  /*
   * Simillar to
   * https://github.com/torvalds/linux/blob/master/drivers/md/dm-verity.h#L85
   * Five variably-size fields follow this struct:
   *
   * struct dm_buffer[v->levels + 1];
   * u8 hash_desc[v->shash_descsize];
   * u8 real_digest[v->digest_size];
   * u8 want_digest[v->digest_size];
   *
   * To access them use: io_hash_desc(), io_real_digest(), io_want_digest(),
   * io_dm_buffers(), and io_dm_j_buffers().
   *
   * Keep attribute aligned, because struct * need to be aligned at 8 byte
   * boundaries.
   */
} __attribute__((aligned(8)));

/*
 * Test if node is not in any list
 */
static inline bool node_not_in_list(struct list_head *node)
{
  return (node == NULL) || (node == LIST_POISON1) || (node == LIST_POISON2) ||
         (node->next == NULL) || (node->prev == NULL) ||
         (node->next == LIST_POISON1) || (node->prev == LIST_POISON2) ||
         list_empty(node);
}

static inline struct data_block *tree_search(struct radix_tree_root *root,
                                             sector_t sector)
{
  struct data_block *data =
      (struct data_block *)radix_tree_lookup(root, (unsigned long)sector);
#if DEBUG
  search_counter++;
  if (data)
  {
    search_found_counter++;
    if (data->type == TYPE_DATA)
      search_data_counter++;
    else if (data->type == TYPE_HASH)
      search_hash_counter++;
  }
#endif
  return data;
}

static inline int tree_insert(struct radix_tree_root *root,
                              struct data_block *data)
{
  int r;
#if DEBUG
  char *ty = "";
  tree_insert_counter++;
  switch (data->type)
  {
  case TYPE_EMPTY:
    tree_insert_empty_counter++;
    ty = "Empty";
    break;
  case TYPE_HASH:
    tree_insert_hash_counter++;
    ty = "Hash";
    break;
  case TYPE_DATA:
    tree_insert_data_counter++;
    ty = "Data";
    break;
  case TYPE_JOURNAL:
    tree_insert_journal_counter++;
    ty = "Journal";
    break;
  }

  // printk(KERN_ERR "Tree insert counter is %llu. Inserted node of type
  // %s\n",tree_insert_counter,ty);
#endif

  if ((r = radix_tree_insert(root, data->sector, data)) == -EEXIST)
  {
#if DEBUG
    printk("Trying to insert the same node of sector %d and type %d again\n",
           (int)data->sector, (int)data->type);
#endif
    radix_tree_delete(root, data->sector);
    r = radix_tree_insert(root, data->sector, data);
  }
  return r;
}

static inline int tree_delete(struct radix_tree_root *root,
                              struct data_block *data)
{
  return (radix_tree_delete(root, data->sector) != NULL);
}

/* Release block */
static inline void block_release(struct data_block *d)
{
  int ref_count;
  struct dm_mintegrity *v = d->v;

  mutex_lock(&v->block_list_clean_lock);
  mutex_lock(&v->block_list_clean_hash_lock);

  ref_count = atomic_dec_return(&d->ref_count);
  BUG_ON(ref_count < 0);

  if (ref_count == 0 && !d->dirty)
  {

#if DEBUG
    clean_counter++;
    // tree_delete_counter++;
#endif

    // mutex_lock(&v->block_tree_lock);
    // rb_erase(&d->node, &v->block_tree_root);
    // mutex_unlock(&v->block_tree_lock);

    if (d->type == TYPE_HASH)
      list_add_tail(&d->list, &v->block_list_clean_hash);
    else
      list_add_tail(&d->list, &v->block_list_clean);

    atomic_inc(&v->block_tokens);
  }
  else if (ref_count == 0 && node_not_in_list(&d->list))
  {
    // Last one holding onto it, its dirty, and its not in the dirty list
    struct list_head *list;
    struct mutex *list_lock;

    if (d->type == TYPE_DATA)
    {
      list = &v->block_list_data_dirty;
      list_lock = &v->block_list_data_dirty_lock;
#if DEBUG
      data_dirty_counter++;
#endif
    }
    else
    {
      list = &v->block_list_hash_dirty;
      list_lock = &v->block_list_hash_dirty_lock;
#if DEBUG
      hash_dirty_counter++;
#endif
    }

    mutex_lock(list_lock);
    /*
            printk(KERN_ERR "Checking for page fault. D type is %d \n",
       d->type); if(!list->prev || !list->prev->next || !list->next ||
       !list->next->prev)
            {
                    printk(KERN_ERR "About to have a page fault!!! \n");
            }
    */
    if (node_not_in_list(&d->list))
    {
      INIT_LIST_HEAD(&d->list);
    }
    if (!virt_addr_valid(list) || !virt_addr_valid(list->prev) ||
        !virt_addr_valid(list->next) || node_not_in_list(list))
    {
      // printk("Avoiding the poison page fault. 1\n");
      INIT_LIST_HEAD(list);
    }

    list_add_tail(&d->list, list);
    mutex_unlock(list_lock);
  }
  mutex_unlock(&v->block_list_clean_hash_lock);
  mutex_unlock(&v->block_list_clean_lock);
}

static inline void block_mark_dirty(struct data_block *d)
{
  // RACE: 123
  // What should this mean?
  d->dirty = true;
}

static void block_end_io(struct bio *bio)
{
  struct data_block *d = bio->bi_private;
  complete_all(&d->event); /* https://www.kernel.org/doc/Documentation/scheduler/completion.txt
                            */
  d->completion_initialized = false;
}

static void block_write_dirty(struct dm_mintegrity *v, bool data, bool flush)
{
  struct data_block *d;
  struct list_head *pos, *n;
  struct list_head *list;
  struct mutex *list_lock, *list_clean_lock;

  struct block_device *dev; /* https://linux-kernel-labs.github.io/refs/heads/master/labs/block_device_drivers.html#struct-block-device-operations-structure
                             */

#if DEBUG
  uint64_t *counter;
#endif

  uint64_t dirty_blocks;
  // Get list, and locks
  if (data)
  {
    list = &v->block_list_data_dirty;
    list_lock = &v->block_list_data_dirty_lock;
    list_clean_lock = &v->block_list_clean_lock;

    dev = (v->data_dev) ? v->data_dev->bdev : v->dev->bdev;

#if DEBUG
    counter = &data_dirty_counter;
#endif
  }
  else
  {
    list = &v->block_list_hash_dirty;
    list_lock = &v->block_list_hash_dirty_lock;
    list_clean_lock = &v->block_list_clean_hash_lock;
    dev = v->dev->bdev;
#if DEBUG
    counter = &hash_dirty_counter;
#endif
  }

  mutex_lock(&v->block_list_prefetch_lock);
  mutex_lock(list_clean_lock);
  mutex_lock(list_lock);
  dirty_blocks = 0;

  list_for_each_safe(pos, n, list)
  {
    struct bio *bio;

    d = container_of(pos, struct data_block, list);
    BUG_ON(atomic_read(&d->ref_count) < 0);

    if (atomic_read(&d->ref_count) != 0 && d->dirty)
    {
      printk(KERN_ERR "This shouldnt happen. The ref count of d is %d, sector "
                      "%llu, data %d.\n",
             atomic_read(&d->ref_count), (unsigned long long)d->sector, data);
      list_del(&d->list);
      INIT_LIST_HEAD(&d->list);
      continue;
    }

    list_del(&d->list);
    init_completion(&d->event);
    d->completion_initialized = true;

#if DEBUG
    (*counter)--;
    clean_counter++;
#endif
    if (d->is_prefetch)
      list_add_tail(&d->list, &v->block_list_prefetch);
    else if (d->type == TYPE_HASH)
      list_add_tail(&d->list, &v->block_list_clean_hash);
    else
      list_add_tail(&d->list, &v->block_list_clean);

    atomic_inc(&v->block_tokens);

    d->dirty = false;

    bio = &d->bio;
    // TO FIX: void bio_init(struct bio *bio, struct bio_vec *table, unsigned
    // short max_vecs);
    //  https://elixir.bootlin.com/linux/latest/source/drivers/md/dm-snap.c#L1343
    //  https://elixir.bootlin.com/linux/latest/source/drivers/md/md-multipath.c#L124
    //  (nulled)
    bio_init(bio, NULL, 0);

    bio->bi_iter.bi_sector = d->sector << (v->dev_block_bits - SECTOR_SHIFT);
    bio->bi_bdev = dev;

    bio->bi_opf = REQ_OP_WRITE;

    bio->bi_max_vecs = 1;
    bio->bi_io_vec = &d->bio_vec;

    bio->bi_end_io = block_end_io;
    bio->bi_private = d;
    bio_add_page(bio, virt_to_page(d->data), v->dev_block_bytes, 0);

#if DEBUG
    bio_add_page_write_counter += v->dev_block_bytes;

#endif
    // DEPRECATED: submit_bio_noacct is used to make I/O requests of block
    // devices. It is passed a struct bio, which describes the I/O that needs to
    // be done.
    // https://www.kernel.org/doc/htmldocs/kernel-api/API-generic-make-request.html
    // https://elixir.bootlin.com/linux/v3.16.85/source/drivers/md/dm-crypt.c#L1136
    // https://lore.kernel.org/lkml/20200629193947.2705954-18-hch@lst.de/:
    // rename submit_bio_noacct to submit_bio_noacct
    submit_bio_noacct(bio);
    dirty_blocks++;
  }

#if DEBUG
  if (dirty_blocks > 0)
    printk(KERN_ERR "Written %llu Dirty blocks.\n", dirty_blocks);
#endif

  mutex_unlock(list_lock);
  mutex_unlock(list_clean_lock);
  mutex_unlock(&v->block_list_prefetch_lock);

  if (flush)
  {
    blkdev_issue_flush(dev); /* https://elixir.bootlin.com/linux/latest/source/include/linux/blkdev.h#L797
                              */
  }
}

static inline void dummy_rotate(struct rb_node *old, struct rb_node *new) {}

/** Get a block of data, with absolute physical disk sector
 * Flags:
 * BLOCK_READ if READ of HASH block
 * BLOCK_ALLOC if WRITE (allocates, but doesn't issue write)
 * BLOCK_PREFETCH issue READ, but don't hold onto it
 * BLOCK_MEMORY only return if in memory, else return NULL
 * BLOCK_DATA if this is a data and not hash block
 *
 * Valid flags:
 * BLOCK_MEMORY - just get from memory
 *
 * Get the block_tree_lock before calling this function
 *
 */
static struct data_block *block_get(struct dm_mintegrity *v, sector_t sector,
                                    int flags, int *tokens)
{
  struct data_block *d;

  bool memory_only = (flags & BLOCK_MEMORY) == BLOCK_MEMORY;
  bool prefetch = (flags & BLOCK_PREFETCH) == BLOCK_PREFETCH;
  bool data_block = (flags & BLOCK_DATA) == BLOCK_DATA;
  bool read = (flags & BLOCK_READ) == BLOCK_READ;
  bool found = false;

#if DEBUG
  block_get_counter++;
#endif

// Lock
#if !COARSE_LOCK
  mutex_lock(&v->block_tree_lock);
#endif

  if (data_block)
    d = tree_search(&v->block_tree_root, sector);
  else
    d = tree_search(&v->hash_block_tree_root, sector);

  if (d)
  {
    found = true;
    BUG_ON(d->sector != sector); // is triggered!
  }

#if DEBUG
  if (found && !prefetch && d->is_prefetch)
    prefetch_useful++;
  if (!found && data_block)
    search_data_missing_counter++;
  else if (!found && !data_block)
    search_hash_missing_counter++;
#endif

  if (!found && !memory_only)
  {
    // Not here, and we need to allocate it
    uint8_t *data;
    struct bio *bio;

    // Get a clean buffer
    mutex_lock(&v->block_list_clean_lock);
    mutex_lock(&v->block_list_clean_hash_lock);
    mutex_lock(&v->block_list_prefetch_lock);

#if DEBUG
    // I think this triggers the kernel panic listed in the dumps dir
    BUG_ON(list_empty(v->block_list_clean.next) &&
           list_empty(v->block_list_clean_hash.next) &&
           list_empty(v->block_list_prefetch.next));
#endif

    if (!list_empty(&v->block_list_clean))
      d = list_entry(v->block_list_clean.next, struct data_block, list);
    else if (!list_empty(&v->block_list_prefetch))
    {
#if DEBUG
      prefetch_reuse++;
      if (prefetch_reuse % 1000 == 0)
      {
        printk(KERN_ERR
               "We prefetched %llu blocks and reused %llu prefetch blocks and "
               "%llu hash blocks. Prefetch usefulness is %llu.\n",
               prefetch_counter, prefetch_reuse, hash_reuse, prefetch_useful);
        printk(KERN_ERR "Wait completion counter is %llu\n",
               wait_completion_counter);
      }
#endif
      d = list_entry(v->block_list_prefetch.next, struct data_block, list);
    }
    else
    {
#if DEBUG
      hash_reuse++;
      if (hash_reuse % 1000 == 0)
      {
        printk(KERN_ERR
               "We prefetched %llu blocks and reused %llu prefetch blocks and "
               "%llu hash blocks. Prefetch usefulness is %llu.\n",
               prefetch_counter, prefetch_reuse, hash_reuse, prefetch_useful);
        printk(KERN_ERR "Wait completion counter is %llu\n",
               wait_completion_counter);
      }
#endif
      d = list_entry(v->block_list_clean_hash.next, struct data_block, list);
    }
#if DEBUG
    clean_counter--;
#endif
    list_del(&d->list);
    mutex_unlock(&v->block_list_prefetch_lock);
    mutex_unlock(&v->block_list_clean_hash_lock);
    mutex_unlock(&v->block_list_clean_lock);
#if DEBUG
    if (prefetch)
    {
      prefetch_counter++;
      if (prefetch_counter % 1000 == 0)
      {
        printk(KERN_ERR
               "We prefetched %llu blocks and reused %llu prefetch blocks and "
               "%llu hash blocks. Prefetch usefulness is %llu.\n",
               prefetch_counter, prefetch_reuse, hash_reuse, prefetch_useful);
        printk(KERN_ERR "Wait completion counter is %llu\n",
               wait_completion_counter);
      }
    }
#endif
    // In the rare event that we get a prefetch block from the list
    wait_for_completion(&d->event);

    // If its part of the tree, we need to remove it
    if (d->type != TYPE_EMPTY)
    {
      if (d->type == TYPE_DATA)
      {
#if USE_RADIX
        tree_delete(&v->block_tree_root, d);
#else
        rb_erase(
            &d->node,
            &v->block_tree_root); /* this seems to trigger a kernel panic, stack
                                     trace: RIP: 0010:rb_erase+0x16c/0x2d0 */
#endif
      }
      else if (d->type == TYPE_HASH)
      {
#if USE_RADIX
        tree_delete(&v->hash_block_tree_root, d);
#else
        rb_erase(&d->node, &v->hash_block_tree_root);
#endif
      }
      else
      {
        printk(KERN_WARNING "%s %d: unexpected data_block type %d\n", __func__,
               __LINE__, d->type);
      }
    }

    // Store data pointer, for easier zeroization
    data = d->data;
    memset(d, 0, sizeof(struct data_block));

    // Restore pointers
    d->v = v;
    d->data = data;
    d->sector = sector;
    d->type = data_block ? TYPE_DATA : TYPE_HASH;

    INIT_LIST_HEAD(&d->list);
    BUG_ON(atomic_read(&d->ref_count) != 0);

    atomic_set(&d->ref_count, 1);
    init_completion(&d->event);
    d->completion_initialized = true;

    if (prefetch)
      d->is_prefetch = true;
    else
      d->is_prefetch = false;

    init_rwsem(&d->lock);

    if (data_block)
      tree_insert(&v->block_tree_root, d);
    else
      tree_insert(&v->hash_block_tree_root, d);

    // Set up bio
    // Only send it out if its a read
    if (flags & BLOCK_READ)
    {
      bio = &d->bio;
      bio_init(bio, NULL, 0);
      bio->bi_iter.bi_sector = sector << (v->dev_block_bits - SECTOR_SHIFT);
      bio->bi_bdev = v->dev->bdev;
      bio->bi_opf = REQ_OP_READ;
      bio->bi_max_vecs = 1;
      bio->bi_io_vec = &d->bio_vec;
      bio->bi_end_io = block_end_io;
      bio->bi_private = d;
      bio_add_page(bio, virt_to_page(d->data), v->dev_block_bytes, 0);

#if DEBUG
      bio_add_page_read_counter += v->dev_block_bytes;
#endif

      submit_bio_noacct(bio);
    }
    else
    {
      // Complete the write event, so others know it can be used
      complete_all(&d->event);
      d->completion_initialized = false;
    }

    *tokens -= 1;

    if (prefetch)
    {
#if !COARSE_LOCK
      mutex_unlock(&v->block_tree_lock);
#endif
      block_release(d);
      return NULL;
    }
  }
  else if (found && !prefetch)
  {
    int ref_count = 0;

    ref_count = atomic_inc_return(&d->ref_count);
    if (ref_count >= 1 && d->dirty && !node_not_in_list(&d->list))
    {
      struct mutex *lock;
      if (d->type == TYPE_HASH)
      {
        lock = &v->block_list_hash_dirty_lock;
#if DEBUG
        hash_dirty_counter--;
#endif
      }
      else
      {
        lock = &v->block_list_data_dirty_lock;
#if DEBUG
        data_dirty_counter--;
#endif
      }

      mutex_lock(lock);
      list_del(&d->list);
      INIT_LIST_HEAD(&d->list);
      mutex_unlock(lock);
    }

    // Its in our buffer, its not a prefetch, so reuse it
    mutex_lock(&v->block_list_clean_lock);
    mutex_lock(&v->block_list_clean_hash_lock);
    mutex_lock(&v->block_list_prefetch_lock);

    if (ref_count == 1 && !d->dirty)
    {
      // We're the first to get it and its clean, so we need to move it out of
      // the free list
      if (!list_empty(&d->list))
      {
        list_del(&d->list);
        INIT_LIST_HEAD(&d->list);
        *tokens -= 1;
      }
      else
      {
        printk("List is empty!");
        printk("List is empty!");
        printk("List is empty!");
        printk("List is empty!");
        INIT_LIST_HEAD(&d->list);
        *tokens -= 1;
      }

#if DEBUG
      clean_counter--;
#endif
    }

    mutex_unlock(&v->block_list_prefetch_lock);
    mutex_unlock(&v->block_list_clean_hash_lock);
    mutex_unlock(&v->block_list_clean_lock);
  }

/* Unlock */
#if !COARSE_LOCK
  mutex_unlock(&v->block_tree_lock);
#endif
  /* Wait for read/write to finish */
  if ((!found && !memory_only && !prefetch && read) ||
      (!memory_only && !prefetch && !data_block && d->completion_initialized))
  {
#if DEBUG
    wait_completion_counter++;
#endif
    wait_for_completion_io(&d->event);
  }

  return d;
}

static void delete_all_blocks(struct dm_mintegrity *v)
{
  struct data_block *d;
  struct list_head *pos, *n;
  struct list_head *list;

#if USE_RADIX
  void **slot;
  struct radix_tree_iter iter;
#else
  struct rb_node *node;
#endif
  list = &v->block_list_hash_dirty;

  list_for_each_safe(pos, n, list)
  {
    d = container_of(pos, struct data_block, list);
    d->type = TYPE_EMPTY;
    BUG_ON(1);
    list_del(&d->list);
    list_add_tail(&d->list, &v->block_list_clean);
#if DEBUG
    clean_counter++;
    hash_dirty_counter--;
#endif
    atomic_inc(&v->block_tokens);
  }

  list = &v->block_list_data_dirty;
  list_for_each_safe(pos, n, list)
  {
    d = container_of(pos, struct data_block, list);
    d->type = TYPE_EMPTY;
    list_del(&d->list);
    list_add_tail(&d->list, &v->block_list_clean);
#if DEBUG
    clean_counter++;
    data_dirty_counter--;
#endif
    atomic_inc(&v->block_tokens);
  }

#if USE_RADIX
  radix_tree_for_each_slot(slot, &v->block_tree_root, &iter, 0)
  {
    d = (struct data_block *)*slot;
    d->type = TYPE_EMPTY;
  }
#else
  node = rb_first(&v->block_tree_root);
  while (node)
  {
    d = container_of(node, struct data_block, node);
    d->type = TYPE_EMPTY;
    node = rb_first(&v->block_tree_root);
  }
#endif
}

struct dm_mintegrity_prefetch_work
{
  struct work_struct work;
  struct dm_mintegrity *v;
  sector_t block;
  unsigned n_blocks;
};

static inline struct data_block **io_dm_buffers(struct dm_mintegrity *v,
                                                struct dm_mintegrity_io *io)
{
  return (struct data_block **)(io + 1);
}

static inline struct shash_desc *io_hash_desc(struct dm_mintegrity *v,
                                              struct dm_mintegrity_io *io)
{
  return (struct shash_desc *)(io_dm_buffers(v, io) + v->levels + 1);
}

static inline u8 *io_real_digest(struct dm_mintegrity *v,
                                 struct dm_mintegrity_io *io)
{
  return (u8 *)(io_hash_desc(v, io)) + v->shash_descsize;
}

static inline u8 *io_want_digest(struct dm_mintegrity *v,
                                 struct dm_mintegrity_io *io)
{
  return io_real_digest(v, io) + v->digest_size;
}

/*
 * Translate input sector number to the sector number on the target device.
 */

/*
        https://elixir.bootlin.com/linux/v5.17-rc8/source/drivers/md/dm-linear.c#L81
        static sector_t linear_map_sector(struct dm_target *ti, sector_t
   bi_sector)
        {
                struct linear_c *lc = ti->private;
                return lc->start + dm_target_offset(ti, bi_sector);
        }
*/
static sector_t mintegrity_map_sector(struct dm_mintegrity *v,
                                      sector_t bi_sector)
{
  return v->data_start_shift + dm_target_offset(v->ti, bi_sector);
}

/*
 * Return hash position of a specified block at a specified tree level
 * (0 is the lowest level).
 * The lowest "hash_per_block_bits"-bits of the result denote hash position
 * inside a hash block. The remaining bits denote location of the hash block.
 */
static sector_t mintegrity_position_at_level(struct dm_mintegrity *v,
                                             sector_t block, int level)
{
  return block >> (level * v->hash_per_block_bits);
}

/* Just return the hash, no new hash calculation
 * 	@param v: pointer to mintegrity superblock
 *	@param block: block to find hash position of
 *	@param hash_block: pointer to hash of block
 */
static void mintegrity_hash_at_level(struct dm_mintegrity *v, sector_t block,
                                     int level, sector_t *hash_block,
                                     unsigned *offset)
{
  sector_t position = mintegrity_position_at_level(v, block, level);
  unsigned idx;

  *hash_block =
      v->hash_level_block[level] + (position >> v->hash_per_block_bits);

  if (!offset)
    return;

  idx = position & ((1 << v->hash_per_block_bits) - 1);
  *offset = idx << (v->dev_block_bits - v->hash_per_block_bits);
}

static unsigned mintegrity_hash_buffer_offset(struct dm_mintegrity *v,
                                              sector_t block, int level)
{
  sector_t position = mintegrity_position_at_level(v, block, level);
  unsigned idx;
  idx = position & ((1 << v->hash_per_block_bits) - 1);
  return idx << (v->dev_block_bits - v->hash_per_block_bits);
}

/*
 * Calculate hash of buffer and put it in io_real_digest
 *
 * Enable the Rust function by setting defining RUST in the top of the program.
 * This option is enabled by default.
 */
#ifdef RUST
static int mintegrity_buffer_hash(struct dm_mintegrity_io *io, const u8 *data,
                                  unsigned int len)
{
  struct dm_mintegrity *v = io->v;
  struct shash_desc *desc;
  int r;
  desc = io_hash_desc(v, io);
  desc->tfm = v->tfm;
  // printk(KERN_ALERT "Rust hashing function");
  //  https://patchwork.kernel.org/project/linux-crypto/cover/20190415003709.1531-1-ebiggers@kernel.org/
  //  desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
#if DEBUG
  compute_hash_counter++;
#endif

  r = crypto_shash_init(desc);
  if (unlikely(r))
  {
    DMERR("crypto_shash_init failed: %d", r);
    return r;
  }

  return rust_calc_hash_salt_c(data, len, io_real_digest(v, io), v->salt,
                               v->salt_size, desc);
}
#else
static int mintegrity_buffer_hash(struct dm_mintegrity_io *io, const u8 *data,
                                  unsigned int len)
{
  struct dm_mintegrity *v = io->v;
  struct shash_desc *desc;
  int r;
  desc = io_hash_desc(v, io);
  desc->tfm = v->tfm;
  // https://patchwork.kernel.org/project/linux-crypto/cover/20190415003709.1531-1-ebiggers@kernel.org/
  // desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
#if DEBUG
  compute_hash_counter++;
#endif

  r = crypto_shash_init(desc);
  if (unlikely(r))
  {
    DMERR("crypto_shash_init failed: %d", r);
    return r;
  }

  r = crypto_shash_update(desc, v->salt, v->salt_size);
  if (unlikely(r))
  {
    DMERR("crypto_shash_update failed: %d", r);
    return r;
  }

  r = crypto_shash_update(desc, data, len);
  if (unlikely(r))
  {
    DMERR("crypto_shash_update failed: %d", r);
    return r;
  }

  r = crypto_shash_final(desc, io_real_digest(v, io));
  if (unlikely(r))
  {
    DMERR("crypto_shash_final failed: %d", r);
    return r;
  }

  return 0;
}
#endif

/*
 * Calculate hmac of root buffer. Clobbers v->hmac_desc and v->hmac_digest
 * Doesn't use locks, also assumes v->root_digest is locked.
 * Result hmac in v->hmac_digest
 */
static int mintegrity_hmac_hash(struct dm_mintegrity *v)
{
  int r = crypto_shash_setkey(v->hmac_tfm, v->secret, v->secret_size);
#if DEBUG
  compute_hmac_counter++;
#endif

  if (unlikely(r))
  {
    DMERR("crypto_shash_setkey failed: %d", r);
    return r;
  }

  r = crypto_shash_init(v->hmac_desc);
  if (unlikely(r))
  {
    DMERR("crypto_shash_init failed: %d", r);
    return r;
  }

  r = crypto_shash_update(v->hmac_desc, v->root_digest, v->digest_size);
  if (unlikely(r))
  {
    DMERR("crypto_shash_update failed: %d", r);
    return r;
  }

  r = crypto_shash_final(v->hmac_desc, v->hmac_digest);
  if (unlikely(r))
  {
    DMERR("crypto_shash_final failed: %d", r);
    return r;
  }

  return 0;
}

static void mintegrity_journal_release(struct journal_block *j)
{
  struct dm_mintegrity *v = j->v;

#if DEBUG
  journal_release_counter++;
#endif

  // Return data
  mempool_free(j->data, v->journal_page_mempool);
  memset(j, 0, sizeof(struct journal_block));
  mempool_free(j, v->journal_block_mempool);
}

static void mintegrity_journal_write_end_io(struct bio *bio)
{
  struct journal_block *j = bio->bi_private;

  if (j->event)
  {
    complete_all(j->event);
  }
#if DEBUG
  journal_write_complete_counter++;
#endif

  mintegrity_journal_release(j);
}

static void mintegrity_journal_read_end_io(struct bio *bio)
{
  struct journal_block *j = bio->bi_private;

  if (j->event)
  {
    complete_all(j->event);
  }
}

static void mintegrity_do_journal_block_io(struct journal_block *j)
{
  submit_bio_noacct(&j->bio);
}

static void mintegrity_init_journal_block(struct journal_block **jb,
                                          struct dm_mintegrity *v,
                                          sector_t sector, unsigned long opf,
                                          int size, bool setPages)
{
  int i;
  struct bio *bio;
  struct journal_block *j;
  *jb = j = mempool_alloc(v->journal_block_mempool, GFP_NOIO);

  j->data = mempool_alloc(v->journal_page_mempool, GFP_NOIO);
  j->v = v;
  j->size = size;
  j->event = NULL;
  atomic_set(&j->available, size);
  atomic_set(&j->finished, 0);
  bio = &j->bio;
  bio_init(bio, NULL, 0);
  bio->bi_iter.bi_sector = sector << (v->dev_block_bits - SECTOR_SHIFT);
  bio->bi_bdev = v->dev->bdev;
  bio->bi_opf = opf;

  bio->bi_max_vecs = J_PAGE_CHUNK_SIZE;
  bio->bi_io_vec = j->bio_vec;
  bio->bi_end_io = (opf & REQ_OP_WRITE ? mintegrity_journal_write_end_io
                                       : mintegrity_journal_read_end_io);
  bio->bi_private = j;

  if (setPages)
  {
    for (i = 0; i < min(J_PAGE_CHUNK_SIZE, size); i++)
    {
      BUG_ON(!bio_add_page(bio, virt_to_page(j->data + v->dev_block_bytes * i),
                           v->dev_block_bytes, 0));
    }
  }
}

static void mintegrity_read_journal_block(struct journal_block **jb,
                                          struct dm_mintegrity *v,
                                          sector_t sector)
{
  struct completion event;
  mintegrity_init_journal_block(jb, v, sector, READ, 1, true);
  init_completion(&event);
  (*jb)->event = &event;
  mintegrity_do_journal_block_io(*jb);

#if DEBUG
  printk(KERN_ERR
         "3: Waiting for completion in mintegrity_read_journal_block\n");
#endif
  wait_for_completion(&event);
#if DEBUG
  printk(KERN_ERR "3: Done waiting in mintegrity_read_journal_block\n");
#endif
}

#if TRICK

static inline int mintegrity_get_journal_ref(struct dm_mintegrity *v)
{
  return atomic_inc_return(&v->j_pending_commit);
}

static inline int mintegrity_put_journal_ref(struct dm_mintegrity *v)
{
  int ref_count = atomic_dec_return(&v->j_pending_commit);

  if (ref_count == 0)
    complete_all(&v->j_pending_event);

  return ref_count;
}

static inline void mintegrity_init_journal_ref(struct dm_mintegrity *v)
{
  init_completion(&v->j_pending_event);
  atomic_set(&v->j_pending_commit, 0);
}

#endif

static void mintegrity_commit_journal(struct dm_mintegrity *v, bool flush)
{
#if !TRICK
  int i = 0;
#endif

  char *tag_ptr;
  sector_t sector;
  struct mint_journal_header mjh;
  struct mint_journal_block_tag tag;
  struct mint_journal_superblock *js = &v->j_sb_header;
  int hpb = v->dev_block_bytes / (2 * v->digest_size);

  // Nothing to commit
  if (v->j_ds_fill == 0)
  {
    return;
  }

#if DEBUG
  journal_commit_counter++;
#endif

  // Journal block isn't fully used up
  if (v->jbs && ((v->full_journal && atomic_read(&v->jbs->available) != 0) ||
                 (!v->full_journal && atomic_read(&v->jbs_available) >= hpb)))
  {
    //  Use this spot for the descriptor block
    int which = 0;
    int toFree = 0;

    which = v->jbs->size -
            atomic_read(&v->jbs->available) / (v->full_journal ? 1 : hpb);

    toFree = (v->jbs->size - 1) - which;

#if TRICK
    while (1)
    {
      if (atomic_read(&v->j_pending_commit) == 0)
        break;

      init_completion(&v->j_pending_event);
      wait_for_completion(&v->j_pending_event);
    }
#else
    while (1)
    {
      volatile atomic_t *a = &v->j_commit_outstanding;
      if (atomic_read(a) == 0)
      {
        break;
      }
      if (i != 0 && i % 10000000 == 0)
      {
        printk(KERN_CRIT "1: 10 millions: %d, %d", i / 10000000,
               atomic_read(&v->j_commit_outstanding));
      }
      i++;
    }
#endif

    tag_ptr = v->j_ds_buffer->data + sizeof(struct mint_journal_header) +
              (v->j_ds_fill - 1) * sizeof(struct mint_journal_block_tag);

    memcpy(&tag, tag_ptr, sizeof(struct mint_journal_block_tag));

    tag.options |= 4;
    memcpy(tag_ptr, &tag, sizeof(struct mint_journal_block_tag));

    BUG_ON(!bio_add_page(
        &v->jbs->bio, virt_to_page(v->jbs->data + v->dev_block_bytes * which),
        v->dev_block_bytes, 0));

    memcpy(v->jbs->data + (v->dev_block_bytes * which), v->j_ds_buffer->data,
           v->dev_block_bytes);

    printk(KERN_ERR "Sending to mintegrity_do_journal_block_io \n");
    mintegrity_do_journal_block_io(v->jbs);
    printk(KERN_ERR "Return from mintegrity_do_journal_block_io \n");

    v->jbs = NULL;
    v->j_ds_buffer->event = NULL;

    mintegrity_journal_write_end_io(&v->j_ds_buffer->bio);

    if (toFree)
    {
      atomic_add(-toFree, &v->j_fill);
      if (atomic_read(&v->j_fill) < 0)
      {
        printk(KERN_CRIT "j_fill < 0");
      }
      if (js->tail < toFree)
      {
        js->tail = v->journal_blocks - 1 - (toFree - js->tail);
      }
      else
      {
        js->tail -= toFree;
      }
    }
#if TRICK

#endif
  }
  else
  {
#if DEBUG
    journal_full++;
    if (journal_full % 2000 == 0)
    {
      printk(KERN_ERR "Journal Full %llu times.\n", journal_full);
    }
#endif
#ifdef DEBUG
    printk(KERN_ERR "Journal is totally full!!");
#endif
#if TRICK
    while (true)
    {
      if (atomic_read(&v->j_pending_commit) == 0)
        break;

      init_completion(&v->j_pending_event);
      wait_for_completion(&v->j_pending_event);
    }
#else
    while (true)
    {
      volatile atomic_t *a = &v->j_commit_outstanding;
      if (atomic_read(a) == 0)
      {
        break;
      }
      if (i != 0 && i % 10000000 == 0)
      {
        printk(KERN_CRIT "2: 10 millions: %d, %d, wait_counter: %llu\n",
               i / 10000000, atomic_read(&v->j_commit_outstanding),
               wait_counter);
      }
      i++;
    }
    wait_counter++;
#endif

    tag_ptr = v->j_ds_buffer->data + sizeof(struct mint_journal_header) +
              (v->j_ds_fill - 1) * sizeof(struct mint_journal_block_tag);

    memcpy(&tag, tag_ptr, sizeof(struct mint_journal_block_tag));

    tag.options |= 4;
    memcpy(tag_ptr, &tag, sizeof(struct mint_journal_block_tag));

    sector = v->journal_start + ((js->tail) % (v->journal_blocks - 1));
    js->tail = (js->tail + 1) % (v->journal_blocks - 1);
    atomic_add(1, &v->j_fill);

    v->j_ds_buffer->bio.bi_opf = REQ_OP_WRITE;
    v->j_ds_buffer->bio.bi_iter.bi_sector =
        sector << (v->dev_block_bits - SECTOR_SHIFT);

#if DEBUG
    bio_add_page_write_counter += v->dev_block_bytes;
#endif
    BUG_ON(!bio_add_page(&v->j_ds_buffer->bio,
                         virt_to_page(v->j_ds_buffer->data), v->dev_block_bytes,
                         0));
    mintegrity_do_journal_block_io(v->j_ds_buffer);

#if TRICK
#endif
  }

  if (flush)
  {
    // printk(KERN_ERR "Flushing the journal \n");
    struct completion event;
    struct journal_block *jb;
    struct mint_journal_superblock *js = &v->j_sb_header;

    // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7d3bf613e99abbd96ac7b90ee3694a246c975021
    // https://www.mail-archive.com/linux-kernel@vger.kernel.org/msg1159111.html
    // (unsure)
    mintegrity_init_journal_block(
        &jb, v, v->journal_start + v->journal_blocks - 1,
        REQ_FUA | REQ_PREFLUSH | REQ_FUA | WRITE, 1, true);

    js->tail = cpu_to_le32(js->tail);
    js->state = 1;
    BUG_ON(!jb->data);

    memcpy(jb->data, js, sizeof(struct mint_journal_superblock));
    js->tail = le32_to_cpu(js->tail);

    memcpy(jb->data + sizeof(struct mint_journal_superblock), v->hmac_digest,
           v->hmac_digest_size);

    // Calculate hmac
    mintegrity_hmac_hash(v);
    memcpy(jb->data + sizeof(struct mint_journal_superblock) +
               v->hmac_digest_size,
           v->hmac_digest, v->hmac_digest_size);

    init_completion(&event);
    jb->event = &event;
    mintegrity_do_journal_block_io(jb);

#if DEBUG
    printk(KERN_ERR "4: Waiting for completion in mintegrity_commit_journal");
#endif
    wait_for_completion(&event);
#if DEBUG
    printk(KERN_ERR "4: Done waiting in mintegrity_commit_journal");
#endif
    if (v->two_disks)
    {
      block_write_dirty(v, true, false);
    }
  }

  v->j_ds_fill = 0;

  // Get new desciptor block
  sector = v->journal_start + ((js->tail) % (v->journal_blocks - 1));
  mintegrity_init_journal_block(&v->j_ds_buffer, v, sector, REQ_FUA, 1, false);
  mjh.magic = cpu_to_le32(MJ_MAGIC);
  mjh.type = cpu_to_le32(TYPE_MJDB);

  memset(v->j_ds_buffer->data, 0, v->dev_block_bytes);
  memcpy(v->j_ds_buffer->data, &mjh, sizeof(struct mint_journal_header));
}

static void mintegrity_add_buffer_to_journal(
    struct dm_mintegrity *v, sector_t sector, struct data_block **data_buffers,
    struct journal_block *journal_buffer, int error, char *tag_ptr, int which)
{
  int i;
  struct mint_journal_block_tag tag = {cpu_to_le32(sector),
                                       cpu_to_le32(sector >> 32), 0};
  int hpb = v->dev_block_bytes / (2 * v->digest_size);

  if (likely(data_buffers))
  {
    for (i = 0; i < v->levels; i++)
    {
      block_mark_dirty(data_buffers[i]);
      block_release(data_buffers[i]);
    }
  }

  if (unlikely(error))
  {
    tag.options |= 1;
  }
  if (tag_ptr)
  {
    memcpy(tag_ptr, &tag, sizeof(struct mint_journal_block_tag));
  }

  i = journal_buffer->size * (v->full_journal ? 1 : hpb);
  if (atomic_inc_return(&journal_buffer->finished) == i)
  {
    mintegrity_do_journal_block_io(journal_buffer);
  }
#if TRICK
  mintegrity_put_journal_ref(v);
#else
  atomic_dec(&v->j_commit_outstanding);
#endif
}

static void mintegrity_checkpoint_journal(struct dm_mintegrity *v)
{
  struct mint_journal_superblock *js = &v->j_sb_header;
#if DEBUG
  journal_checkpoint_counter++;
#endif

  if (v->full_journal)
  {
    block_write_dirty(v, false, false);
    block_write_dirty(v, true, true);
    if (v->two_disks)
    {
      blkdev_issue_flush(v->dev->bdev);
    }
  }
  else
  {
    block_write_dirty(v, false, true);
    block_write_dirty(v, true, true);
    if (v->two_disks)
    {
      blkdev_issue_flush(v->dev->bdev);
    }
  }
  atomic_set(&v->j_fill, 0);
  js->tail = 0;
}

static void mintegrity_get_memory_tokens(struct dm_mintegrity *v, int tokens)
{
  // Lock journal
  int cur_tokens;
  down_write(&v->j_lock);

  cur_tokens = atomic_read(&v->block_tokens);

  if (cur_tokens < tokens)
  {
#if DEBUG
    printk(KERN_INFO "Not enough tokens %llu\n", token_counter);
#endif
    printk(KERN_INFO "Not enough tokens %llu\n", token_counter);
    token_counter++;
    // Not enough memory - commit everything
    mintegrity_commit_journal(v, true);
    mintegrity_checkpoint_journal(v);
#if FEATURE_EVICTOR
  }
  else if ((cur_tokens * 10) <=
           (DM_MINTEGRITY_BLOCK_TOKENS * EVICT_L_THRLD))
  {
    /* Activate evict task */
    complete_all(&v->evict_wait);
#endif
  }

  BUG_ON(atomic_read(&v->block_tokens) < tokens);
  BUG_ON(atomic_sub_return(tokens, &v->block_tokens) < 0);

  up_write(&v->j_lock);
}

static int mintegrity_get_memory_tokens_pre(struct dm_mintegrity *v,
                                            int tokens)
{
  if (atomic_read(&v->block_tokens) < tokens)
  {
    int i = 0;
    for (i = 0; i < tokens; i++)
    {
      struct data_block *d =
          (struct data_block *)kzalloc(sizeof(struct data_block), GFP_KERNEL);
      if (!d)
      {
        return 1;
      }
      d->data = (uint8_t *)__get_free_page(GFP_KERNEL);
      if (!d->data)
      {
        kfree(d);
        return 1;
      }
      list_add_tail(&d->list, &v->block_list_clean);
      init_completion(&d->event);
      complete_all(&d->event);
      d->completion_initialized = false;
      d->is_prefetch = false;
    }
    atomic_add(tokens, &v->block_tokens);
  }
  // BUG_ON(atomic_read(&v->block_tokens) < tokens);
  // Can't recover without everything in memory right now...
  BUG_ON(atomic_sub_return(tokens, &v->block_tokens) < 0);
  return 0;
}

static void mintegrity_return_memory_tokens(struct dm_mintegrity *v,
                                            int tokens)
{
  atomic_add(tokens, &v->block_tokens);
}

/*
        Set the journal_block **buffer to the mintegrity_jbs journalbocks
   pointer If current journal is whack, new journal will be initialzed The tags
   will be transferred as well
*/
static int mintegrity_get_journal_buffer(struct dm_mintegrity *v,
                                         struct journal_block **buffer,
                                         uint8_t **tag)
{
  int r;
  struct mint_journal_superblock *js = &v->j_sb_header;

  // Lock journal
  down_write(&v->j_lock);

  // Check if we have space in the descriptor block for a tag
  if (v->j_ds_fill == v->j_ds_max)
  {
    // We don't lets get a new one
    // printk(KERN_ERR "We dont have enough descriptors\n");
    mintegrity_commit_journal(v, false);
  }

  // NO jbs or current one is full
  if (v->jbs == NULL || atomic_read(&v->jbs->available) == 0)
  {
    sector_t sector;
    int size = J_PAGE_CHUNK_SIZE;

    // Check for space - need blocks chunk + commit block
    if (atomic_read(&v->j_fill) + 1 + J_PAGE_CHUNK_SIZE >=
        v->journal_blocks - 1)
    {
      // Make space in journal
      mintegrity_commit_journal(v, true);
      mintegrity_checkpoint_journal(v);
    }

    // Not enough for a full chunk
    if (v->j_ds_fill + J_PAGE_CHUNK_SIZE >= v->j_ds_max)
    {
      size = v->j_ds_max - v->j_ds_fill;
    }

    // Get new one
    sector = (v->journal_start + ((js->tail) % (v->journal_blocks - 1)));
    mintegrity_init_journal_block(&v->jbs, v, sector, WRITE, size, false);
    v->jbs->hasExtra = false;

    // Increment tail position
    js->tail = (js->tail + size) % (v->journal_blocks - 1);
    atomic_add(size, &v->j_fill);

    if (v->full_journal)
    {
      atomic_set(&v->jbs->available, size);
    }
    else
    {
      atomic_set(&v->jbs->available,
                 size * v->dev_block_bytes / (2 * v->digest_size));
    }
    atomic_set(&v->jbs->finished, 0);
  }

  *buffer = v->jbs;

  if (v->full_journal)
  {
    r = (v->jbs->size - 1) - atomic_dec_return(&v->jbs->available);
    BUG_ON(!bio_add_page(&v->jbs->bio,
                         virt_to_page(v->jbs->data + v->dev_block_bytes * r),
                         v->dev_block_bytes, 0));
    if (r == v->jbs->size - 1)
    {
      v->jbs = NULL;
    }
  }
  else
  {
    int hpb = v->dev_block_bytes / (2 * v->digest_size);
    r = (v->jbs->size * hpb - 1) - atomic_dec_return(&v->jbs->available);
    if (r % hpb == 0)
    {
      BUG_ON(!bio_add_page(
          &v->jbs->bio,
          virt_to_page(v->jbs->data + v->dev_block_bytes * (r / hpb)),
          v->dev_block_bytes, 0));
    }

    if (r == v->jbs->size * hpb - 1)
    {
      v->jbs = NULL;
    }
  }

  // struct mint_journal_block_tag location in descriptor block
  *tag = v->j_ds_buffer->data + sizeof(struct mint_journal_header) +
         v->j_ds_fill * sizeof(struct mint_journal_block_tag);

  // Increment descriptor block fill
  v->j_ds_fill++;
#if !TRICK
  atomic_inc(&v->j_commit_outstanding);
#endif
  // Unlock journal

  up_write(&v->j_lock);
#if TRICK
  mintegrity_get_journal_ref(v);
#endif
  return r;
}

static void mintegrity_unmount_journal(struct dm_mintegrity *v)
{
  struct journal_block *jb;
  struct mint_journal_superblock *js = &v->j_sb_header;
  struct completion event;

  mintegrity_commit_journal(v, true);
  mintegrity_checkpoint_journal(v);
  mintegrity_hmac_hash(v);

  js->tail = 0;
  js->state = 0;

  mintegrity_init_journal_block(
      &jb, v, v->journal_start + v->journal_blocks - 1, WRITE, 1, true);

  memcpy(jb->data, js, sizeof(struct mint_journal_superblock));
  memcpy(jb->data + sizeof(struct mint_journal_superblock), v->hmac_digest,
         v->hmac_digest_size);
  memcpy(jb->data + sizeof(struct mint_journal_superblock) +
             v->hmac_digest_size,
         v->hmac_digest, v->hmac_digest_size);

  init_completion(&event);
  jb->event = &event;
  mintegrity_do_journal_block_io(jb);
  wait_for_completion(&event);
}

/*
        Recover the mintegrity journal.
*/
static int mintegrity_recover_journal(struct dm_mintegrity *v)
{
  struct dm_mintegrity_io *io;
  struct completion event;
  struct mint_journal_header mjh;
  struct journal_block *jb;
  struct mint_journal_superblock *js = &v->j_sb_header;
  char root_digest[v->digest_size];

  js->tail = 0;
  js->state = 0;

  // Max number of block tags in one journal descriptor block
  v->j_ds_max = (v->dev_block_bytes - sizeof(struct mint_journal_header)) /
                sizeof(struct mint_journal_block_tag);
  v->j_ds_max = (v->j_ds_max) - (v->j_ds_max % J_PAGE_CHUNK_SIZE) - 1;

  v->journal_block_mempool =
      mempool_create_kmalloc_pool(12000, sizeof(struct journal_block));
  v->journal_page_mempool = mempool_create(
      12000, (void *(*)(gfp_t, void *))__get_free_pages,
      (void (*)(void *, void *))free_pages,
      (void *)J_PAGE_ORDER_SIZE); // kernel oops: dmsetup: page allocation
                                  // failure: order:4, mode:0xcc0(GFP_KERNEL),
                                  // nodemask=(null),cpuset=/,mems_allowed=0

  // Allocate io struct for usage
  // https://lore.kernel.org/dm-devel/1454860417-3203-10-git-send-email-snitzer@redhat.com/
  io = kzalloc(v->ti->per_io_data_size, GFP_KERNEL);
  if (!io)
  {
    DMERR("Failed to allocate memory for temp io\n");
    return -ENOMEM;
  }
  io->v = v;

  // Read superblock
  mintegrity_read_journal_block(&jb, v,
                                v->journal_start + v->journal_blocks - 1);
  memcpy(js, jb->data, sizeof(struct mint_journal_superblock));
  js->tail = le32_to_cpu(js->tail);

  /*
  Sector journal:
  * all data matches new hashes
          -> replay new hashes and recover from hmac
          -> ok, proceed to recover from hmac
  * something doesnt match, meaning merkle tree is old version, and data was
  stopped from fulling writing out
          -> check all old hashes against old tree
          -> check all hashes, and verify that they form new root hash
          -> check that data matches either old or new
  */

  // Dirty
  if (js->state)
  {
    sector_t sector_start, sector_end;
    unsigned opf;

    printk(KERN_CRIT "Recoverying journal...\n");

    // Back up root digest
    // Compute new hmac
    mintegrity_hmac_hash(v);
    memcpy(root_digest, v->root_digest, v->digest_size);
    // Replay descriptor blocks until tail
    sector_start = v->journal_start;
    sector_end = v->journal_start + js->tail;

    while (true)
    {
      int i, level;
      bool found;
      struct journal_block *desc_jb, *data_jb;
      sector_t sector_descriptor = sector_start + 1;
      found = false;
      printk(KERN_CRIT "Scanning for desc: %ld, %ld", sector_descriptor,
             sector_end);

      while (sector_descriptor <= sector_end)
      {
        mintegrity_read_journal_block(&desc_jb, v, sector_descriptor);
        memcpy(&mjh, desc_jb->data, sizeof(struct mint_journal_header));
        mjh.magic = le32_to_cpu(mjh.magic);
        mjh.type = le32_to_cpu(mjh.type);

        if (mjh.magic == MJ_MAGIC && mjh.type == TYPE_MJDB)
        {
          found = true;
          break;
        }
        mintegrity_journal_release(desc_jb);
        sector_descriptor++;
      }

      // Didn't find another descriptor
      if (!found)
      {
        break;
      }
      printk(KERN_CRIT "Descriptor: %ld...\n", sector_descriptor);

      // Loop through descriptor tags
      for (i = 0; i < v->j_ds_max; i++)
      {
        int tokens;
        int r;
        struct data_block *d, *h;
        uint32_t options;
        sector_t data_sector;

        struct mint_journal_block_tag *tag =
            (struct mint_journal_block_tag
                 *)(desc_jb->data + sizeof(struct mint_journal_header) +
                    i * sizeof(struct mint_journal_block_tag));
        data_sector = le32_to_cpu(tag->high);
        data_sector = (data_sector << 32) | le32_to_cpu(tag->low);
        options = le32_to_cpu(tag->options);

        if (options & 1)
        {
          // Last one
          if (options & 4)
          {
            break;
          }
          // Skip this one
          continue;
        }

        printk(KERN_CRIT "Write data to: %ld -> %ld\n", data_sector,
               data_sector + v->data_start);

        // Read data to write
        mintegrity_read_journal_block(&data_jb, v, sector_start + i);

        // Add escaped magic sequence
        if (options & 2)
        {
          data_jb->data[0] = 0x59;
          data_jb->data[1] = 0x4c;
          data_jb->data[2] = 0x49;
          data_jb->data[3] = 0x4c;
        }

        // Get destination data
        tokens = v->levels + 1;
        if (mintegrity_get_memory_tokens_pre(v, tokens))
        {
          mintegrity_journal_release(desc_jb);
          mintegrity_journal_release(jb);
          kfree(io);
          return -ENOMEM;
        }

        d = block_get(v, data_sector + v->data_start, BLOCK_DATA, &tokens);
        memcpy(d->data, data_jb->data, v->dev_block_bytes);
        mintegrity_journal_release(data_jb);

        r = mintegrity_buffer_hash(io, d->data, v->dev_block_bytes);
        block_release(d);
        if (r)
        {
          mintegrity_journal_release(desc_jb);
          mintegrity_journal_release(jb);
          kfree(io);
          if (tokens)
            mintegrity_return_memory_tokens(v, tokens);
          return -EINVAL;
        }

        // Write things bottom up
        for (level = 0; level < v->levels; level++)
        {
          sector_t hash_block;
          unsigned offset;

          mintegrity_hash_at_level(v, data_sector, level, &hash_block, &offset);
          h = block_get(v, hash_block, BLOCK_READ, &tokens);

          memcpy(h->data + offset, io_real_digest(v, io), v->digest_size);
          r = mintegrity_buffer_hash(io, h->data, v->dev_block_bytes);

          block_release(h);
          if (r)
          {
            mintegrity_journal_release(desc_jb);
            mintegrity_journal_release(jb);
            kfree(io);
            if (tokens)
              mintegrity_return_memory_tokens(v, tokens);
            return -EINVAL;
          }
        }
        if (tokens)
          mintegrity_return_memory_tokens(v, tokens);

        // Copy into root
        memcpy(v->root_digest, io_real_digest(v, io), v->digest_size);

        // Last tag
        if (options & 4)
        {
          break;
        }
      }
      mintegrity_journal_release(desc_jb);
      sector_start = sector_descriptor;
    }

    // Compute new hmac
    mintegrity_hmac_hash(v);

    if (memcmp(v->hmac_digest,
               jb->data + sizeof(struct mint_journal_superblock) +
                   v->hmac_digest_size,
               v->hmac_digest_size))
    {
      printk(KERN_CRIT "Recovered hmac doesn't match!\n");
      // New hmac doesn't match - abort everything
      delete_all_blocks(v);

      // Restore previous
      memcpy(v->root_digest, root_digest, v->digest_size);

      // Compute original hmac
      mintegrity_hmac_hash(v);

      if (memcmp(v->hmac_digest,
                 jb->data + sizeof(struct mint_journal_superblock),
                 v->hmac_digest_size))
      {
        printk(KERN_CRIT "Original hmac doesn't match!\n");
        // Original doesn't match - print error message
        // Will try to read as best as possible
      }
      else
      {
        printk(KERN_CRIT "Original hmac matches!\n");
      }
    }
    else
    {
      printk(KERN_CRIT "Recovered hmac matches!\n");
      // New hmac matches! - write everything out
      block_write_dirty(v, false, true);
      block_write_dirty(v, true, true);
    }
    // Write out clean journal end
    mintegrity_journal_release(jb);
    js->tail = 0;
    js->state = 0;

    // WRITE_SYNC: comapte write_dev_supers function
    // https://elixir.bootlin.com/linux/v5.17-rc8/source/fs/btrfs/disk-io.c#L3973
    // REQ_META REQ_PRIO:
    // https://patchwork.kernel.org/project/linux-block/patch/20190209045311.15677-20-colyli@suse.de/
    // unsigned opf = REQ_OP_WRITE | REQ_FUA | REQ_SYNC | REQ_META | REQ_PRIO;
    opf = REQ_OP_WRITE | REQ_FUA | REQ_SYNC;

    mintegrity_init_journal_block(
        &jb, v, v->journal_start + v->journal_blocks - 1, opf, 1, true);
    memcpy(jb->data, js, sizeof(struct mint_journal_superblock));
    memcpy(jb->data + sizeof(struct mint_journal_superblock), v->hmac_digest,
           v->hmac_digest_size);
    memcpy(jb->data + sizeof(struct mint_journal_superblock) +
               v->hmac_digest_size,
           v->hmac_digest, v->hmac_digest_size);

    init_completion(&event);
    jb->event = &event;
    mintegrity_do_journal_block_io(jb);
    wait_for_completion(&event);
  }
  else
  {
    int tokens;
    struct data_block *h;
    sector_t hash_block;
    unsigned offset;

    tokens = 1;
    mintegrity_get_memory_tokens_pre(v, tokens);
    mintegrity_hash_at_level(v, 0, v->levels - 1, &hash_block, &offset);
    h = block_get(v, hash_block, BLOCK_READ, &tokens);
    if (tokens)
      mintegrity_return_memory_tokens(v, tokens);
    mintegrity_buffer_hash(io, h->data, v->dev_block_bytes);

    if (memcmp(v->root_digest, io_real_digest(v, io), v->digest_size))
    {
      printk(KERN_CRIT "Root node doesn't match!");

      // Back up root digest

      memcpy(root_digest, v->root_digest, v->digest_size);
      memcpy(v->root_digest, io_real_digest(v, io), v->digest_size);
      mintegrity_hmac_hash(v);

      if (memcmp(v->hmac_digest,
                 jb->data + sizeof(struct mint_journal_superblock),
                 v->hmac_digest_size))
      {
        printk(KERN_CRIT "Recovery hmac doesn't match either!");
        memcpy(v->root_digest, root_digest, v->digest_size);
        mintegrity_hmac_hash(v);
      }
    }
    block_release(h);
  }

  kfree(io);

  // Number of blocks necessary per transaction - packed digests + data block
  v->j_ds_fill = 0;

  // Need at least one transaction + superblock + descriptor + commit
  if (v->journal_blocks < 4)
  {
    return -EINVAL;
  }

  // New descriptor block
  mintegrity_init_journal_block(&v->j_ds_buffer, v, (v->journal_start), WRITE,
                                1, false);

  // Copy descriptor header
  mjh.magic = cpu_to_le32(MJ_MAGIC);
  mjh.type = cpu_to_le32(TYPE_MJDB);
  memset(v->j_ds_buffer->data, 0, v->dev_block_bytes);
  memcpy(v->j_ds_buffer->data, &mjh, sizeof(struct mint_journal_header));

  js->tail = 0;
  atomic_set(&v->j_fill, 0);

#if TRICK
  mintegrity_init_journal_ref(v);
#else
  atomic_set(&v->j_commit_outstanding, 0);
#endif

  atomic_set(&v->jbs_available, 0);
  atomic_set(&v->jbs_finished, 0);
  v->jbs = NULL;

  return 0;
}

/*
 * Verify hash of a metadata block pertaining to the specified data block
 * ("block" argument) at a specified level ("level" argument).
 *
 * On successful return, io_want_digest(v, io) contains the hash value for
 * a lower tree level or for the data block (if we're at the lowest level).
 *
 * If "skip_unverified" is true, unverified buffer is skipped and 1 is returned.
 * If "skip_unverified" is false, unverified buffer is hashed and verified
 * against current value of io_want_digest(v, io).
 *
 * If dmb is not NULL, then the buffer, data and offset are stored into that
 * pointer and the dm-bufio buffer is NOT RELEASED
 *
 * Lock the tree lock before calling this function.
 */

static int mintegrity_verify_level(struct dm_mintegrity_io *io, sector_t block,
                                   int level, bool skip_unverified,
                                   struct data_block **dmb, int *tokens)
{
  int r;
  sector_t hash_block;
  unsigned offset;
  struct data_block *d;
  struct dm_mintegrity *v = io->v;

  u8 *result;

  mintegrity_hash_at_level(v, block, level, &hash_block, &offset);
#if DEBUG
  verify_level_counter++;
#endif

  // printk(KERN_CRIT "mintegrity_verify_level: %ld, %d, %d, %p, %d\n", block,
  // level, skip_unverified, dmb, *tokens);

  d = block_get(v, hash_block,
                BLOCK_READ | (skip_unverified ? BLOCK_MEMORY : 0), tokens);
  if (!d)
  {
    printk(KERN_ALERT
           "block_get returned null (mintegrity_verify_level)\n (miss)");
    return 1;
  }

  // https://lore.kernel.org/lkml/20171127103824.36526-3-mark.rutland@arm.com/
  // https://www.spinics.net/lists/kernel/msg2657453.html
  // if (!ACCESS_ONCE(d->verified))

  if (skip_unverified)
  {
    r = 1;
    // printk(KERN_ERR "Skipping unverified!\n");
    // DMERR_LIMIT("metadata block %llu is skipped, block %llu, level %d, offset
    // %u",
    //		(unsigned long long)hash_block, block, level, offset);
    goto release_ret_r;
  }

  r = mintegrity_buffer_hash(io, d->data, v->dev_block_bytes);
  if (unlikely(r))
  {
    printk(KERN_ERR "Bad buffer hash!\n");
    goto release_ret_r;
  }

  result = io_real_digest(v, io);

  if (unlikely(memcmp(result, io_want_digest(v, io), v->digest_size)))
  {
    // Retry once in case of write race condition
    printk(KERN_DEBUG "%s %d: digest mis-match for the first try (meta %llu "
                      "block %llu level %d offset %u\n",
           __func__, __LINE__, (unsigned long long)hash_block,
           (unsigned long long)block, level, offset);

    /*
            commit af41db5ef7c7cf0fee860f65cab59d0d188098d2
            Author: Mark Rutland <mark.rutland@arm.com>
            Date:   Mon Jul 16 11:05:57 2018 -0700

            tools/memory-model: Remove ACCESS_ONCE() from model

            Since commit:

            b899a850431e2dd0 ("compiler.h: Remove ACCESS_ONCE()")

            ... there has been no definition of ACCESS_ONCE() in the kernel
       tree, and it has been necessary to use READ_ONCE() or WRITE_ONCE()
       instead.
    */
    // https://stackoverflow.com/questions/34988277/write-once-in-linux-kernel-lists

    // if (WRITE_ONCE(d->verified, 1))
    if (READ_ONCE(d->verified))
    {
      // FIXME: should we just cast the data_block?
      goto normal_return;
    }

    memcpy(io_want_digest(v, io), io->previous_hash, v->digest_size);
    r = mintegrity_buffer_hash(io, d->data, v->dev_block_bytes);

    if (unlikely(r))
    {
      printk(KERN_ERR "Second bad buffer hash!\n");
      goto release_ret_r;
    }

    result = io_real_digest(v, io);

    if (unlikely(memcmp(result, io_want_digest(v, io), v->digest_size)) &&
        //! ACCESS_ONCE(d->verified))
        !READ_ONCE(d->verified))
    {
      printk(KERN_ERR "Metadata block is corrupted!\n");
      DMERR_LIMIT(
          "metadata block %llu is corrupted, block %llu, level %d, offset %u",
          (unsigned long long)hash_block, (unsigned long long)block, level,
          offset);
      v->hash_failed = 1;
      dump_stack();
      r = -EIO;
      goto release_ret_r;
    }
  }

  d->verified = true;

normal_return:
  memcpy(io_want_digest(v, io), d->data + offset, v->digest_size);
  io->previous_hash = d->data + offset;

  // Return back the whole block we read and verified
  if (dmb)
  {
    *dmb = d;
  }
  else
  {
    block_release(d);
  }

  return 0;

release_ret_r:
  block_release(d);
  return r;
}

/*
 * Verify one "dm_mintegrity_io" structure.
 */
static int mintegrity_verify_read_io(struct dm_mintegrity_io *io)
{
  struct dm_mintegrity *v = io->v;
  struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_io_data_size);
  unsigned b;
  int i, j, r = 0;
  struct data_block **dm_buffers = io_dm_buffers(v, io);
  struct shash_desc *desc;
  bool skip_chain = false;

#if COARSE_LOCK
  mutex_lock(&v->block_tree_lock);
#endif

  for (b = 0; b < io->n_blocks; b++)
  {
    int r;
    int tokens;
    u8 *result;
    unsigned todo;
    sector_t data_sector;
    data_sector = io->block + b;
    skip_chain = false;

    if (likely(v->levels))
    {
      /*
       * First, we try to get the requested hash for
       * the current block. If the hash block itself is
       * verified, zero is returned. If it isn't, this
       * function returns non-0 and we fall back to whole
       * chain verification.
       */
      tokens = 1;
      mintegrity_get_memory_tokens(v, tokens);

      // Bhu: lock tree
      r = mintegrity_verify_level(io, data_sector, 0, true, NULL, &tokens);

      // Bhu: unlock tree
      if (tokens)
        mintegrity_return_memory_tokens(v, tokens);
      if (likely(!r))
      {
        skip_chain = true;
        goto test_block_hash;
      }
      if (r < 0)
      {
#if COARSE_LOCK
        mutex_unlock(&v->block_tree_lock);
#endif
        return r;
      }
    }

    memcpy(io_want_digest(v, io), v->root_digest, v->digest_size);

    // Race condition fix
    io->previous_hash = v->root_digest;

    // Get memory buffer tokens
    tokens = v->levels;
    mintegrity_get_memory_tokens(v, tokens);

    // Bhu: lock tree
    for (i = v->levels - 1; i >= 0; i--)
    {
      int r = mintegrity_verify_level(io, data_sector, i, false, dm_buffers + i,
                                      &tokens);
      if (unlikely(r))
      {
#if COARSE_LOCK
        mutex_unlock(&v->block_tree_lock);
#endif

        if (tokens)
          mintegrity_return_memory_tokens(v, tokens);
        for (j = v->levels - 1; j > i; j--)
        {
          block_release(dm_buffers[j]);
        }
        return r;
      }
    }
    // Bhu: unlock tree
    if (tokens)
      mintegrity_return_memory_tokens(v, tokens);

  test_block_hash:
    desc = io_hash_desc(v, io);
    desc->tfm = v->tfm;
    // desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
    result = io_real_digest(v, io);
    r = crypto_shash_init(desc);

    if (r)
    {
      DMERR("crypto_shash_init failed: %d", r);
      goto release_ret_r;
    }
    r = crypto_shash_update(desc, v->salt, v->salt_size);

    if (r)
    {
      DMERR("crypto_shash_update failed: %d", r);
      goto release_ret_r;
    }

    todo = 1 << v->dev_block_bits;
    do
    {
      u8 *page;
      unsigned len;
      struct bio_vec bv = bio_iter_iovec(bio, io->iter);

      page = kmap_atomic(bv.bv_page);
      len = bv.bv_len;
      if (likely(len >= todo))
      {
        len = todo;
      }
      r = crypto_shash_update(desc, page + bv.bv_offset, len);
      kunmap_atomic(page);

      if (r)
      {
        DMERR("crypto_shash_update failed: %d", r);
        goto release_ret_r;
      }

      bio_advance_iter(bio, &io->iter, len);
      todo -= len;
    } while (todo);

#if DEBUG
    compute_hash_counter++;
#endif
    r = crypto_shash_final(desc, result);

    if (r)
    {
      DMERR("crypto_shash_final failed: %d", r);
      goto release_ret_r;
    }

    if (memcmp(result, io_want_digest(v, io), v->digest_size))
    {
      // If zero digest is enabled and it matches the wanted digest
      if (v->zero_digest &&
          !memcmp(io_want_digest(v, io), v->zero_digest, v->digest_size))
      {
        // Zero it out
        todo = 1 << v->dev_block_bits;
        // FIXME: hack to reset iterator
        io->iter.bi_sector -= (todo >> 9);
        io->iter.bi_size += todo;
        io->iter.bi_idx--;
        io->iter.bi_bvec_done = 0;

        do
        {
          u8 *page;
          unsigned len;
          struct bio_vec bv = bio_iter_iovec(
              bio, io->iter); // kernel panic: page not found BUG: unable to
                              // handle page fault for address: ffff88910166029c
                              // -> give qemu more ram :)

          page = kmap_atomic(bv.bv_page);
          len = bv.bv_len;
          if (likely(len >= todo))
          {
            len = todo;
          }

          memset(page + bv.bv_offset, 0, len);
          kunmap_atomic(page);

          bio_advance_iter(bio, &io->iter, len);
          todo -= len;
        } while (todo);
      }
      else
      {
        DMERR_LIMIT("data block %llu is corrupted",
                    (unsigned long long)(io->block + b));
        v->hash_failed = 1;
        r = -EIO;
        goto release_ret_r;
      }
    }

    if (!skip_chain)
    {
      for (i = v->levels - 1; i >= 0; i--)
      {
        block_release(dm_buffers[i]);
      }
    }
  }
// end for
#if COARSE_LOCK
  mutex_unlock(&v->block_tree_lock);
#endif

  return 0;

release_ret_r:
#if COARSE_LOCK
  mutex_unlock(&v->block_tree_lock);
#endif

  if (!skip_chain)
  {
    for (i = v->levels - 1; i >= 0; i--)
    {
      block_release(dm_buffers[i]);
    }
  }
  return r;
}

static int mintegrity_verify_write_io(struct dm_mintegrity_io *io)
{
  unsigned b;
  int i, j;
  struct data_block *data_block, *d;
  struct dm_mintegrity *v = io->v;
  struct bio *bio = dm_bio_from_per_bio_data(io, v->ti->per_io_data_size);
  // int hpb = v->dev_block_bytes / (2 * v->digest_size);

  for (b = 0; b < io->n_blocks; b++)
  {
    int r;
    u8 *result;
    u8 *data;
    unsigned todo;
    uint8_t *tag = NULL;

    int which;
    int tokens;

    // Pointers for modified hash and data block
    struct data_block **dm_buffers = io_dm_buffers(v, io);

    // Pointer for journal entry
    struct journal_block *j_buffer;
    sector_t sector = io->block + b;

    // Set all to NULL for possible cleanup
    for (i = 0; i < v->levels + 1; i++)
    {
      dm_buffers[i] = NULL;
    }

    // while (true) {
    //	if((!v->full_journal && atomic_read(&v->jbs_available) >= hpb) &&
    // atomic_read(v->j_commit_outstanding) > 0) {
    //		//Wait for the journal buffer to be refilled.
    //		printk("Waiting for journal buffer to be refilled\n");
    //	}
    //	else
    //		break;
    // }

    // Get memory buffer tokens
    tokens = v->levels + 1;
    mintegrity_get_memory_tokens(v, tokens);

    // Get journal block
    if ((which = mintegrity_get_journal_buffer(v, &j_buffer, &tag)) < 0)
    {
      // Safe to return because nothing needs to be cleaned up here
      if (tokens)
        mintegrity_return_memory_tokens(v, tokens);
      DMERR("Get journal buffer error!!\n");
      return -EIO;
    }

    // The io digest we want is the root
    memcpy(io_want_digest(v, io), v->root_digest, v->digest_size);

    // Read levels, TOP DOWN and compare to io want, which is set after
    // every successive read
    io->previous_hash = v->root_digest;

// Bhu: lock tree
#if COARSE_LOCK
    mutex_lock(&v->block_tree_lock);
#endif

    for (i = v->levels - 1; i >= 0; i--)
    {
      r = mintegrity_verify_level(io, sector, i, false, dm_buffers + i,
                                  &tokens);
      if (unlikely(r))
      {
        DMERR("failed write read layers");

#if COARSE_LOCK
        mutex_unlock(&v->block_tree_lock);
#endif

        for (j = v->levels - 1; j > i; j--)
        {
          atomic_dec(&dm_buffers[j]->writers);
          block_release(dm_buffers[j]);
        }

        mintegrity_add_buffer_to_journal(v, sector, NULL, j_buffer, -EIO, tag,
                                         which);
        if (tokens)
          mintegrity_return_memory_tokens(v, tokens);
        return -EIO;
      }
      atomic_inc(&dm_buffers[i]->writers);
    }
    // Get ready to write to disk
    data_block = block_get(v, sector + v->data_start, BLOCK_DATA, &tokens);

// Bhu: unlock tree
#if COARSE_LOCK
    mutex_unlock(&v->block_tree_lock);
#endif

    if (tokens)
      mintegrity_return_memory_tokens(v, tokens);

    block_mark_dirty(data_block);
    data = data_block->data;

    // Copy from bio vector to journal data buffer
    todo = v->dev_block_bytes;
    do
    {
      u8 *page;
      unsigned len;
      struct bio_vec bv = bio_iter_iovec(bio, io->iter);

      page = kmap_atomic(bv.bv_page);
      len = bv.bv_len;
      if (likely(len >= todo))
      {
        len = todo;
      }

      memcpy(data + v->dev_block_bytes - todo, page + bv.bv_offset, len);
      kunmap_atomic(page);

      bio_advance_iter(bio, &io->iter, len);
      todo -= len;
    } while (todo);

    // Hash new data, will be saved to v->io_real_digest
    r = mintegrity_buffer_hash(io, data, v->dev_block_bytes);
    if (unlikely(r))
    {
      block_release(data_block);
      goto bad;
    }
    result = io_real_digest(v, io);

    // Copy into journal
    if (v->full_journal)
    {
      memcpy(j_buffer->data + (v->dev_block_bytes * which), data,
             v->dev_block_bytes);
    }
    else
    {
      // Copy previous
      memcpy(j_buffer->data + (v->digest_size * 2 * which),
             dm_buffers[0]->data + mintegrity_hash_buffer_offset(v, sector, 0),
             v->digest_size);

      // Copy new
      memcpy(j_buffer->data + (v->digest_size * 2 * which) + v->digest_size,
             result, v->digest_size);
    }

    // Copy data hash into first level
    memcpy(dm_buffers[0]->data + mintegrity_hash_buffer_offset(v, sector, 0),
           result, v->digest_size);

    // Write things back bottom up
    for (i = 1; i < v->levels; i++)
    {
      d = dm_buffers[i - 1];
      if (atomic_dec_return(&d->writers) == 0)
      {
        // Acquire lock - prevent bad concurrent writer updates
        // if another writer enters while one has already started
        down_write(&d->lock);

        // Calculate hash for level below io_dm_buffers
        r = mintegrity_buffer_hash(io, d->data, v->dev_block_bytes);
        if (unlikely(r))
        {
          up_write(&d->lock);
          block_release(data_block);
          DMERR("failed to calculate write buffer hash for level");
          goto bad;
        }
        result = io_real_digest(v, io);

        // Copy hash into current level
        memcpy(dm_buffers[i]->data +
                   mintegrity_hash_buffer_offset(v, sector, i),
               result, v->digest_size);

        up_write(&d->lock);
      }
    }

    d = dm_buffers[v->levels - 1];
    if (atomic_dec_return(&d->writers) == 0)
    {
      down_write(&d->lock);
      // Update root merkle tree hashes
      r = mintegrity_buffer_hash(io, d->data, v->dev_block_bytes);
      if (unlikely(r < 0))
      {
        up_write(&d->lock);
        block_release(data_block);
        DMERR("failed to calculate write buffer hash for level");
        goto bad;
      }
      result = io_real_digest(v, io);
      memcpy(v->root_digest, result, v->digest_size);
      up_write(&d->lock);
    }

    block_release(data_block);
    mintegrity_add_buffer_to_journal(v, sector, dm_buffers, j_buffer, 0, tag,
                                     which);
    continue;

  bad:
    DMERR("ERROR at end of write work");
    mintegrity_add_buffer_to_journal(v, sector, dm_buffers, j_buffer, -EIO, tag,
                                     which);
    return -EIO;
  }
#if DEBUG
  pending_write--;
  if (pending_write % 4000 == 0)
    printk(KERN_ERR "Pending writes: %llu \n", pending_write);
#endif
  // Finished!
  return 0;
}

static void mintegrity_read_work(struct work_struct *w)
{
  int error;
  struct dm_mintegrity_io *io = container_of(w, struct dm_mintegrity_io, work);
  struct bio *bio = dm_bio_from_per_bio_data(io, io->v->ti->per_io_data_size);

  error = mintegrity_verify_read_io(io);

  up(&io->v->request_limit);
  bio_endio(bio);
}

#if CHECKPOINT
static void mintegrity_commit_checkpoint_work(struct work_struct *w)
{
  struct delayed_work *dwork = NULL;
  struct dm_mintegrity *v = NULL;

  checkpoint_work_counter++;

  printk(KERN_ERR "Checkpoint work scheduled %llu\n", checkpoint_work_counter);
  dwork = container_of(w, struct delayed_work, work);

  BUG_ON(!dwork);

  v = container_of(dwork, struct dm_mintegrity, delayed_work);
  BUG_ON(!v);
  mintegrity_checkpoint_journal(v);

  printk(KERN_ERR "Queueing next checkpoint work %llu\n",
         checkpoint_work_counter);
  INIT_DELAYED_WORK(&(v->delayed_work), mintegrity_commit_checkpoint_work);
  queue_delayed_work(v->delayed_workqueue, &v->delayed_work,
                     msecs_to_jiffies(3000));
}
#endif

static void mintegrity_read_end_io(struct bio *bio)
{
  struct dm_mintegrity_io *io = bio->bi_private;

  bio->bi_iter.bi_sector =
      bio->bi_iter.bi_sector -
      (io->v->data_start << (io->v->dev_block_bits - SECTOR_SHIFT));

  bio->bi_end_io = io->orig_bi_end_io;
  bio->bi_private = io->orig_bi_private;
  if (atomic_read(&bio->__bi_remaining) <= 0)
  {
    // printk(KERN_ERR "Going to trigger a bug in mintegrity_read_end_io.\n");
    // atomic_set(&bio->__bi_remaining, 1);
  }

  INIT_WORK(&(io->work), mintegrity_read_work);
  queue_work(io->v->workqueue, &io->work);
}

static void mintegrity_write_work(struct work_struct *w)
{
  int error;
  struct dm_mintegrity_io *io = container_of(w, struct dm_mintegrity_io, work);
  struct bio *bio = dm_bio_from_per_bio_data(io, io->v->ti->per_io_data_size);

  // printk(KERN_ERR "%s[%d] (%d) processing one write work\n", __func__,
  // __LINE__, smp_processor_id());
  error = mintegrity_verify_write_io(io);

  if (unlikely(bio->bi_opf & (REQ_OP_FLUSH | REQ_FUA)))
  {
    down_write(&io->v->j_lock);
    printk(KERN_ERR "We are in mintegrity_write_work. Commiting journal.\n");
    mintegrity_commit_journal(io->v, true);
    up_write(&io->v->j_lock);
  }

  up(&io->v->request_limit);
  bio_endio(bio);
}

#if FEATURE_PREFETCH
/*
 * Prefetch buffers for the specified io. The root buffer is not prefetched,
 * it is assumed that it will be cached all the time. At the lowest level,
 * up to (dm_mintegrity_prefetch_cluster) / v->dev_block_bytes is prefeteched
 * in one request
 */
static void mintegrity_prefetch_io(struct work_struct *work)
{
  int i;
  sector_t s;
  struct dm_mintegrity_prefetch_work *pw =
      container_of(work, struct dm_mintegrity_prefetch_work, work);
  struct dm_mintegrity *v = pw->v;

  for (i = v->levels - 2; i >= 0; i--)
  {
    sector_t hash_block_start;
    sector_t hash_block_end;
    mintegrity_hash_at_level(v, pw->block, i, &hash_block_start, NULL);
    mintegrity_hash_at_level(v, pw->block + pw->n_blocks - 1, i,
                             &hash_block_end, NULL);

#if COARSE_LOCK
    mutex_lock(&v->block_tree_lock);
#endif
    for (s = hash_block_start; s < hash_block_end - hash_block_start + 1; s++)
    {
      int tokens = 1;
      down_write(&v->j_lock);

      if (atomic_dec_return(&v->block_tokens) < 0)
      {
        // Couldn't get a token, everything is used up, avoid making
        // things worse
        mintegrity_return_memory_tokens(v, 1);
        up_write(&v->j_lock);
        kfree(pw);
        return;
      }
      up_write(&v->j_lock);

      block_get(v, s, BLOCK_READ | BLOCK_PREFETCH, &tokens);
      if (tokens)
        mintegrity_return_memory_tokens(v, tokens);
    }
#if COARSE_LOCK
    mutex_unlock(&v->block_tree_lock);
#endif
  }

  kfree(pw);
#if DEBUG
  pending_prefetch--;
  if (pending_prefetch % 4000 == 0)
    printk(KERN_ERR "Pending prefetch: %llu \n", pending_prefetch);
#endif
}

static void mintegrity_submit_prefetch(struct dm_mintegrity *v,
                                       struct dm_mintegrity_io *io)
{
  struct dm_mintegrity_prefetch_work *pw;

  pw = kmalloc(sizeof(struct dm_mintegrity_prefetch_work),
               GFP_NOIO | __GFP_NORETRY | __GFP_NOMEMALLOC | __GFP_NOWARN);

  if (!pw)
    return;

  INIT_WORK(&pw->work, mintegrity_prefetch_io);
  pw->v = v;
  pw->block = io->block;
  pw->n_blocks = io->n_blocks;
  queue_work(v->prefetch_workqueue, &pw->work);
#if DEBUG
  pending_prefetch++;
#endif
}
#endif

#if FEATURE_EVICTOR
#define EVICTOR_TIMEOUT 100

/* background evictor thread */
static int mintegrity_evitor(void *ptr)
{
  struct dm_mintegrity *v = ptr;

  struct mutex *list_lock;
  struct list_head *pos, *n, *list;
  struct block_device *dev;

  while (1)
  {
    bool evict_finished;
    init_completion(&v->evict_wait);
    wait_for_completion_interruptible_timeout(&v->evict_wait, EVICTOR_TIMEOUT);

    /* Exit evictor thread */
    if (kthread_should_stop())
    {
      return 0;
    }

    evict_finished = 0;

    /* First try to write out data blocks */
    list = &v->block_list_data_dirty;
    list_lock = &v->block_list_data_dirty_lock;
    dev = (v->data_dev) ? v->data_dev->bdev : v->dev->bdev;

    mutex_lock(&v->block_list_clean_lock);
    mutex_lock(list_lock);

    list_for_each_safe(pos, n, list)
    {
      struct bio *bio;
      struct data_block *d;
      int new_token;

      d = container_of(pos, struct data_block, list);

      if (atomic_read(&d->ref_count) != 0 && d->dirty)
      {
        printk(KERN_ERR
               "This shouldnt happen. The ref count of d is %d, sector %llu\n",
               atomic_read(&d->ref_count), (unsigned long long)d->sector);
        list_del(&d->list);
        INIT_LIST_HEAD(&d->list);
        continue;
      }

      list_del(&d->list);
      init_completion(&d->event);
      d->completion_initialized = true;

      list_add_tail(&d->list, &v->block_list_clean);

      d->dirty = false;

      bio = &d->bio;
      bio_init(bio, NULL, 0);
      bio->bi_iter.bi_sector = d->sector << (v->dev_block_bits - SECTOR_SHIFT);
      bio->bi_bdev = dev;

      bio->bi_opf = REQ_OP_WRITE; /* https://elixir.bootlin.com/linux/latest/source/drivers/md/bcache/btree.c#L257
                                   */

      bio->bi_max_vecs = 1;
      bio->bi_io_vec = &d->bio_vec;
      bio->bi_end_io = block_end_io;
      bio->bi_private = d;
      bio_add_page(bio, virt_to_page(d->data), v->dev_block_bytes, 0);
      submit_bio_noacct(bio);

      new_token = atomic_inc_return(&v->block_tokens);
      if ((new_token * 10) > (DM_MINTEGRITY_BLOCK_TOKENS * EVICT_H_THRLD))
      {
        evict_finished = 1;
        break;
      }
    }
    mutex_unlock(list_lock);
    mutex_unlock(&v->block_list_clean_lock);

    if (evict_finished)
      continue;

    /* Then try to write out hash blocks */
    list = &v->block_list_hash_dirty;
    list_lock = &v->block_list_hash_dirty_lock;
    dev = (v->data_dev) ? v->data_dev->bdev : v->dev->bdev;

    mutex_lock(&v->block_list_clean_hash_lock);
    mutex_lock(list_lock);
    list_for_each_safe(pos, n, list)
    {
      struct bio *bio;
      struct data_block *d;
      int new_token;

      d = container_of(pos, struct data_block, list);

      if (atomic_read(&d->ref_count) != 0 && d->dirty)
      {
        printk(KERN_ERR
               "This shouldnt happen. The ref count of d is %d, sector %llu\n",
               atomic_read(&d->ref_count), (unsigned long long)d->sector);
        list_del(&d->list);
        INIT_LIST_HEAD(&d->list);
        continue;
      }

      list_del(&d->list);
      init_completion(&d->event);
      d->completion_initialized = true;

      list_add_tail(&d->list, &v->block_list_clean_hash);

      d->dirty = false;

      bio = &d->bio;
      bio_init(bio, NULL, 0);
      bio->bi_iter.bi_sector = d->sector << (v->dev_block_bits - SECTOR_SHIFT);
      bio->bi_bdev = dev;

      bio->bi_opf = REQ_OP_WRITE;

      bio->bi_max_vecs = 1;
      bio->bi_io_vec = &d->bio_vec;
      bio->bi_end_io = block_end_io;
      bio->bi_private = d;
      bio_add_page(bio, virt_to_page(d->data), v->dev_block_bytes, 0);
      submit_bio_noacct(bio);

      new_token = atomic_inc_return(&v->block_tokens);
      if ((new_token * 10) > (DM_MINTEGRITY_BLOCK_TOKENS * EVICT_H_THRLD))
      {
        evict_finished = 1;
        break;
      }
    }
    mutex_unlock(list_lock);
    mutex_unlock(&v->block_list_clean_hash_lock);
  }
  return 0;
}
#endif

/*
 * Bio map function. It allocates dm_mintegrity_io structure and bio vector and
 * fills them. Then it issues prefetches and the I/O.
 */
// rsrc: https://xuechendi.github.io/2013/11/14/device-mapper-deep-dive
// sample mapping:
// https://gist.githubusercontent.com/gauravmmh/7523ed24b80010b45691e2fed5e0625a/raw/39f19cab478e80f534ece57a5079fe3c5b652ccd/basic_target.c
// medium sample:
// https://gauravmmh1.medium.com/writing-your-own-device-mapper-target-539689d19a89
static int mintegrity_map(struct dm_target *ti, struct bio *bio)
{
#ifdef DEBUG
  printk("dm-mintegrity map");
#endif
  struct dm_mintegrity *v;
  struct dm_mintegrity_io *io;

  v = ti->private;

  // Block device
  bio->bi_bdev = (v->data_dev ? v->data_dev->bdev : v->dev->bdev);

  // bi_sector: device address in 512 byte
  bio->bi_iter.bi_sector = mintegrity_map_sector(v, bio->bi_iter.bi_sector);

  if (((unsigned)bio->bi_iter.bi_sector | bio_sectors(bio)) &
      ((1 << (v->dev_block_bits - SECTOR_SHIFT)) - 1))
  {
    DMERR_LIMIT("unaligned io");
    return -EIO;
  }

  if (bio_end_sector(bio) >> (v->dev_block_bits - SECTOR_SHIFT) >
      v->data_blocks)
  {
    DMERR_LIMIT("io out of range");
    return -EIO;
  }

#ifdef DEBUG
  printk(KERN_CRIT "bio orientation: %s",
         bio_data_dir(bio) == WRITE ? "write" : "read");
#endif
  if (bio_data_dir(bio) == WRITE || bio_data_dir(bio) == READ)
  {
    // Common setup
    io = dm_per_bio_data(bio, ti->per_io_data_size);
    io->v = v;
    io->block = bio->bi_iter.bi_sector >> (v->dev_block_bits - SECTOR_SHIFT);
    io->n_blocks = bio->bi_iter.bi_size >> v->dev_block_bits;
    io->iter = bio->bi_iter;

#if DEBUG
    total_requests++;
    if (v->request_limit.count == 0)
    {
      printk(KERN_ERR
             "This is the last request in a while. Total requests: %llu\n",
             total_requests);
    }
#endif

    // Limit the number of requests
    down(&v->request_limit);

#if FEATURE_PREFETCH
    // Prefetch blocks
    mintegrity_submit_prefetch(v, io);
#endif

    // WRITE
    if (bio_data_dir(bio) == WRITE)
    {
      INIT_WORK(&(io->work), mintegrity_write_work);
      queue_work(io->v->workqueue, &io->work);

#if DEBUG
      pending_write++;
#endif
    }
    else
    // READ
    {
      // Check local cache for non-written out blocks
      struct data_block *b;
      int tokens = 1;
      bool all_in_memory = true;
      sector_t block_idx = 0;
      struct bio *split = NULL;
      int split_sectors = 0;
      char *data;

      // last block state
      // 0: no last block
      // 1: last block in buffer
      // 2: last block not in buffer
      int last_block = 0;

#if COARSE_LOCK
      mutex_lock(&v->block_tree_lock);
#endif

      for (block_idx = 0; block_idx < io->n_blocks; block_idx += 1)
      {
        tokens = 1;
        mintegrity_get_memory_tokens(v, tokens);

        // Get a block of data, with absolute physical disk sector
        b = block_get(v, io->block + block_idx + v->data_start,
                      BLOCK_MEMORY | BLOCK_READ | BLOCK_DATA, &tokens);

        if (tokens)
          mintegrity_return_memory_tokens(v, tokens);

        if (b)
        {
          unsigned int todo = v->dev_block_bytes;
          unsigned int copied = 0;
          struct bio_vec bv;
          struct bvec_iter iter;

          // If block not in buffer
          if (last_block == 2)
          {
            // https://elixir.bootlin.com/linux/latest/source/block/bio.c#L1494
            /*
                    http://books.gigatux.nl/mirror/kerneldevelopment/0672327201/ch13lev1sec3.html:

                    A more important usage, however, is to allow the splitting
               of bio structures. With this feature, drivers such as RAID
               (Redundant Array of Inexpensive Disks, a hard disk setup that
               allows single volumes to span multiple disks for performance and
               reliability purposes) can take a single bio structure, initially
               intended for a single device, and split it up among the multiple
               hard drives in the RAID array. All the RAID driver needs to do is
               copy the bio structure and update the bi_idx field to point to
               where the individual drive should start its operation.
            */
            split = bio_split(bio, split_sectors, GFP_NOIO, &fs_bio_set);

            // bio_end_io:
            // https://www.kernel.org/doc/htmldocs/filesystems/API-bio-endio.html

            // https://www.kernel.org/doc/htmldocs/filesystems/API-bio-chain.html:
            // https://patchwork.kernel.org/project/linux-block/patch/1452636519-32697-1-git-send-email-keith.busch@intel.com/:
            // For h/w that advertise their block storage's underlying chunk
            // size, it's a big performance win to not submit commands that
            // cross them.
            //       (target, parent)
            bio_chain(split, bio);

            // https://dri.freedesktop.org/docs/drm/core-api/kernel-api.html#c.submit_bio_noacct
            // https://lore.kernel.org/nvdimm/d8e792a2-1333-6852-6334-a681953f0bdc@suse.de/:
            // generic_make_request -> submit_bio_noacct
            // https://www.kernel.org/doc/htmldocs/kernel-api/API-generic-make-request.html
            submit_bio_noacct(split);

            split = NULL;
            split_sectors = 0;
          }

          // bio_for_each_segment: https://lwn.net/Articles/26404/
          bio_for_each_segment(bv, bio, iter)
          {
            // printk(KERN_WARNING "bv.bv_len = %d", bv.bv_len);
            // bv_len: Number of bytes in the address range
            if (bv.bv_len > todo)
            {
              printk(KERN_CRIT "Block sizes do not match. dm table states %d, "
                               "real size is %d",
                     bv.bv_len, v->dev_block_bytes);
              printk(KERN_CRIT "Redo the setup and change size for mkmint!");
              BUG_ON(bv.bv_len > todo);
            }

            // block: remove bvec_kmap_irq and bvec_kunmap_irq
            // https://patchwork.kernel.org/project/linux-block/patch/20210608160603.1535935-11-hch@lst.de/
            // https://lore.kernel.org/all/20220303111905.321089-3-hch@lst.de/
            // https://lwn.net/Articles/26175/
            // BUG:
            // https://elixir.bootlin.com/linux/latest/source/include/linux/highmem-internal.h#L249
            data = bvec_kmap_local(&bv);
            memcpy(data, b->data + v->dev_block_bytes - todo, bv.bv_len);
            flush_dcache_page(bv.bv_page);

            // removed from kernel:
            // https://listman.redhat.com/archives/dm-devel/2015-May/msg00155.html
            kunmap_local(data);

            copied += bv.bv_len;
            todo -= copied;
            if (todo == 0)
              break;
          }

          bio_advance_iter(bio, &bio->bi_iter, copied);

          block_release(b);
          last_block = 1;
        }
        // block not found
        else
        {
          /* from blk_types.h
           * The basic unit of block I/O is a sector. It is used in a number of
           * contexts in Linux (blk, bio, genhd). The size of one sector is 512
           * = 2**9 bytes. Variables of type sector_t represent an offset or
           * size that is a multiple of 512 bytes. Hence these two constants.
           *
           * #ifndef SECTOR_SHIFT
           * #define SECTOR_SHIFT 9
           * #endif
           * #ifndef SECTOR_SIZE
           * #define SECTOR_SIZE (1 << SECTOR_SHIFT)
           * #endif
           */

          split_sectors += min(1 << (v->dev_block_bits - SECTOR_SHIFT),
                               (int)bio_sectors(bio));
#ifdef DEBUG
          printk(
              KERN_DEBUG "(v->dev_block_bits - SECTOR_SHIFT) = (%d - %d) = %d",
              v->data_start, SECTOR_SHIFT, (v->dev_block_bits - SECTOR_SHIFT));
#endif

          // Send out read request
          if (all_in_memory)
          {
            /* regarding biovec:
               (https://www.kernel.org/doc/Documentation/block/biovecs.txt) In
               the new scheme of things, everything that must be mutated in
               order to partially complete a bio is segregated into struct
               bvec_iter: bi_sector, bi_size and bi_idx have been moved there;
               and instead of modifying bv_offset and bv_len, struct bvec_iter
               has bi_bvec_done, which represents the number of bytes completed
               in the current bvec.
            */
            all_in_memory = false;
            bio->bi_iter.bi_sector =
                bio->bi_iter.bi_sector +
                (v->data_start << (v->dev_block_bits - SECTOR_SHIFT));

            io->orig_bi_end_io = bio->bi_end_io;
            io->orig_bi_private = bio->bi_private;
            bio->bi_end_io = mintegrity_read_end_io;
            bio->bi_private = io;
          }

          if (split_sectors == bio_sectors(bio))
          {
            // last block, directly send down
            submit_bio_noacct(bio);
          }
          // not in buffer
          last_block = 2;
        }
      }
#if COARSE_LOCK
      mutex_unlock(&v->block_tree_lock);
#endif

      // Block in buffer
      if (all_in_memory || last_block == 1)
      {
        // Got all pages from buffer, or last block is from buffer, finalize
        // read request
        up(&v->request_limit);
        bio_endio(bio);
      }
#ifdef DEBUG
      printk(KERN_CRIT "End map read...\n");
#endif
    }
  }

  if (bio_data_dir(bio) & REQ_SYNC)
  {
    mintegrity_commit_journal(v, true);
  }

  return DM_MAPIO_SUBMITTED;
}

/*
 * Status: V (valid) or C (corruption found)
 */
static void mintegrity_status(struct dm_target *ti, status_type_t type,
                              unsigned status_flags, char *result,
                              unsigned maxlen)
{
  struct dm_mintegrity *v = ti->private;
  unsigned sz = 0;
  unsigned x;

  switch (type)
  {
  case STATUSTYPE_INFO:
    DMEMIT("%c", v->hash_failed ? 'C' : 'V');
    break;

  case STATUSTYPE_TABLE:
    DMEMIT("%s %u %llu %llu %s ", v->dev->name, 1 << v->dev_block_bits,
           (unsigned long long)v->data_blocks,
           (unsigned long long)v->hash_start, v->alg_name);

    for (x = 0; x < v->digest_size; x++)
    {
      DMEMIT("%02x", v->root_digest[x]);
    }

    DMEMIT(" ");
    if (!v->salt_size)
    {
      DMEMIT("-");
    }
    else
    {
      for (x = 0; x < v->salt_size; x++)
      {
        DMEMIT("%02x", v->salt[x]);
      }
    }
    break;
  }
}

static int mintegrity_prepare_ioctl(struct dm_target *ti,
                                    struct block_device **bdev)
{
  struct dm_mintegrity *v = ti->private;

  if (!v->data_dev->bdev)
  {
    printk(KERN_ERR "data_dev->bdev is not defined. Exiting");
    return 0;
  }

  *bdev = v->data_dev->bdev;

  if (v->data_start || ti->len != bdev_nr_sectors(v->data_dev->bdev))
    return 1;
  return 0;
}

static int mintegrity_iterate_devices(struct dm_target *ti,
                                      iterate_devices_callout_fn fn,
                                      void *data)
{
  struct dm_mintegrity *v = ti->private;

  // TODO: iterate two disk combination?
  if (v->data_dev)
  {
    return fn(ti, v->data_dev, v->data_start_shift, ti->len, data);
  }
  else
  {
    return fn(ti, v->dev, v->data_start_shift, ti->len, data);
  }
}

static void mintegrity_io_hints(struct dm_target *ti,
                                struct queue_limits *limits)
{
  struct dm_mintegrity *v = ti->private;

  // TODO: multi block?
  if (limits->logical_block_size < 1 << v->dev_block_bits)
    limits->logical_block_size = 1 << v->dev_block_bits;

  if (limits->physical_block_size < 1 << v->dev_block_bits)
    limits->physical_block_size = 1 << v->dev_block_bits;

  blk_limits_io_min(limits, limits->logical_block_size);
}

static void mintegrity_dtr(struct dm_target *ti)
{
  struct dm_mintegrity *v = ti->private;

  printk("dm-mintegrity destructor");
  if (v->workqueue)
  {
    flush_workqueue(v->workqueue);
    destroy_workqueue(v->workqueue);
  }

  if (v->prefetch_workqueue)
  {
    flush_workqueue(v->prefetch_workqueue);
    destroy_workqueue(v->prefetch_workqueue);
  }

#if FEATURE_EVICTOR
  /* Stop evict thread */
  kthread_stop(v->evict_task);
  complete_all(&v->evict_wait);
#endif

#if CHECKPOINT
  cancel_delayed_work(&v->delayed_work);

  if (v->delayed_workqueue)
  {
    flush_workqueue(v->delayed_workqueue);
    destroy_workqueue(v->delayed_workqueue);
  }
#endif

  if (v->created)
  {
    mintegrity_unmount_journal(v);
  }

  {
    struct data_block *d;
    struct list_head *pos, *n;

    list_for_each_safe(pos, n, &v->block_list_clean)
    {
      d = container_of(pos, struct data_block, list);
      free_page((unsigned long)d->data);
      kfree(d);
    }

    list_for_each_safe(pos, n, &v->block_list_clean_hash)
    {
      d = container_of(pos, struct data_block, list);
      free_page((unsigned long)d->data);
      kfree(d);
    }

    list_for_each_safe(pos, n, &v->block_list_prefetch)
    {
      d = container_of(pos, struct data_block, list);
      free_page((unsigned long)d->data);
      kfree(d);
    }
  }

  if (v->journal_page_mempool)
  {
    mempool_destroy(v->journal_page_mempool);
  }

  if (v->journal_block_mempool)
  {
    mempool_destroy(v->journal_block_mempool);
  }

  kfree(v->zero_digest);
  kfree(v->secret);
  kfree(v->hmac_digest);
  kfree(v->hmac_desc);

  if (v->hmac_tfm)
  {
    crypto_free_shash(v->hmac_tfm);
  }

  kfree(v->hmac_alg_name);
  kfree(v->salt);
  kfree(v->root_digest);

  if (v->tfm)
  {
    crypto_free_shash(v->tfm);
  }

  kfree(v->alg_name);

  if (v->data_dev)
  {
    dm_put_device(ti, v->data_dev);
  }

  if (v->dev)
  {
    dm_put_device(ti, v->dev);
  }

  kfree(v);
}

/*
 * TODO: nice parser, IMPORTANT
 * Target parameters:
 *  <hash device>
 *	<data device>
 *	<block size>
 *  <number of hash blocks>
 *  <number of journal blocks>
 *  <number of data blocks>
 *  <data hash type>
 *  <root digest>
 *  <salt>
 *  <hmac hash type>
 *  <hmac secret>
 *  lazy|nolazy
 *  full|sector
 *
 *	<salt>		Hex string or "-" if no salt.
 */
static int mintegrity_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
  struct dm_mintegrity *v;
  int r, i, a;
  unsigned num;
  unsigned long long num_ll;
  sector_t hash_position;
  char dummy;

  // Allocate struct dm_mintegrity for this device mapper instance
  v = kzalloc(sizeof(struct dm_mintegrity), GFP_KERNEL);
  if (!v)
  {
    ti->error = "Cannot allocate mintegrity structure";
    return -ENOMEM;
  }
  ti->private = v;
  v->ti = ti;

  // Check that dmsetup table is writeable
  // TODO: read only mode
  if (!(dm_table_get_mode(ti->table) & FMODE_WRITE))
  {
    ti->error = "Device must be writeable!";
    r = -EINVAL;
    goto bad;
  }

  for (a = 0; a < argc; a++)
    printk(KERN_CRIT "argv[%d] = %s\n", a, argv[a]);

  // Check argument count
  if (argc != 13)
  {
    ti->error = "Invalid argument count: 14 arguments required";
    r = -EINVAL;
    goto bad;
  }

  // argv[0] <hash device>
  r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &v->dev);
  if (r)
  {
    ti->error = "Device lookup failed";
    goto bad;
  }

  // argv[1] <data device>
  if (strcmp(argv[0], argv[1]))
  {
    v->two_disks = true;
    r = dm_get_device(ti, argv[1], dm_table_get_mode(ti->table), &v->data_dev);
    if (r)
    {
      ti->error = "Device lookup failed";
      goto bad;
    }
  }
  // fixing the nulllptr bug.
  // using one device does not seem to be supported very good, since there are
  // no checks at all..
  else
  {
    printk(KERN_WARNING "Entering the world of pain (undefined behaviour)");
    v->data_dev = v->dev;
  }

  // argv[2] <block size>
  if (sscanf(argv[2], "%u%c", &num, &dummy) != 1 || !num || (num & (num - 1)) ||
      num > PAGE_SIZE || num < bdev_logical_block_size(v->dev->bdev))
  {
    ti->error = "Invalid data device block size";
    r = -EINVAL;
    goto bad;
  }
  v->dev_block_bits = __ffs(num);
  v->dev_block_bytes = (1 << v->dev_block_bits);

  // argv[3] <number of hash blocks>
  if (sscanf(argv[3], "%llu%c", &num_ll, &dummy) != 1)
  {
    ti->error = "Invalid number of hash blocks";
    r = -EINVAL;
    goto bad;
  }
  v->hash_blocks = num_ll;
  // 1, because skip superblock
  v->hash_start = 1;

  // argv[4] <number of journal blocks>
  if (sscanf(argv[4], "%llu%c", &num_ll, &dummy) != 1)
  {
    ti->error = "Invalid number of journal blocks";
    r = -EINVAL;
    goto bad;
  }
  v->journal_blocks = num_ll;
  v->journal_start = v->hash_start + v->hash_blocks;

  // argv[5] <number of data blocks>
  if (sscanf(argv[5], "%llu%c", &num_ll, &dummy) != 1 ||
      (sector_t)(num_ll << (v->dev_block_bits - SECTOR_SHIFT)) >>
              (v->dev_block_bits - SECTOR_SHIFT) !=
          num_ll)
  {
    ti->error = "Invalid data blocks";
    r = -EINVAL;
    goto bad;
  }
  v->data_blocks = num_ll;
  v->data_start = v->two_disks ? 0 : v->journal_start + v->journal_blocks;

  // Check that device is long enough
  if (ti->len > (v->data_blocks << (v->dev_block_bits - SECTOR_SHIFT)))
  {
    ti->error = "Data device is too small";
    r = -EINVAL;
    goto bad;
  }

  // argv[6] <data hash type>
  v->alg_name = kstrdup(argv[6], GFP_KERNEL);
  if (!v->alg_name)
  {
    ti->error = "Cannot allocate algorithm name";
    r = -ENOMEM;
    goto bad;
  }

  // Allocate a crypto hash object based on algorithm name
  v->tfm = crypto_alloc_shash(v->alg_name, 0, 0);
  if (IS_ERR(v->tfm))
  {
    ti->error = "Cannot initialize hash function";
    r = PTR_ERR(v->tfm);
    v->tfm = NULL;
    goto bad;
  }

  // Check that a disk block can hold at least 2 hashes
  v->digest_size = crypto_shash_digestsize(v->tfm);
  if ((1 << v->dev_block_bits) < v->digest_size * 2)
  {
    ti->error = "Digest size too big";
    r = -EINVAL;
    goto bad;
  }
  v->shash_descsize = sizeof(struct shash_desc) + crypto_shash_descsize(v->tfm);

  // Allocate space to keep track of root hash
  v->root_digest = kzalloc(v->digest_size, GFP_KERNEL);
  if (!v->root_digest)
  {
    ti->error = "Cannot allocate root digest";
    r = -ENOMEM;
    goto bad;
  }

  // argv[7] <root digest>
  if (strlen(argv[7]) != v->digest_size * 2 ||
      hex2bin(v->root_digest, argv[7], v->digest_size))
  {
    ti->error = "Invalid root digest";
    r = -EINVAL;
    goto bad;
  }

  // argv[8] <salt>
  if (strcmp(argv[8], "-"))
  { // no salt if "-"
    v->salt_size = strlen(argv[8]) / 2;
    v->salt = kzalloc(v->salt_size, GFP_KERNEL);
    if (!v->salt)
    {
      ti->error = "Cannot allocate salt";
      r = -ENOMEM;
      goto bad;
    }
    if (strlen(argv[8]) != v->salt_size * 2 ||
        hex2bin(v->salt, argv[8], v->salt_size))
    {
      ti->error = "Invalid salt";
      r = -EINVAL;
      goto bad;
    }
  }

  // argv[9] <hmac hash type>
  v->hmac_alg_name = kstrdup(argv[9], GFP_KERNEL);
  if (!v->hmac_alg_name)
  {
    ti->error = "Cannot allocate algorithm name";
    r = -ENOMEM;
    goto bad;
  }

  // Allocate a crypto hash object based on algorithm name
  v->hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
  if (IS_ERR(v->hmac_tfm))
  {
    ti->error = "Cannot initialize hash function";
    r = PTR_ERR(v->hmac_tfm);
    v->hmac_tfm = NULL;
    goto bad;
  }
  v->hmac_digest_size = crypto_shash_digestsize(v->hmac_tfm);

  v->hmac_desc =
      kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(v->hmac_tfm),
              GFP_KERNEL);
  if (!v->hmac_desc)
  {
    ti->error = "Cannot allocate mintegrity structure";
    return -ENOMEM;
  }

  v->hmac_digest = kzalloc(v->hmac_digest_size, GFP_KERNEL);
  if (!v->hmac_digest)
  {
    ti->error = "Cannot allocate mintegrity structure";
    return -ENOMEM;
  }

  v->hmac_desc->tfm = v->hmac_tfm;
  // v->hmac_desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

  // argv[10] <hmac secret>
  v->secret_size = strlen(argv[10]) / 2;
  v->secret = kzalloc(v->secret_size, GFP_KERNEL);
  if (!v->secret)
  {
    ti->error = "Cannot allocate secret";
    r = -ENOMEM;
    goto bad;
  }
  if (strlen(argv[10]) != v->secret_size * 2 ||
      hex2bin(v->secret, argv[10], v->secret_size))
  {
    ti->error = "Invalid secret";
    r = -EINVAL;
    goto bad;
  }

  // argv[11] lazy|nolazy
  // Allocate space to keep track of a zero hash block
  if (!strcmp(argv[11], "lazy"))
  {
    struct shash_desc *desc;
    char c = 0;
    v->zero_digest = kzalloc(v->digest_size, GFP_KERNEL);
    if (!v->zero_digest)
    {
      ti->error = "Cannot allocate zero digest";
      r = -ENOMEM;
      goto bad;
    }
    // Pre-compute zero hash
    desc = kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(v->tfm),
                   GFP_KERNEL);
    if (!desc)
    {
      ti->error = "Cannot allocate zero shash_desc";
      r = -ENOMEM;
      goto bad;
    }
    desc->tfm = v->tfm;
    // = CRYPTO_TFM_REQ_MAY_SLEEP;
    r = crypto_shash_init(desc);
    if (r < 0)
    {
      kfree(desc);
      ti->error = "crypto_shash_init zero failed";
      r = -EINVAL;
      goto bad;
    }
    r = crypto_shash_update(desc, v->salt, v->salt_size);
    if (r < 0)
    {
      kfree(desc);
      ti->error = "crypto_shash_update zero failed";
      r = -EINVAL;
      goto bad;
    }
    for (i = 0; i < v->dev_block_bytes; i++)
    {
      r = crypto_shash_update(desc, &c, 1);
      if (r < 0)
      {
        kfree(desc);
        ti->error = "crypto_shash_update zero failed";
        r = -EINVAL;
        goto bad;
      }
    }
    r = crypto_shash_final(desc, v->zero_digest);
    if (r < 0)
    {
      kfree(desc);
      ti->error = "crypto_shash_final zero failed";
      r = -EINVAL;
      goto bad;
    }
    kfree(desc);
  }
  else if (strcmp(argv[11], "nolazy"))
  {
    ti->error = "Invalid lazy|nolazy argument";
    r = -EINVAL;
    goto bad;
  }

  // argv[12] lazy|nolazy
  if (!strcmp(argv[12], "full"))
  {
    v->full_journal = true;
  }
  else if (strcmp(argv[12], "sector"))
  {
    ti->error = "Invalid optional argument";
    r = -EINVAL;
    goto bad;
  }
  else
  {
    v->full_journal = false;
  }

  // End of parsing, begin of actual init
  // Compute start of each hash level
  v->hash_per_block_bits = __fls((1 << v->dev_block_bits) / v->digest_size);
  v->levels = 0;
  if (v->data_blocks)
  {
    while (v->hash_per_block_bits * v->levels < 64 &&
           (unsigned long long)(v->data_blocks - 1) >>
               (v->hash_per_block_bits * v->levels))
    {
      v->levels++;
    }
  }

  if (v->levels > DM_MINTEGRITY_MAX_LEVELS)
  {
    ti->error = "Too many tree levels";
    r = -E2BIG;
    goto bad;
  }

  hash_position = v->hash_start;
  for (i = v->levels - 1; i >= 0; i--)
  {
    sector_t s = (v->data_blocks +
                  ((sector_t)1 << ((i + 1) * v->hash_per_block_bits)) - 1) >>
                 ((i + 1) * v->hash_per_block_bits);
    v->hash_level_block[i] = hash_position;

    if (hash_position + s < hash_position)
    {
      ti->error = "Hash device offset overflow";
      r = -E2BIG;
      goto bad;
    }
    hash_position += s;
  }

  /* Initialize lock for IO operations */
  mutex_init(&v->block_tree_lock);
  mutex_init(&v->block_list_clean_lock);
  mutex_init(&v->block_list_clean_hash_lock);
  mutex_init(&v->block_list_prefetch_lock);
  mutex_init(&v->block_list_hash_dirty_lock);
  mutex_init(&v->block_list_data_dirty_lock);

#if USE_RADIX
  INIT_RADIX_TREE(&v->block_tree_root, GFP_ATOMIC | GFP_KERNEL);
#else
  v->block_tree_root = RB_ROOT;
#endif

  INIT_LIST_HEAD(&v->block_list_clean);
  INIT_LIST_HEAD(&v->block_list_clean_hash);
  INIT_LIST_HEAD(&v->block_list_prefetch);
  INIT_LIST_HEAD(&v->block_list_hash_dirty);
  INIT_LIST_HEAD(&v->block_list_data_dirty);

#if DEBUG
  search_counter = 0;
  search_hash_counter = 0;
  search_data_counter = 0;
  search_hash_missing_counter = 0;
  search_data_missing_counter = 0;
  search_found_counter = 0;
  tree_insert_counter = 0;
  clean_counter = 0;
  data_dirty_counter = 0;
  hash_dirty_counter = 0;
  bio_add_page_counter = 0;
  block_get_counter = 0;
  tree_delete_counter = 0;
  compute_hash_counter = 0;
  compute_hmac_counter = 0;
  journal_release_counter = 0;
  journal_write_complete_counter = 0;
  journal_commit_counter = 0;
  journal_checkpoint_counter = 0;
  verify_level_counter = 0;
  prefetch_counter = 0;
  tree_delete_empty_counter = 0;
  tree_delete_hash_counter = 0;
  tree_delete_data_counter = 0;
  tree_delete_journal_counter = 0;
  bio_add_page_read_counter = 0;
  bio_add_page_write_counter = 0;
  tree_insert_empty_counter = 0;
  tree_insert_hash_counter = 0;
  tree_insert_data_counter = 0;
  tree_insert_journal_counter = 0;
  total_tree_nodes = 0;
  hash_reuse = 0;
  prefetch_reuse = 0;
  prefetch_counter = 0;
  prefetch_useful = 0;
  wait_completion_counter = 0;
  journal_full = 0;
  total_requests = 0;
  pending_write = 0;
  pending_prefetch = 0;
#endif

  checkpoint_work_counter = 0;
  token_counter = 0;
  wait_counter = 0;

  init_rwsem(&(v->j_lock));
  sema_init(&v->request_limit, DM_MINTEGRITY_DEFAULT_REQUEST_LIMIT);

  atomic_set(&v->block_tokens, DM_MINTEGRITY_BLOCK_TOKENS);

  for (i = 0; i < atomic_read(&v->block_tokens); i++)
  {
    // Replace with kmem_cache
    struct data_block *d =
        (struct data_block *)kzalloc(sizeof(struct data_block), GFP_KERNEL);

    if (!d)
    {
      ti->error = "Failed to allocate journal page buffer";
      r = -ENOMEM;
      goto bad;
    }

    d->data = (uint8_t *)__get_free_page(GFP_KERNEL);
    if (!d->data)
    {
      kfree(d);
      ti->error = "Failed to allocate journal page buffer";
      r = -ENOMEM;
      goto bad;
    }

    list_add_tail(&d->list, &v->block_list_clean);
    init_completion(&d->event);
    complete_all(&d->event);
    d->completion_initialized = false;
    d->is_prefetch = false;
  }

  // Read queue
  /* WQ_UNBOUND greatly improves performance when running on ramdisk */
  v->workqueue = alloc_workqueue("kmintegrityd",
                                 WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND,
                                 num_online_cpus());
  if (!v->workqueue)
  {
    ti->error = "Cannot allocate read workqueue";
    r = -ENOMEM;
    goto bad;
  }

  v->prefetch_workqueue = alloc_workqueue(
      "kmintegrityd-prefetch", WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND,
      num_online_cpus());
  if (!v->prefetch_workqueue)
  {
    ti->error = "Cannot allocate prefetch workqueue";
    r = -ENOMEM;
    goto bad;
  }

#if CHECKPOINT
  v->delayed_workqueue = alloc_workqueue(
      "kmintegrityd-write",
      WQ_CPU_INTENSIVE | WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
  if (!v->delayed_workqueue)
  {
    ti->error = "Cannot allocate write workqueue";
    r = -ENOMEM;
    goto bad;
  }

  INIT_DELAYED_WORK(&(v->delayed_work), mintegrity_commit_checkpoint_work);
  queue_delayed_work(v->delayed_workqueue, &v->delayed_work,
                     msecs_to_jiffies(3000));
#endif

  ti->per_io_data_size = roundup(
      sizeof(struct dm_mintegrity_io) + v->shash_descsize + v->digest_size * 2 +
          (v->levels + 1) * sizeof(struct data_block *),
      __alignof__(struct dm_mintegrity_io));
  r = mintegrity_recover_journal(v);

  if (r < 0)
  {
    ti->error = "Could not recover journal";
    r = -EIO;
    goto bad;
  }

  v->created = 1;
  barrier();

#if FEATURE_EVICTOR
  v->evict_task = kthread_run(mintegrity_evitor, v, "dmm_evictor-%p", v);
#endif

#if DEBUG
  printk(KERN_CRIT "dm-mintegrity init:\n"
                   "\thash_start = %lu\n"
                   "\tjournal_start = %lu\n"
                   "\tdata_start = %lu\n"
                   "\tdata_start_shift = %lu\n"
                   "\thash_blocks = %lu\n"
                   "\tjournal_blocks = %lu\n"
                   "\tdata_blocks = %lu\n"
                   "\tdev_block_bits = %u\n"
                   "\thash_per_block_bits = %u\n"
                   "\tdev_block_bytes = %u\n"
                   "\tlevels = %u\n",
         v->hash_start, v->journal_start, v->data_start, v->data_start_shift,
         v->hash_blocks, v->journal_blocks, v->data_blocks, v->dev_block_bits,
         v->hash_per_block_bits, v->dev_block_bytes, v->levels);
  for (i = v->levels - 1; i >= 0; i--)
    printk(KERN_DEBUG "\tlevel[%d] = %lu\n", i, v->hash_level_block[i]);
#endif
  return 0;

bad:
  mintegrity_dtr(ti);
  return r;
}

// https://elixir.bootlin.com/linux/v5.17-rc8/source/drivers/md/dm-linear.c#L29
// https://elixir.bootlin.com/linux/v3.19.8/source/include/linux/device-mapper.h#L77
// https://lore.kernel.org/dm-devel/1444911052-9423-5-git-send-email-hch@lst.de/
// https://lore.kernel.org/dm-devel/1439363241-31772-9-git-send-email-mlin@kernel.org/:
// kill merge_bvec_fn -> */
/* https://android.googlesource.com/kernel/common/+/refs/heads/android-4.19-q/drivers/md/dm-linear.c
 */
static struct target_type mintegrity_target = {
    .name = "dmx",
    .version = {2, 0, 0},
    .module = THIS_MODULE,
    .ctr = mintegrity_ctr,
    .dtr = mintegrity_dtr,
    .map = mintegrity_map,
    .status = mintegrity_status,
    .prepare_ioctl = mintegrity_prepare_ioctl,
    .iterate_devices = mintegrity_iterate_devices,
    .io_hints = mintegrity_io_hints,
};

static int __init dm_mintegrity_init(void)
{
  int r = dm_register_target(&mintegrity_target);
  if (r)
  {
    DMERR("register failed %d", r);
  }

#ifdef RUST
  printk(KERN_ALERT "Rust is enabled and will be called");
#endif
  return r;
}

static void __exit dm_mintegrity_exit(void)
{
  dm_unregister_target(&mintegrity_target);
}

module_init(dm_mintegrity_init);
module_exit(dm_mintegrity_exit);

MODULE_AUTHOR("Jan Kasiak <j.kasiak@gmail.com>");
MODULE_AUTHOR("Mikulas Patocka <mpatocka@redhat.com>");
MODULE_AUTHOR("Mandeep Baines <msb@chromium.org>");
MODULE_AUTHOR("Will Drewry <wad@chromium.org>");
MODULE_AUTHOR("Leon Gross <leon.gross@rub.de> <lg@edgeless.systems>");
MODULE_DESCRIPTION(
    DM_NAME
    "Target for transparent RW disk integrity checking. Dependency: dm_mod");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: dm_mod");

// load dm_mod via dmsetup
// sudo dmsetup create test-linear --table '0 100 linear /dev/loop0 0'
