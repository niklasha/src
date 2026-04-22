/*	$OpenBSD$	*/

#ifndef RESIZE_FFS_H
#define RESIZE_FFS_H

#include <stddef.h>
#include <stdint.h>

enum resize_owner_kind {
	RESIZE_OWNER_INODE_DB,
	RESIZE_OWNER_INODE_IB,
	RESIZE_OWNER_INDIRECT_SLOT,
	RESIZE_OWNER_CG_META
};

struct resize_owner_ref {
	enum resize_owner_kind kind;
	uint64_t owner_ino;
	int32_t lbn_or_level;
	uint64_t owner_block_fsb;
	uint32_t slot_index;
};

#define RESIZE_MOVE_F_COPIED		0x00000001U
#define RESIZE_MOVE_F_REPOINTED	0x00000002U
#define RESIZE_MOVE_F_FREED		0x00000004U

enum resize_mutation_op {
	RESIZE_MUT_COPY = 1,
	RESIZE_MUT_REPOINT = 2,
	RESIZE_MUT_FREE = 3,
	RESIZE_MUT_SB_SIZE = 4,
	RESIZE_MUT_INODE_REMAP_MAP = 5,
	RESIZE_MUT_INODE_REMAP_EXEC = 6,
	RESIZE_MUT_SHIFT_CHUNK = 7
};

struct resize_move {
	uint64_t old_fsb;
	uint64_t new_fsb;
	uint32_t bytes;
	uint32_t flags;
	uint64_t owner_abs_offset;
	uint32_t owner_width;
	struct resize_owner_ref owner;
};

struct resize_backend_ops {
	int (*read_block)(void *, uint64_t, void *, size_t);
	int (*write_block)(void *, uint64_t, const void *, size_t);
	int (*sync_target)(void *);

	int (*journal_intent)(void *, enum resize_mutation_op,
	    const struct resize_move *);
	int (*journal_applied)(void *, enum resize_mutation_op,
	    const struct resize_move *);
	int (*sync_journal)(void *);

	int (*owner_get)(void *, const struct resize_owner_ref *, uint64_t *);
	int (*owner_set)(void *, const struct resize_owner_ref *, uint64_t);

	int (*alloc_is_free)(void *, uint64_t, int *);
	int (*alloc_mark_allocated)(void *, uint64_t);
	int (*alloc_mark_free)(void *, uint64_t);
};

struct resize_ctx {
	void *cookie;
	const struct resize_backend_ops *ops;
	uint32_t fs_fsize;
};

int	resize_check_move_invariant(struct resize_ctx *, struct resize_move *);
int	resize_copy_stage(struct resize_ctx *, struct resize_move *);
int	resize_repoint_stage(struct resize_ctx *, struct resize_move *);
int	resize_free_stage(struct resize_ctx *, struct resize_move *);

#endif /* RESIZE_FFS_H */
