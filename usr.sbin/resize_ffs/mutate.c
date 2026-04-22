/*	$OpenBSD$	*/

#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "resize_ffs.h"

static int
resize_validate_ctx(struct resize_ctx *ctx)
{
	if (ctx == NULL || ctx->ops == NULL)
		return (EINVAL);
	if (ctx->cookie == NULL)
		return (EINVAL);
	if (ctx->ops->read_block == NULL || ctx->ops->write_block == NULL)
		return (EINVAL);
	if (ctx->ops->sync_target == NULL)
		return (EINVAL);
	if (ctx->ops->journal_intent == NULL || ctx->ops->journal_applied == NULL)
		return (EINVAL);
	if (ctx->ops->sync_journal == NULL)
		return (EINVAL);
	if (ctx->ops->owner_get == NULL || ctx->ops->owner_set == NULL)
		return (EINVAL);
	if (ctx->ops->alloc_is_free == NULL)
		return (EINVAL);
	if (ctx->ops->alloc_mark_allocated == NULL)
		return (EINVAL);
	if (ctx->ops->alloc_mark_free == NULL)
		return (EINVAL);
	if (ctx->fs_fsize == 0)
		return (EINVAL);
	return (0);
}

static int
resize_check_flag_order(uint32_t flags)
{
	if ((flags & RESIZE_MOVE_F_FREED) != 0 &&
	    (flags & RESIZE_MOVE_F_REPOINTED) == 0)
		return (EINVAL);
	if ((flags & RESIZE_MOVE_F_REPOINTED) != 0 &&
	    (flags & RESIZE_MOVE_F_COPIED) == 0)
		return (EINVAL);
	return (0);
}

static int
resize_move_nfrags(struct resize_ctx *ctx, const struct resize_move *move,
    uint64_t *nfragsp)
{
	uint64_t nfrags;

	if (move->bytes == 0)
		return (EINVAL);
	if (move->bytes % ctx->fs_fsize != 0)
		return (EINVAL);
	nfrags = (uint64_t)move->bytes / (uint64_t)ctx->fs_fsize;
	if (nfrags == 0)
		return (EINVAL);
	*nfragsp = nfrags;
	return (0);
}

static int
resize_alloc_run_is_free(struct resize_ctx *ctx, uint64_t start_fsb,
    uint64_t nfrags, int *is_free)
{
	uint64_t i, fsb;
	int bit_free;
	int error;

	*is_free = 1;
	for (i = 0; i < nfrags; i++) {
		fsb = start_fsb + i;
		error = ctx->ops->alloc_is_free(ctx->cookie, fsb, &bit_free);
		if (error != 0)
			return (error);
		if (!bit_free) {
			*is_free = 0;
			return (0);
		}
	}
	return (0);
}

static int
resize_alloc_run_mark(struct resize_ctx *ctx, uint64_t start_fsb,
    uint64_t nfrags, int allocated)
{
	uint64_t i, fsb;
	int error;

	for (i = 0; i < nfrags; i++) {
		fsb = start_fsb + i;
		if (allocated)
			error = ctx->ops->alloc_mark_allocated(ctx->cookie, fsb);
		else
			error = ctx->ops->alloc_mark_free(ctx->cookie, fsb);
		if (error != 0)
			return (error);
	}
	return (0);
}

int
resize_check_move_invariant(struct resize_ctx *ctx, struct resize_move *move)
{
	uint64_t owner_fsb;
	uint64_t nfrags;
	uint64_t old_end, new_end;
	int old_is_free, new_is_free;
	int error;

	if ((error = resize_validate_ctx(ctx)) != 0)
		return (error);
	if (move == NULL)
		return (EINVAL);
	error = resize_move_nfrags(ctx, move, &nfrags);
	if (error != 0)
		return (error);
	if (move->old_fsb == move->new_fsb)
		return (EINVAL);
	if ((error = resize_check_flag_order(move->flags)) != 0)
		return (error);
	if (move->old_fsb > UINT64_MAX - nfrags)
		return (EOVERFLOW);
	if (move->new_fsb > UINT64_MAX - nfrags)
		return (EOVERFLOW);
	old_end = move->old_fsb + nfrags;
	new_end = move->new_fsb + nfrags;
	if ((move->old_fsb < move->new_fsb && old_end > move->new_fsb) ||
	    (move->new_fsb < move->old_fsb && new_end > move->old_fsb))
		return (EINVAL);

	error = ctx->ops->owner_get(ctx->cookie, &move->owner, &owner_fsb);
	if (error != 0)
		return (error);

	if ((move->flags & RESIZE_MOVE_F_REPOINTED) != 0) {
		if (owner_fsb != move->new_fsb)
			return (EINVAL);
	} else {
		if (owner_fsb != move->old_fsb)
			return (EINVAL);
	}

	error = resize_alloc_run_is_free(ctx, move->old_fsb, nfrags,
	    &old_is_free);
	if (error != 0)
		return (error);
	error = resize_alloc_run_is_free(ctx, move->new_fsb, nfrags,
	    &new_is_free);
	if (error != 0)
		return (error);

	if ((move->flags & RESIZE_MOVE_F_FREED) != 0) {
		if (!old_is_free)
			return (EINVAL);
	} else {
		if (old_is_free)
			return (EINVAL);
	}

	if ((move->flags & RESIZE_MOVE_F_COPIED) != 0) {
		if (new_is_free)
			return (EINVAL);
	} else {
		if (!new_is_free)
			return (EINVAL);
	}

	return (0);
}

int
resize_copy_stage(struct resize_ctx *ctx, struct resize_move *move)
{
	unsigned char *buf;
	uint64_t nfrags;
	int old_is_free, new_is_free;
	int error;

	error = resize_check_move_invariant(ctx, move);
	if (error != 0)
		return (error);
	if ((move->flags & RESIZE_MOVE_F_COPIED) != 0)
		return (EINVAL);
	if ((move->flags & RESIZE_MOVE_F_REPOINTED) != 0)
		return (EINVAL);
	if ((move->flags & RESIZE_MOVE_F_FREED) != 0)
		return (EINVAL);
	error = resize_move_nfrags(ctx, move, &nfrags);
	if (error != 0)
		return (error);

	error = resize_alloc_run_is_free(ctx, move->old_fsb, nfrags,
	    &old_is_free);
	if (error != 0)
		return (error);
	error = resize_alloc_run_is_free(ctx, move->new_fsb, nfrags,
	    &new_is_free);
	if (error != 0)
		return (error);
	if (old_is_free || !new_is_free)
		return (EINVAL);

	buf = malloc(move->bytes);
	if (buf == NULL)
		return (ENOMEM);

	/*
	 * Intent reaches stable storage before target mutation so replay can
	 * reason about partial progress after a crash.
	 */
	error = ctx->ops->journal_intent(ctx->cookie, RESIZE_MUT_COPY, move);
	if (error != 0)
		goto out;
	error = ctx->ops->sync_journal(ctx->cookie);
	if (error != 0)
		goto out;

	error = ctx->ops->read_block(ctx->cookie, move->old_fsb, buf,
	    move->bytes);
	if (error != 0)
		goto out;
	error = ctx->ops->write_block(ctx->cookie, move->new_fsb, buf,
	    move->bytes);
	if (error != 0)
		goto out;
	error = ctx->ops->sync_target(ctx->cookie);
	if (error != 0)
		goto out;

	error = resize_alloc_run_mark(ctx, move->new_fsb, nfrags, 1);
	if (error != 0)
		goto out;

	/* Applied is logged only after target bytes are durable. */
	error = ctx->ops->journal_applied(ctx->cookie, RESIZE_MUT_COPY, move);
	if (error != 0)
		goto out;
	error = ctx->ops->sync_journal(ctx->cookie);
	if (error != 0)
		goto out;

	move->flags |= RESIZE_MOVE_F_COPIED;
	error = resize_check_move_invariant(ctx, move);
out:
	free(buf);
	return (error);
}

int
resize_repoint_stage(struct resize_ctx *ctx, struct resize_move *move)
{
	uint64_t owner_fsb;
	int error;

	error = resize_check_move_invariant(ctx, move);
	if (error != 0)
		return (error);
	if ((move->flags & RESIZE_MOVE_F_COPIED) == 0)
		return (EINVAL);
	if ((move->flags & RESIZE_MOVE_F_REPOINTED) != 0)
		return (EINVAL);
	if ((move->flags & RESIZE_MOVE_F_FREED) != 0)
		return (EINVAL);

	error = ctx->ops->owner_get(ctx->cookie, &move->owner, &owner_fsb);
	if (error != 0)
		return (error);
	if (owner_fsb != move->old_fsb)
		return (EINVAL);

	/* Repoint is replayable because the intent is durable first. */
	error = ctx->ops->journal_intent(ctx->cookie, RESIZE_MUT_REPOINT,
	    move);
	if (error != 0)
		return (error);
	error = ctx->ops->sync_journal(ctx->cookie);
	if (error != 0)
		return (error);

	error = ctx->ops->owner_set(ctx->cookie, &move->owner,
	    move->new_fsb);
	if (error != 0)
		return (error);
	error = ctx->ops->sync_target(ctx->cookie);
	if (error != 0)
		return (error);

	/* Applied confirms durable ownership transfer old_fsb -> new_fsb. */
	error = ctx->ops->journal_applied(ctx->cookie, RESIZE_MUT_REPOINT,
	    move);
	if (error != 0)
		return (error);
	error = ctx->ops->sync_journal(ctx->cookie);
	if (error != 0)
		return (error);

	move->flags |= RESIZE_MOVE_F_REPOINTED;
	return (resize_check_move_invariant(ctx, move));
}

int
resize_free_stage(struct resize_ctx *ctx, struct resize_move *move)
{
	uint64_t owner_fsb;
	uint64_t nfrags;
	int old_is_free;
	int error;

	error = resize_check_move_invariant(ctx, move);
	if (error != 0)
		return (error);
	if ((move->flags & RESIZE_MOVE_F_COPIED) == 0)
		return (EINVAL);
	if ((move->flags & RESIZE_MOVE_F_REPOINTED) == 0)
		return (EINVAL);
	if ((move->flags & RESIZE_MOVE_F_FREED) != 0)
		return (EINVAL);
	error = resize_move_nfrags(ctx, move, &nfrags);
	if (error != 0)
		return (error);

	error = ctx->ops->owner_get(ctx->cookie, &move->owner, &owner_fsb);
	if (error != 0)
		return (error);
	if (owner_fsb != move->new_fsb)
		return (EINVAL);

	error = resize_alloc_run_is_free(ctx, move->old_fsb, nfrags,
	    &old_is_free);
	if (error != 0)
		return (error);
	if (old_is_free)
		return (EINVAL);

	/* Free is ordered last; old_fsb stays allocated until repoint is stable. */
	error = ctx->ops->journal_intent(ctx->cookie, RESIZE_MUT_FREE, move);
	if (error != 0)
		return (error);
	error = ctx->ops->sync_journal(ctx->cookie);
	if (error != 0)
		return (error);

	error = resize_alloc_run_mark(ctx, move->old_fsb, nfrags, 0);
	if (error != 0)
		return (error);
	error = ctx->ops->sync_target(ctx->cookie);
	if (error != 0)
		return (error);

	error = ctx->ops->journal_applied(ctx->cookie, RESIZE_MUT_FREE, move);
	if (error != 0)
		return (error);
	error = ctx->ops->sync_journal(ctx->cookie);
	if (error != 0)
		return (error);

	move->flags |= RESIZE_MOVE_F_FREED;
	return (resize_check_move_invariant(ctx, move));
}
