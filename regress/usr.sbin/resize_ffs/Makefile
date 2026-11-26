#	$OpenBSD$

# Test the resize_ffs built in this tree.  Ask make for the object
# directory of usr.sbin/resize_ffs instead of assuming /usr/obj, so trees
# with local obj directories work too.  resize_ffs.sh fails if the binary
# does not exist; it never falls back to /usr/sbin/resize_ffs.
.if !defined(RESIZE_FFS)
RESIZE_FFS_OBJDIR !=	cd ${.CURDIR}/../../../usr.sbin/resize_ffs && \
			${MAKE} -V .OBJDIR
RESIZE_FFS =		${RESIZE_FFS_OBJDIR}/resize_ffs
.endif

REGRESS_TARGETS =	grow-journal \
			shrink-relocate-ffs1 \
			shrink-relocate-ffs2 \
			shrink-moves-parent-first \
			shrink-ffs2-initediblk \
			shrink-symlink-maxlen-ffs1 \
			shrink-symlink-maxlen-ffs2 \
			shrink-moves-checked \
			shrink-moves-incomplete-ffs1 \
			shrink-moves-incomplete-ffs2 \
			shrink-ffs2-extattr \
			shrink-move-dry-run \
			push-forward-shrink-fails \
			shrink-refused-ffs1 \
			shrink-refused-ffs2 \
			parse-overflow-fails \
			truncated-journal-fails \
			grow-ffs1-partial-cg \
			grow-ffs2-partial-cg \
			grow-header-only-cg \
			grow-partial-cg-kept \
			grow-whole-cgs \
			grow-default-size \
			grow-dry-run-geometry \
			unaligned-size-fails \
			grow-no-gain-fails \
			noop-default-size-ffs1 \
			noop-default-size-ffs2 \
			noop-same-size-ffs1 \
			noop-same-size-ffs2 \
			grow-one-frag-ffs1 \
			grow-one-frag-ffs2 \
			legacy-image-grow
REGRESS_ROOT_TARGETS =	${REGRESS_TARGETS}

# legacy-image-grow needs an FFS1 image made by an older newfs (with
# cluster summaries); pass it as LEGACY_FFS_IMAGE=/path/to/image.
.if !defined(LEGACY_FFS_IMAGE)
REGRESS_SKIP_TARGETS +=	legacy-image-grow
.endif
LEGACY_FFS_IMAGE ?=

.for t in ${REGRESS_TARGETS}
$t:
	${SUDO} env OBJDIR=${.OBJDIR} SRCDIR=${.CURDIR} \
		RESIZE_FFS=${RESIZE_FFS} \
		LEGACY_FFS_IMAGE=${LEGACY_FFS_IMAGE} \
		ksh ${.CURDIR}/resize_ffs.sh $t
.endfor

.include <bsd.regress.mk>
