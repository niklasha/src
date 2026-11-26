#!/bin/ksh
#
# $OpenBSD$

set -eu

PATH=/bin:/sbin:/usr/bin:/usr/sbin

NEWFS=${NEWFS:-/sbin/newfs}
FSCK_FFS=${FSCK_FFS:-/sbin/fsck_ffs}
DUMPFS=${DUMPFS:-/sbin/dumpfs}
VNCONFIG=${VNCONFIG:-/sbin/vnconfig}
MOUNT=${MOUNT:-/sbin/mount}
UMOUNT=${UMOUNT:-/sbin/umount}

TMP=
IMG=
MNT=
REF=
VND=
RESIZE_FFS=${RESIZE_FFS:-}

fail()
{
	echo "FAILED: $*" >&2
	exit 1
}

# The binary under test must be given explicitly; the Makefile passes the
# one in usr.sbin/resize_ffs's object directory.  Never fall back to an
# installed binary: that silently tests the wrong code.
find_resize_ffs()
{
	[ -n "${RESIZE_FFS}" ] ||
		fail "RESIZE_FFS not set; build usr.sbin/resize_ffs or" \
		    "pass RESIZE_FFS=/path/to/resize_ffs"
	[ -f "${RESIZE_FFS}" ] && [ -x "${RESIZE_FFS}" ] ||
		fail "resize_ffs binary ${RESIZE_FFS} not found; build" \
		    "usr.sbin/resize_ffs first or pass RESIZE_FFS="
	echo "resize_ffs under test: ${RESIZE_FFS}" \
	    "(sha256 $(sha256 -q "${RESIZE_FFS}"))" >&2
}

cleanup()
{
	if [ -n "${MNT}" ] && mount | grep -Fq " on ${MNT} "; then
		${UMOUNT} "${MNT}" >/dev/null 2>&1 || true
	fi
	if [ -n "${VND}" ]; then
		${VNCONFIG} -u "${VND}" >/dev/null 2>&1 || true
		VND=
	fi
	if [ -n "${TMP}" ]; then
		rm -rf "${TMP}"
	fi
}

setup_tmp()
{
	TMP=$(mktemp -d /tmp/resize_ffs_regress.XXXXXXXXXX) ||
		fail "mktemp failed"
	IMG=${TMP}/image
	MNT=${TMP}/mnt
	REF=${TMP}/ref
	mkdir "${MNT}" "${REF}"
}

attach_vnd()
{
	[ -z "${VND}" ] || fail "vnd already attached"
	VND=$(${VNCONFIG} "${IMG}") || fail "vnconfig attach failed"
}

detach_vnd()
{
	[ -n "${VND}" ] || return 0
	${VNCONFIG} -u "${VND}" >/dev/null || fail "vnconfig detach failed"
	VND=
}

mount_img()
{
	[ -n "${VND}" ] || fail "mount_img requires attached vnd"
	${MOUNT} /dev/${VND}c "${MNT}" >/dev/null ||
		fail "mount failed"
}

umount_img()
{
	${UMOUNT} "${MNT}" >/dev/null || fail "umount failed"
}

# create_image size_mb [format]: newfs's default format unless given.
create_image()
{
	size_mb=$1
	fmtopt=

	[ -n "${2:-}" ] && fmtopt="-O $2"
	rm -f "${IMG}"
	dd if=/dev/zero of="${IMG}" bs=1m count=0 seek="${size_mb}" \
	    status=none || fail "dd create image failed"
	attach_vnd
	${NEWFS} -q ${fmtopt} /dev/r${VND}c >/dev/null || fail "newfs failed"
	detach_vnd
}

grow_container()
{
	size_mb=$1

	dd if=/dev/zero of="${IMG}" bs=1m count=0 seek="${size_mb}" \
	    status=none || fail "dd grow image failed"
}

checksum_tree()
{
	base=$1
	out=$2

	find "${base}" -type f | sort | while IFS= read -r f; do
		rel=${f#${base}/}
		set -- $(cksum "${f}")
		echo "$1 $2 ${rel}"
	done > "${out}"
}

assert_contains()
{
	file=$1
	text=$2

	grep -Fq "${text}" "${file}" ||
		fail "${file} missing expected text: ${text}"
}

assert_not_empty()
{
	file=$1

	[ -s "${file}" ] || fail "${file} is empty"
}

fs_field()
{
	dev=$1
	key=$2

	${DUMPFS} "${dev}" | awk -v key="${key}" '
		/^cs\[\]/ { exit }
		{
			for (i = 1; i < NF; i++)
				if ($i == key && !(key in v))
					v[key] = $(i + 1)
		}
		END { print v[key] }
	'
}

fs_bytes()
{
	size=$(fs_field /dev/r${VND}c size)
	fsize=$(fs_field /dev/r${VND}c fsize)
	echo $((size * fsize))
}

# fsck_ffs exits 0 even when it reports damage with -n, so require that
# its output has nothing but the phase banners and the final summary.
fsck_clean()
{
	dev=$1
	out=${TMP}/fsck.out

	${FSCK_FFS} -fn "${dev}" > "${out}" 2>&1 ||
		fail "fsck_ffs failed on ${dev}"
	if grep -Ev '^\*\* |^[0-9]+ files, [0-9]+ used, [0-9]+ free ' \
	    "${out}" | grep -q .; then
		cat "${out}" >&2
		fail "fsck_ffs reported damage on ${dev}"
	fi
}

check_fs_state()
{
	expect_bytes=$1
	expect_cksum=$2
	actual_cksum=${TMP}/mounted.cksum
	actual_bytes=

	attach_vnd
	fsck_clean /dev/r${VND}c
	actual_bytes=$(fs_bytes)
	[ "${actual_bytes}" = "${expect_bytes}" ] ||
		fail "expected ${expect_bytes} bytes, got ${actual_bytes}"
	mount_img
	checksum_tree "${MNT}" "${actual_cksum}"
	diff -u "${expect_cksum}" "${actual_cksum}" >/dev/null ||
		fail "fixture checksum mismatch"
	umount_img
	detach_vnd
}

make_grow_fixture()
{
	mkdir -p "${REF}/alpha" "${REF}/beta"
	print "grow fixture" > "${REF}/alpha/note.txt"
	jot -b x 4096 > "${REF}/alpha/pattern.txt"
	dd if=/dev/zero bs=1k count=512 2>/dev/null | tr '\0' A \
	    > "${REF}/beta/medium.bin"
	dd if=/dev/zero bs=1m count=4 2>/dev/null | tr '\0' B \
	    > "${REF}/beta/large.bin"
	checksum_tree "${REF}" "${TMP}/ref.cksum"

	attach_vnd
	mount_img
	cp -R "${REF}/." "${MNT}/" || fail "copy fixture failed"
	sync
	umount_img
	detach_vnd
}

make_shrink_fixture()
{
	mkdir -p "${REF}/data"
	dd if=/dev/zero bs=1m count=12 2>/dev/null | tr '\0' C \
	    > "${REF}/data/keep.bin"
	print "shrink fixture" > "${REF}/data/keep.txt"
	checksum_tree "${REF}" "${TMP}/ref.cksum"

	attach_vnd
	mount_img
	dd if=/dev/zero bs=1m count=8 2>/dev/null | tr '\0' D \
	    > "${MNT}/filler.bin"
	cp -R "${REF}/." "${MNT}/" || fail "copy shrink fixture failed"
	rm -f "${MNT}/filler.bin"
	sync
	umount_img
	detach_vnd
}

run_grow_journal()
{
	setup_tmp
	create_image 16
	make_grow_fixture
	grow_container 24

	"${RESIZE_FFS}" --check-invariants --size 24m \
	    --journal "${TMP}/grow.journal" "${IMG}" \
	    > "${TMP}/grow.out" 2> "${TMP}/grow.err" ||
		fail "grow resize failed"
	assert_contains "${TMP}/grow.out" "new_size=25165824"
	check_fs_state 25165824 "${TMP}/ref.cksum"

	"${RESIZE_FFS}" --verbose --recover --journal "${TMP}/grow.journal" \
	    "${IMG}" > "${TMP}/recover.out" 2> "${TMP}/recover.err" ||
		fail "recover failed"
	assert_contains "${TMP}/recover.err" \
	    "recover: journal appears fully applied; nothing to replay"

	"${RESIZE_FFS}" --verbose --resume --journal "${TMP}/grow.journal" \
	    "${IMG}" > "${TMP}/resume.out" 2> "${TMP}/resume.err" ||
		fail "resume failed"
	assert_contains "${TMP}/resume.err" "resume: finalized at fs_offset=0"

	"${RESIZE_FFS}" --check-invariants --revert \
	    --journal "${TMP}/grow.journal" "${IMG}" \
	    > "${TMP}/revert.out" 2> "${TMP}/revert.err" ||
		fail "grow revert failed"
	check_fs_state 16777216 "${TMP}/ref.cksum"
}

# create_image_opts size_mb newfs-options...: newfs with explicit options.
create_image_opts()
{
	size_mb=$1
	shift

	rm -f "${IMG}"
	dd if=/dev/zero of="${IMG}" bs=1m count=0 seek="${size_mb}" \
	    status=none || fail "dd create image failed"
	attach_vnd
	${NEWFS} -q "$@" /dev/r${VND}c >/dev/null || fail "newfs $* failed"
	detach_vnd
}

# Shrink fixture with a deterministic layout.  The image is made with a
# huge maxbpg (-e), so files are allocated sequentially: a filler written
# first takes most of the low half, keep.bin (with an indirect block)
# lands largely beyond 16 MB, and removing the filler leaves the free
# space below 16 MB.  An indirect block is allocated just before the
# blocks it maps, so it lies below most of its children.  With
# "dirs", directories made first are spread over all cylinder groups by
# the kernel, so a shrink to 16 MB always has to move inodes.  Without
# them, the files are made in the root directory, whose inodes are in
# cg 0, so no inode has to move.
make_layout_fixture()
{
	with_dirs=$1
	i=0
	sub=.

	[ "${with_dirs}" = dirs ] && sub=data
	mkdir -p "${REF}/${sub}"
	dd if=/dev/zero bs=1m count=12 2>/dev/null | tr '\0' C \
	    > "${REF}/${sub}/keep.bin"
	print "shrink fixture" > "${REF}/${sub}/keep.txt"
	if [ "${with_dirs}" = dirs ]; then
		while [ ${i} -lt 24 ]; do
			mkdir "${REF}/dir${i}"
			jot $((i + 1)) > "${REF}/dir${i}/list"
			i=$((i + 1))
		done
	fi

	attach_vnd
	mount_img
	if [ "${with_dirs}" = dirs ]; then
		i=0
		while [ ${i} -lt 24 ]; do
			mkdir "${MNT}/dir${i}"
			cp "${REF}/dir${i}/list" "${MNT}/dir${i}/list"
			i=$((i + 1))
		done
	fi
	dd if=/dev/zero bs=1m count=16 2>/dev/null | tr '\0' D \
	    > "${MNT}/filler.bin"
	mkdir -p "${MNT}/${sub}"
	cp "${REF}/${sub}/keep.bin" "${REF}/${sub}/keep.txt" "${MNT}/${sub}/" ||
		fail "copy shrink fixture failed"
	rm -f "${MNT}/filler.bin"
	sync
	umount_img
	detach_vnd
	checksum_tree "${REF}" "${TMP}/ref.cksum"
}

# count_parent_before_child log fsize bsize: from a --verbose relocation
# log, count child blocks whose parent indirect block is also moved and
# has a lower old block number, i.e. the plan entries that sorting the
# plan by old_fsb puts in the wrong order (the D13a hazard).
count_parent_before_child()
{
	awk -v fsize="$2" -v bsize="$3" '
	function field(name,    i) {
		for (i = 1; i <= NF; i++)
			if (index($i, name "=") == 1)
				return substr($i, length(name) + 2)
		return ""
	}
	FNR == NR && /\] copy old_fsb=/ {
		if (field("bytes") == bsize)
			parent[field("old_fsb") * fsize] = field("old_fsb")
		next
	}
	/\] copy old_fsb=/ { cur = field("old_fsb"); next }
	/\] repoint owner_abs=/ {
		o = field("owner_abs")
		k = o - (o % bsize)
		if ((k in parent) && parent[k] + 0 < cur + 0)
			n++
	}
	END { print n + 0 }' "$1" "$1"
}

# The automatic plan after an inode remap must keep children before
# their parent indirect block (D13a: it used to be sorted by old_fsb).
# The fixture guarantees an inode remap and moved parents that lie below
# their moved children; then shrink, check, revert, check.
run_shrink_relocate()
{
	fmt=$1

	setup_tmp
	create_image_opts 32 -O ${fmt} -e 1000000
	make_layout_fixture dirs
	attach_vnd
	load_geom
	BSIZE=$(fs_field /dev/r${VND}c bsize)
	detach_vnd

	"${RESIZE_FFS}" --verbose --check-invariants --size 16m \
	    --journal "${TMP}/shrink.journal" "${IMG}" \
	    > "${TMP}/shrink.out" 2> "${TMP}/shrink.err" ||
		fail "shrink resize failed: $(tail -3 "${TMP}/shrink.err")"
	assert_contains "${TMP}/shrink.err" "inode(s) will be relocated"
	assert_contains "${TMP}/shrink.err" "phase: relocating ("
	n=$(count_parent_before_child "${TMP}/shrink.err" ${FSIZE} ${BSIZE})
	[ "${n}" -gt 0 ] ||
		fail "fixture moved no indirect block below its children"
	echo "shrink-relocate-ffs${fmt}: ${n} child block(s) above a moved" \
	    "parent" >&2
	check_fs_state 16777216 "${TMP}/ref.cksum"

	"${RESIZE_FFS}" --check-invariants --revert \
	    --journal "${TMP}/shrink.journal" "${IMG}" \
	    > "${TMP}/revert.out" 2> "${TMP}/revert.err" ||
		fail "shrink revert failed: $(tail -3 "${TMP}/revert.err")"
	check_fs_state 33554432 "${TMP}/ref.cksum"
}

# A --moves plan sorted by old_fsb moves every parent indirect block
# before its children (D13a, deterministic).  The child pointer updates
# must reach the moved copy of the parent.  The plan is the automatic
# plan of the same image, taken from a --verbose run on a copy.
run_shrink_moves_parent_first()
{
	setup_tmp
	create_image_opts 32 -O 1 -e 1000000
	make_layout_fixture nodirs
	attach_vnd
	load_geom
	BSIZE=$(fs_field /dev/r${VND}c bsize)
	detach_vnd
	cp "${IMG}" "${TMP}/orig.img" || fail "copy image failed"

	"${RESIZE_FFS}" --verbose --size 16m --journal "${TMP}/auto.journal" \
	    "${IMG}" > "${TMP}/auto.out" 2> "${TMP}/auto.err" ||
		fail "automatic shrink failed"
	if grep -q "inode(s) will be relocated" "${TMP}/auto.err"; then
		fail "fixture has inodes beyond 16 MB"
	fi
	awk '
	function field(name,    i) {
		for (i = 1; i <= NF; i++)
			if (index($i, name "=") == 1)
				return substr($i, length(name) + 2)
		return ""
	}
	/\] copy old_fsb=/ {
		o = field("old_fsb"); n = field("new_fsb"); b = field("bytes")
	}
	/\] repoint owner_abs=/ {
		print o, n, b, field("owner_abs"), field("width")
	}' "${TMP}/auto.err" | sort -n -k1,1 > "${TMP}/plan.moves"
	[ -s "${TMP}/plan.moves" ] || fail "empty plan"
	n=$(awk -v fsize=${FSIZE} -v bsize=${BSIZE} '
	{ pos[$1 * fsize] = NR; if ($3 == bsize) isblk[$1 * fsize] = 1
	  line[NR] = $4 }
	END {
		for (i = 1; i <= NR; i++) {
			k = line[i] - (line[i] % bsize)
			if ((k in pos) && (k in isblk) && pos[k] < i)
				c++
		}
		print c + 0
	}' "${TMP}/plan.moves")
	[ "${n}" -gt 0 ] || fail "sorted plan has no parent before a child"

	cp "${TMP}/orig.img" "${IMG}" || fail "restore image failed"
	"${RESIZE_FFS}" --verbose --check-invariants --size 16m \
	    --moves "${TMP}/plan.moves" --journal "${TMP}/moves.journal" \
	    "${IMG}" > "${TMP}/moves.out" 2> "${TMP}/moves.err" ||
		fail "shrink with --moves failed: $(tail -3 "${TMP}/moves.err")"
	check_fs_state 16777216 "${TMP}/ref.cksum"
	assert_contains "${TMP}/moves.err" "owner slot(s) redirected"
	echo "shrink-moves-parent-first: ${n} child(ren) after their parent," \
	    "$(sed -n 's/^plan: \([0-9]*\) owner slot.*/\1/p' \
	    "${TMP}/moves.err") redirected" >&2

	"${RESIZE_FFS}" --check-invariants --revert \
	    --journal "${TMP}/moves.journal" "${IMG}" \
	    > "${TMP}/revert.out" 2> "${TMP}/revert.err" ||
		fail "revert failed: $(tail -3 "${TMP}/revert.err")"
	check_fs_state 33554432 "${TMP}/ref.cksum"
}

# cg_initiblk cg: cg_initediblk of a cg on the attached vnd.
cg_initiblk()
{
	${DUMPFS} /dev/r${VND}c | awk -v cg="cg $1:" '
	$0 == cg { found = 1; next }
	found && $1 == "cgx" {
		for (i = 1; i < NF; i++)
			if ($i == "initiblk") { print $(i + 1); exit }
	}'
}

# D13b: FFS2 initializes inode blocks lazily (cg_initediblk).  Inodes
# moved out of the removed cylinder groups go to the lowest free inode
# numbers, which lie in cg 0 beyond its initialized inode blocks; the
# blocks must be initialized and cg_initediblk raised, or fsck_ffs
# reports the inodes unallocated (and the kernel would zero them).
run_shrink_ffs2_initediblk()
{
	i=0

	setup_tmp
	create_image_opts 32 -O 2 -b 4096 -f 512
	while [ ${i} -lt 64 ]; do
		mkdir -p "${REF}/d${i}"
		jot $((i + 1)) > "${REF}/d${i}/a"
		print ${i} > "${REF}/d${i}/b"
		ln -s a "${REF}/d${i}/l"
		i=$((i + 1))
	done
	checksum_tree "${REF}" "${TMP}/ref.cksum"
	attach_vnd
	mount_img
	cp -RP "${REF}/." "${MNT}/" || fail "copy fixture failed"
	sync
	umount_img
	before=$(cg_initiblk 0)
	detach_vnd

	"${RESIZE_FFS}" --verbose --check-invariants --size 12m \
	    --journal "${TMP}/shrink.journal" "${IMG}" \
	    > "${TMP}/shrink.out" 2> "${TMP}/shrink.err" ||
		fail "shrink failed: $(tail -3 "${TMP}/shrink.err")"
	nrm=$(sed -n 's/^inode-remap: \([0-9]*\) inode(s) will.*/\1/p' \
	    "${TMP}/shrink.err")
	[ -n "${nrm}" ] && [ "${nrm}" -gt "${before}" ] ||
		fail "only ${nrm:-0} inode(s) remapped, cg 0 initiblk ${before}"
	attach_vnd
	after=$(cg_initiblk 0)
	detach_vnd
	[ "${after}" -gt "${before}" ] ||
		fail "cg 0 initiblk ${before} -> ${after}: not raised"
	echo "shrink-ffs2-initediblk: ${nrm} inodes remapped, cg 0 initiblk" \
	    "${before} -> ${after}" >&2
	check_fs_state 12582912 "${TMP}/ref.cksum"

	"${RESIZE_FFS}" --check-invariants --revert \
	    --journal "${TMP}/shrink.journal" "${IMG}" \
	    > "${TMP}/revert.out" 2> "${TMP}/revert.err" ||
		fail "revert failed: $(tail -3 "${TMP}/revert.err")"
	check_fs_state 33554432 "${TMP}/ref.cksum"
}

# Shrinks that cannot work are refused before anything is written, also
# with --force and --dry-run: exit 1, no journal, image byte-identical.
run_shrink_refused()
{
	fmt=$1

	setup_tmp
	create_image_opts 32 -O ${fmt} -e 1000000
	make_layout_fixture dirs
	cp "${IMG}" "${TMP}/orig.img" || fail "copy image failed"
	: > "${TMP}/empty.moves"

	for opts in "--size 8m" "--force --size 8m" "--dry-run --size 8m" \
	    "--size 1m" "--force --size 1m" \
	    "--policy shrink-move --size 8m" \
	    "--moves ${TMP}/empty.moves --size 16m" \
	    "--force --moves ${TMP}/empty.moves --size 16m"; do
		rm -f "${TMP}/shrink.journal"
		set +e
		"${RESIZE_FFS}" ${opts} --journal "${TMP}/shrink.journal" \
		    "${IMG}" > "${TMP}/shrink.out" 2> "${TMP}/shrink.err"
		rc=$?
		set -e
		[ ${rc} -eq 1 ] ||
			fail "shrink (${opts}) exited ${rc}, expected 1"
		assert_not_empty "${TMP}/shrink.err"
		[ ! -e "${TMP}/shrink.journal" ] ||
			fail "shrink (${opts}) wrote a journal"
		assert_image_unchanged
	done
	check_fs_state 33554432 "${TMP}/ref.cksum"
}

# expect_refused name args...: resize_ffs must exit 1, write no journal
# and leave the image byte-identical to ${TMP}/orig.img.
expect_refused()
{
	name=$1
	shift

	rm -f "${TMP}/refused.journal"
	set +e
	"${RESIZE_FFS}" "$@" --journal "${TMP}/refused.journal" "${IMG}" \
	    > "${TMP}/refused.out" 2> "${TMP}/refused.err"
	rc=$?
	set -e
	[ ${rc} -eq 1 ] || fail "${name}: exited ${rc}, expected 1"
	assert_not_empty "${TMP}/refused.err"
	[ ! -e "${TMP}/refused.journal" ] || fail "${name}: wrote a journal"
	if ! cmp -s "${TMP}/orig.img" "${IMG}"; then
		fail "${name}: image modified by a refused shrink"
	fi
	echo "${name}: refused: $(tail -1 "${TMP}/refused.err")" >&2
}

# The kernel keeps a symlink in the inode only when it is shorter than
# fs_maxsymlinklen (60 on FFS1, 120 on FFS2); a link of exactly that
# length has a data block.  Symlinks of length L-1, L and L+1 in eight
# directories spread over the cylinder groups; the shrink to 12 MB must
# move the blocks of the ones in removed groups.
run_shrink_symlink_maxlen()
{
	fmt=$1
	i=0

	setup_tmp
	create_image_opts 32 -O ${fmt} -f 1024 -b 8192 -c 4096
	attach_vnd
	L=$(fs_field /dev/r${VND}c symlinklen)
	[ -n "${L}" ] && [ "${L}" -gt 1 ] || fail "cannot read symlinklen"
	mount_img
	: > "${TMP}/links"
	while [ ${i} -lt 8 ]; do
		mkdir "${MNT}/d${i}"
		print ${i} > "${MNT}/d${i}/f"
		for n in $((L - 1)) ${L} $((L + 1)); do
			t=$(printf "%0${n}d" ${i})
			ln -s "${t}" "${MNT}/d${i}/s${n}"
			echo "d${i}/s${n} ${t}" >> "${TMP}/links"
		done
		i=$((i + 1))
	done
	checksum_tree "${MNT}" "${TMP}/ref.cksum"
	umount_img
	detach_vnd

	"${RESIZE_FFS}" --verbose --check-invariants --size 12m \
	    --journal "${TMP}/shrink.journal" "${IMG}" \
	    > "${TMP}/shrink.out" 2> "${TMP}/shrink.err" ||
		fail "shrink failed: $(tail -3 "${TMP}/shrink.err")"
	assert_contains "${TMP}/shrink.err" "inode(s) will be relocated"
	check_fs_state 12582912 "${TMP}/ref.cksum"
	attach_vnd
	mount_img
	while read -r p t; do
		[ "$(readlink "${MNT}/${p}")" = "${t}" ] ||
			fail "symlink ${p} lost its target"
	done < "${TMP}/links"
	umount_img
	detach_vnd

	"${RESIZE_FFS}" --check-invariants --revert \
	    --journal "${TMP}/shrink.journal" "${IMG}" \
	    > "${TMP}/revert.out" 2> "${TMP}/revert.err" ||
		fail "revert failed: $(tail -3 "${TMP}/revert.err")"
	check_fs_state 33554432 "${TMP}/ref.cksum"
}

# ffs2_db0_slot ino: byte offset of di_db[0] of an FFS2 inode in cg 0
# (geometry from load_geom and INOPB/IBLKNO).
ffs2_db0_slot()
{
	echo $(( (IBLKNO + ($1 / INOPB) * FRAG) * FSIZE + \
	    ($1 % INOPB) * 256 + 112 ))
}

read_u64()
{
	dd if="${IMG}" bs=1 skip=$1 count=8 2>/dev/null | od -An -t d8 |
	    tr -d ' ' | sed -e 's/^0*//' -e 's/^$/0/'
}

# A --moves plan is checked against the bitmaps before anything is
# written: a destination in use, a free source, an owner slot that does
# not hold the source and a wrong pointer width are refused.  A valid
# one-fragment move then works.
run_shrink_moves_checked()
{
	setup_tmp
	create_image_opts 32 -O 2 -f 1024 -b 8192
	mkdir -p "${REF}"
	dd if=/dev/zero bs=1k count=1 2>/dev/null | tr '\0' a > "${REF}/a"
	dd if=/dev/zero bs=1k count=1 2>/dev/null | tr '\0' b > "${REF}/b"
	checksum_tree "${REF}" "${TMP}/ref.cksum"
	attach_vnd
	load_geom
	IBLKNO=$(fs_field /dev/r${VND}c iblkno)
	INOPB=$(fs_field /dev/r${VND}c inopb)
	mount_img
	cp "${REF}/a" "${REF}/b" "${MNT}/"
	ia=$(stat -f %i "${MNT}/a")
	ib=$(stat -f %i "${MNT}/b")
	umount_img
	detach_vnd
	sa=$(ffs2_db0_slot ${ia})
	sb=$(ffs2_db0_slot ${ib})
	fa=$(read_u64 ${sa})
	fb=$(read_u64 ${sb})
	[ -n "${fa}" ] && [ -n "${fb}" ] && [ "${fa}" -ne "${fb}" ] ||
		fail "cannot find the fragments of a and b"
	# The first data fragment of cg 1 is free in a fresh file system.
	free=$((FPG + DBLKNO + 1))
	new=$(( (NCG - 1) * FPG * FSIZE ))
	cp "${IMG}" "${TMP}/orig.img" || fail "copy image failed"

	echo "${fa} ${fb} 1024 ${sa} 8" > "${TMP}/p1"
	expect_refused "destination in use" --size ${new} --moves "${TMP}/p1"
	assert_contains "${TMP}/refused.err" "destination fragment ${fb} is in use"
	echo "$((free + 1)) ${free} 1024 ${sa} 8" > "${TMP}/p2"
	expect_refused "unowned source" --size ${new} --moves "${TMP}/p2"
	echo "${fa} ${free} 1024 ${sb} 8" > "${TMP}/p3"
	expect_refused "wrong owner slot" --size ${new} --moves "${TMP}/p3"
	echo "${fa} ${free} 1024 ${sa} 4" > "${TMP}/p4"
	expect_refused "pointer width" --size ${new} --moves "${TMP}/p4"

	echo "${fa} ${free} 1024 ${sa} 8" > "${TMP}/p5"
	"${RESIZE_FFS}" --check-invariants --size ${new} --moves "${TMP}/p5" \
	    --journal "${TMP}/ok.journal" "${IMG}" > "${TMP}/ok.out" \
	    2> "${TMP}/ok.err" ||
		fail "valid --moves shrink failed: $(tail -3 "${TMP}/ok.err")"
	[ "$(read_u64 ${sa})" -eq ${free} ] || fail "a was not moved"
	check_fs_state ${new} "${TMP}/ref.cksum"
}

# A shrink must move every allocated fragment beyond the new size: a
# --moves plan that leaves data behind (here an empty one) is refused
# before anything is written.  The automatic plan then works.
run_shrink_moves_incomplete()
{
	fmt=$1

	setup_tmp
	create_image_opts 32 -O ${fmt} -e 1000000
	make_layout_fixture nodirs
	cp "${IMG}" "${TMP}/orig.img" || fail "copy image failed"
	: > "${TMP}/empty.moves"
	for opts in "" "--force" "--dry-run"; do
		expect_refused "empty plan ${opts}" ${opts} --size 16m \
		    --moves "${TMP}/empty.moves"
		assert_contains "${TMP}/refused.err" \
		    "beyond the new size would be lost"
	done
	"${RESIZE_FFS}" --check-invariants --size 16m \
	    --journal "${TMP}/ok.journal" "${IMG}" > "${TMP}/ok.out" \
	    2> "${TMP}/ok.err" ||
		fail "automatic shrink failed: $(tail -3 "${TMP}/ok.err")"
	check_fs_state 16777216 "${TMP}/ref.cksum"
}

# FFS2 extended attribute blocks (di_extb) are not relocated, so a
# shrink with any used inode that has extended attribute data is
# refused before anything is written.  OpenBSD never makes them; the
# test sets di_extsize and then di_extb[0] of a file by hand.
run_shrink_ffs2_extattr()
{
	setup_tmp
	create_image_opts 32 -O 2 -f 1024 -b 8192
	mkdir -p "${REF}"
	print extattr > "${REF}/x"
	checksum_tree "${REF}" "${TMP}/ref.cksum"
	attach_vnd
	load_geom
	IBLKNO=$(fs_field /dev/r${VND}c iblkno)
	INOPB=$(fs_field /dev/r${VND}c inopb)
	mount_img
	cp "${REF}/x" "${MNT}/"
	ix=$(stat -f %i "${MNT}/x")
	umount_img
	detach_vnd
	new=$(( (NCG - 1) * FPG * FSIZE ))
	cp "${IMG}" "${TMP}/clean.img" || fail "copy image failed"
	for off in 92 96; do	# di_extsize, di_extb[0]
		cp "${TMP}/clean.img" "${IMG}"
		printf '\001' | dd of="${IMG}" bs=1 conv=notrunc \
		    seek=$(( $(ffs2_db0_slot ${ix}) - 112 + off )) 2>/dev/null
		cp "${IMG}" "${TMP}/orig.img"
		expect_refused "extattr at ${off}" --size ${new}
		assert_contains "${TMP}/refused.err" "extended attribute"
	done
	cp "${TMP}/clean.img" "${IMG}"
	"${RESIZE_FFS}" --check-invariants --size ${new} \
	    --journal "${TMP}/ok.journal" "${IMG}" > "${TMP}/ok.out" \
	    2> "${TMP}/ok.err" ||
		fail "shrink failed: $(tail -3 "${TMP}/ok.err")"
	check_fs_state ${new} "${TMP}/ref.cksum"
}

run_shrink_move_dry_run()
{
	setup_tmp
	create_image 32 1

	"${RESIZE_FFS}" --dry-run --policy shrink-move --size 16m "${IMG}" \
	    > "${TMP}/shift.out" 2> "${TMP}/shift.err" ||
		fail "shrink-move dry-run failed"
	assert_contains "${TMP}/shift.out" "policy=shrink-move"
	assert_contains "${TMP}/shift.out" "new_offset=16777216"
	assert_contains "${TMP}/shift.out" "delta=16777216"

	"${RESIZE_FFS}" --dry-run --shrink-side beginning --size 16m "${IMG}" \
	    > "${TMP}/alias.out" 2> "${TMP}/alias.err" ||
		fail "shrink-side alias dry-run failed"
	assert_contains "${TMP}/alias.out" "policy=shrink-move"
	assert_contains "${TMP}/alias.out" "new_offset=16777216"
}

run_push_forward_shrink_fails()
{
	setup_tmp
	create_image 32

	if "${RESIZE_FFS}" --policy push-forward --size 16m "${IMG}" \
	    > "${TMP}/push.out" 2> "${TMP}/push.err"; then
		fail "push-forward shrink unexpectedly succeeded"
	fi
	assert_not_empty "${TMP}/push.err"
	assert_contains "${TMP}/push.err" \
	    "policy push-forward is not implemented for shrinking yet"
}

run_parse_overflow_fails()
{
	setup_tmp

	if "${RESIZE_FFS}" --dry-run --size 18014398509481985K /dev/null \
	    > "${TMP}/overflow.out" 2> "${TMP}/overflow.err"; then
		fail "oversized suffix value unexpectedly succeeded"
	fi
	assert_not_empty "${TMP}/overflow.err"
}

run_truncated_journal_fails()
{
	setup_tmp
	create_image 16
	make_grow_fixture
	grow_container 24

	"${RESIZE_FFS}" --size 24m --journal "${TMP}/grow.journal" "${IMG}" \
	    > "${TMP}/grow.out" 2> "${TMP}/grow.err" ||
		fail "grow resize failed"

	journal_sz=$(stat -f %z "${TMP}/grow.journal") ||
		fail "stat failed"
	[ "${journal_sz}" -gt 16 ] || fail "journal unexpectedly tiny"
	dd if="${TMP}/grow.journal" of="${TMP}/truncated.journal" bs=1 \
	    count=$((${journal_sz} - 16)) status=none ||
		fail "journal truncation failed"

	if "${RESIZE_FFS}" --recover --journal "${TMP}/truncated.journal" \
	    "${IMG}" > "${TMP}/bad.out" 2> "${TMP}/bad.err"; then
		fail "recover with truncated journal unexpectedly succeeded"
	fi
	assert_contains "${TMP}/bad.err" "open journal: Invalid argument"
}


# Geometry of the file system on the attached vnd, from dumpfs.
load_geom()
{
	dev=/dev/r${VND}c

	FPG=$(fs_field "${dev}" fpg)
	FSIZE=$(fs_field "${dev}" fsize)
	FRAG=$(fs_field "${dev}" frag)
	CBLKNO=$(fs_field "${dev}" cblkno)
	DBLKNO=$(fs_field "${dev}" dblkno)
	CGSIZE=$(fs_field "${dev}" cgsize)
	CGOFFSET=$(fs_field "${dev}" cgoffset)
	SBLKNO=$(fs_field "${dev}" sblkno)
	NCG=$(fs_field "${dev}" ncg)
	SIZE=$(fs_field "${dev}" size)
	DSIZE=$(fs_field "${dev}" blocks)
	[ -n "${CGOFFSET}" ] || CGOFFSET=0
	[ -n "${FPG}" ] && [ -n "${FSIZE}" ] && [ -n "${DBLKNO}" ] ||
		fail "cannot parse dumpfs geometry"
}

# Frags from the start of cg $1 to the end of its inode table (cgdmin).
cg_meta_frags()
{
	cg=$1
	off=0

	# FFS1 rotates the cg metadata by cgoffset in odd cylinder groups
	[ $((cg % 2)) -eq 1 ] && off=${CGOFFSET}
	echo $((off + DBLKNO))
}

# Size in bytes resize_ffs must produce for a target of $1 frags: the
# last cg is dropped unless it holds its metadata plus one data block.
expect_fit_bytes()
{
	tf=$1
	ncg=$(((tf + FPG - 1) / FPG))
	last=$((ncg - 1))
	rem=$((tf - last * FPG))
	need=$(($(cg_meta_frags ${last}) + FRAG))

	if [ ${rem} -lt ${need} ]; then
		echo $((last * FPG * FSIZE))
	else
		echo $((tf * FSIZE))
	fi
}

# An FFS image shaped like the root file system that triggered the
# invalid-geometry bug: 522327 sectors, bsize 16384, fsize 2048 and
# 65376 frags per cg, i.e. two cylinder groups, the second partial.
# The container is then grown to 1048599 sectors (not a multiple of
# the fragment size).
make_quad_shape_image()
{
	fmt=$1

	rm -f "${IMG}"
	dd if=/dev/zero of="${IMG}" bs=512 count=0 seek=522327 \
	    status=none || fail "dd create image failed"
	attach_vnd
	${NEWFS} -q -O "${fmt}" -b 16384 -f 2048 -c 65376 \
	    /dev/r${VND}c >/dev/null 2>&1 || fail "newfs failed"
	detach_vnd
	make_grow_fixture
	attach_vnd
	load_geom
	detach_vnd
	[ "${FPG}" -eq 65376 ] && [ "${FSIZE}" -eq 2048 ] &&
	    [ "${NCG}" -eq 2 ] || fail "unexpected newfs geometry"
	OLD_BYTES=$((SIZE * FSIZE))
	grow_container_sectors 1048599
}

grow_container_sectors()
{
	dd if=/dev/zero of="${IMG}" bs=512 count=0 seek="$1" \
	    status=none || fail "dd grow image failed"
}

# Grow to $1 frags; expect the result computed by expect_fit_bytes.
grow_and_check()
{
	tf=$1
	expect=$(expect_fit_bytes ${tf})

	"${RESIZE_FFS}" --check-invariants --verbose --size $((tf * FSIZE)) \
	    --journal "${TMP}/grow.journal" "${IMG}" \
	    > "${TMP}/grow.out" 2> "${TMP}/grow.err" ||
		fail "grow to ${tf} frags failed"
	assert_contains "${TMP}/grow.out" "new_size=${expect}"
	if [ ${expect} -ne $((tf * FSIZE)) ]; then
		assert_contains "${TMP}/grow.err" "cannot be allocated"
	elif grep -q "cannot be allocated" "${TMP}/grow.err"; then
		fail "unexpected truncation warning"
	fi
	check_fs_state ${expect} "${TMP}/ref.cksum"
	check_dsize
}

# fs_dsize counts data frags only: each new cg adds its size minus its
# superblock copy, cg block and inode table (as in newfs and growfs).
check_dsize()
{
	attach_vnd
	nsize=$(fs_field /dev/r${VND}c size)
	nncg=$(fs_field /dev/r${VND}c ncg)
	ndsize=$(fs_field /dev/r${VND}c blocks)
	detach_vnd
	want=$((DSIZE + nsize - SIZE - (nncg - NCG) * (DBLKNO - SBLKNO)))
	[ "${ndsize}" -eq "${want}" ] ||
		fail "fs_dsize ${ndsize}, expected ${want}"
}

# The reproducer: grow 255M -> 512M to 536881152 bytes (262149 frags).
# The 5th cg would get 645 frags: room for its superblock copy and cg
# block, but not for its inode table, which used to be placed beyond
# the end of the file system and the partition.
run_grow_partial_cg()
{
	fmt=$1
	tf=262149

	setup_tmp
	make_quad_shape_image ${fmt}
	rem=$((tf - 4 * FPG))
	[ ${rem} -gt $((CBLKNO + CGSIZE / FSIZE)) ] &&
	    [ ${rem} -lt $(cg_meta_frags 4) ] ||
		fail "test geometry does not exercise a partial cg"
	grow_and_check ${tf}
	[ "$(expect_fit_bytes ${tf})" -eq $((4 * FPG * FSIZE)) ] ||
		fail "expected the partial cg to be dropped"

	"${RESIZE_FFS}" --check-invariants --revert \
	    --journal "${TMP}/grow.journal" "${IMG}" \
	    > "${TMP}/revert.out" 2> "${TMP}/revert.err" ||
		fail "grow revert failed"
	check_fs_state ${OLD_BYTES} "${TMP}/ref.cksum"
}

# Tail just big enough for the superblock copy and cg block.
run_grow_header_only_cg()
{
	setup_tmp
	make_quad_shape_image 1
	grow_and_check $((4 * FPG + CBLKNO + CGSIZE / FSIZE))
}

# Tail holds the metadata plus one block and one more frag: the cg is
# kept and the size is fragment- but not block-aligned.
run_grow_partial_cg_kept()
{
	setup_tmp
	make_quad_shape_image 1
	tf=$((4 * FPG + $(cg_meta_frags 4) + FRAG + 1))
	grow_container_sectors $((tf * FSIZE / 512))
	grow_and_check ${tf}
	attach_vnd
	[ "$(fs_field /dev/r${VND}c ncg)" -eq 5 ] || fail "expected 5 cgs"
	detach_vnd
}

# Whole cylinder groups only.
run_grow_whole_cgs()
{
	setup_tmp
	make_quad_shape_image 2
	grow_and_check $((4 * FPG))
}

# Without --size the target is the container rounded down to fsize.
run_grow_default_size()
{
	setup_tmp
	make_quad_shape_image 1
	expect=$(expect_fit_bytes $((1048599 * 512 / FSIZE)))

	"${RESIZE_FFS}" --check-invariants --journal "${TMP}/grow.journal" \
	    "${IMG}" > "${TMP}/grow.out" 2> "${TMP}/grow.err" ||
		fail "grow to container size failed"
	assert_contains "${TMP}/grow.out" "new_size=${expect}"
	check_fs_state ${expect} "${TMP}/ref.cksum"
}

run_grow_dry_run_geometry()
{
	setup_tmp
	make_quad_shape_image 1

	"${RESIZE_FFS}" --dry-run --size 536881152 "${IMG}" \
	    > "${TMP}/dry.out" 2> "${TMP}/dry.err" ||
		fail "dry-run failed"
	assert_contains "${TMP}/dry.out" "target=$((4 * FPG * FSIZE)) "
	assert_contains "${TMP}/dry.out" "ncg=2->4"
	assert_contains "${TMP}/dry.err" "cannot be allocated"
	check_fs_state ${OLD_BYTES} "${TMP}/ref.cksum"
}

run_unaligned_size_fails()
{
	setup_tmp
	make_quad_shape_image 1

	if "${RESIZE_FFS}" --size 536881153 --journal "${TMP}/grow.journal" \
	    "${IMG}" > "${TMP}/bad.out" 2> "${TMP}/bad.err"; then
		fail "unaligned size unexpectedly succeeded"
	fi
	assert_contains "${TMP}/bad.err" "target size must align to fs_fsize="
	check_fs_state ${OLD_BYTES} "${TMP}/ref.cksum"
}

# Growing a file system of whole cgs by less than one cg's metadata
# gains nothing and must fail without touching the file system.
run_grow_no_gain_fails()
{
	setup_tmp
	make_quad_shape_image 1
	grow_and_check $((4 * FPG))
	rm -f "${TMP}/grow.journal"

	if "${RESIZE_FFS}" --size $(((4 * FPG + 23) * FSIZE)) \
	    --journal "${TMP}/grow.journal" "${IMG}" \
	    > "${TMP}/bad.out" 2> "${TMP}/bad.err"; then
		fail "grow without gain unexpectedly succeeded"
	fi
	assert_contains "${TMP}/bad.err" "not enough new space"
	check_fs_state $((4 * FPG * FSIZE)) "${TMP}/ref.cksum"
}

# A file system exactly as newfs makes it on a partition it fills: newfs
# keeps a last cg once it holds roundup(dblkno, frag) frags, i.e. even
# when there is no room for a data block in it.  10 cgs, the last one
# with exactly that many frags; directories spread over the cgs.
make_newfs_short_last_cg_image()
{
	fmt=$1

	rm -f "${IMG}"
	dd if=/dev/zero of="${IMG}" bs=512 count=0 seek=$((10 * 4096)) \
	    status=none || fail "dd create probe image failed"
	attach_vnd
	${NEWFS} -q -O "${fmt}" -b 4096 -f 512 -c 4096 \
	    /dev/r${VND}c >/dev/null 2>&1 || fail "newfs probe failed"
	load_geom
	detach_vnd
	[ "${FSIZE}" -eq 512 ] && [ "${FPG}" -eq 4096 ] ||
		fail "unexpected probe geometry"
	lastmin=$(((DBLKNO + FRAG - 1) / FRAG * FRAG))

	rm -f "${IMG}"
	dd if=/dev/zero of="${IMG}" bs=512 count=0 \
	    seek=$((9 * FPG + lastmin)) status=none ||
		fail "dd create image failed"
	attach_vnd
	${NEWFS} -q -O "${fmt}" -b 4096 -f 512 -c 4096 \
	    /dev/r${VND}c >/dev/null 2>&1 || fail "newfs failed"
	load_geom
	detach_vnd
	[ "${FPG}" -eq 4096 ] && [ "${NCG}" -eq 10 ] &&
	    [ "${SIZE}" -eq $((9 * FPG + lastmin)) ] ||
		fail "newfs did not keep a short last cg (ncg ${NCG}," \
		    "size ${SIZE}, fpg ${FPG})"
	[ $((SIZE - 9 * FPG)) -lt $((DBLKNO + FRAG)) ] ||
		fail "last cg is not short of a data block"

	i=0
	while [ ${i} -lt 60 ]; do
		mkdir -p "${REF}/d${i}"
		print "dir ${i}" > "${REF}/d${i}/f"
		i=$((i + 1))
	done
	make_grow_fixture
	OLD_BYTES=$((SIZE * FSIZE))
	cp "${IMG}" "${TMP}/orig.img" || fail "copy image failed"
}

# Nothing may have been written: the image must be byte-identical.
assert_image_unchanged()
{
	if ! cmp -s "${TMP}/orig.img" "${IMG}"; then
		cmp -l "${TMP}/orig.img" "${IMG}" | head -20 >&2
		fail "image modified by a no-op request"
	fi
}

# Run resize_ffs with the given options; it must say "nothing to do",
# exit 0 and leave the file system untouched.
expect_noop()
{
	rm -f "${TMP}/noop.journal"
	"${RESIZE_FFS}" --check-invariants --journal "${TMP}/noop.journal" \
	    "$@" "${IMG}" > "${TMP}/noop.out" 2> "${TMP}/noop.err" ||
		fail "no-op request $* failed: $(cat "${TMP}/noop.err")"
	assert_contains "${TMP}/noop.out" \
	    "nothing to do: file system size is already ${OLD_BYTES} bytes"
	if grep -Eq "inode-remap|cannot be allocated|relocat" \
	    "${TMP}/noop.err"; then
		cat "${TMP}/noop.err" >&2
		fail "no-op request $* planned a shrink"
	fi
	[ ! -e "${TMP}/noop.journal" ] || fail "no-op request wrote a journal"
	assert_image_unchanged
}

# No --size on a partition newfs filled completely: must not shrink.
run_noop_default_size()
{
	setup_tmp
	make_newfs_short_last_cg_image $1
	expect_noop --dry-run
	expect_noop
	check_fs_state ${OLD_BYTES} "${TMP}/ref.cksum"
}

# --size equal to the current size: must not shrink.
run_noop_same_size()
{
	setup_tmp
	make_newfs_short_last_cg_image $1
	expect_noop --dry-run --size ${OLD_BYTES}
	expect_noop --size ${OLD_BYTES}
	check_fs_state ${OLD_BYTES} "${TMP}/ref.cksum"
}

# One frag more than the current size: the short last cg is kept and
# grows by one frag; --revert restores the original file system.
run_grow_one_frag()
{
	setup_tmp
	make_newfs_short_last_cg_image $1
	tf=$((SIZE + 1))
	grow_container_sectors $((tf * FSIZE / 512))
	cp "${IMG}" "${TMP}/orig.img" || fail "copy image failed"

	"${RESIZE_FFS}" --dry-run --size $((tf * FSIZE)) "${IMG}" \
	    > "${TMP}/dry.out" 2> "${TMP}/dry.err" ||
		fail "dry-run +1 frag failed"
	assert_contains "${TMP}/dry.out" "target=$((tf * FSIZE)) "
	assert_contains "${TMP}/dry.out" "ncg=10->10"
	assert_image_unchanged

	"${RESIZE_FFS}" --check-invariants --verbose --size $((tf * FSIZE)) \
	    --journal "${TMP}/grow.journal" "${IMG}" \
	    > "${TMP}/grow.out" 2> "${TMP}/grow.err" ||
		fail "grow by one frag failed: $(cat "${TMP}/grow.err")"
	assert_contains "${TMP}/grow.out" "new_size=$((tf * FSIZE))"
	if grep -Eq "inode-remap|cannot be allocated" "${TMP}/grow.err"; then
		cat "${TMP}/grow.err" >&2
		fail "grow by one frag planned a shrink"
	fi
	check_fs_state $((tf * FSIZE)) "${TMP}/ref.cksum"
	check_dsize
	attach_vnd
	[ "$(fs_field /dev/r${VND}c ncg)" -eq 10 ] || fail "expected 10 cgs"
	detach_vnd

	"${RESIZE_FFS}" --check-invariants --revert \
	    --journal "${TMP}/grow.journal" "${IMG}" \
	    > "${TMP}/revert.out" 2> "${TMP}/revert.err" ||
		fail "revert failed: $(cat "${TMP}/revert.err")"
	check_fs_state ${OLD_BYTES} "${TMP}/ref.cksum"
}

# Optional: grow a copy of a legacy FFS1 image (one made by an older
# newfs, with cluster summaries, contigsumsize > 0), given in
# LEGACY_FFS_IMAGE, to twice its cg count and to a partial cg.
run_legacy_image_grow()
{
	src=${LEGACY_FFS_IMAGE:-}

	[ -n "${src}" ] && [ -f "${src}" ] ||
		fail "LEGACY_FFS_IMAGE not set"
	for kind in whole partial; do
		setup_tmp
		cp "${src}" "${IMG}" || fail "copy legacy image failed"
		attach_vnd
		load_geom
		${MOUNT} -r /dev/${VND}c "${MNT}" >/dev/null ||
			fail "mount legacy image failed"
		checksum_tree "${MNT}" "${TMP}/ref.cksum"
		umount_img
		detach_vnd
		tf=$((2 * NCG * FPG))
		[ ${kind} = partial ] && tf=$((tf + $(cg_meta_frags $((2 * NCG))) / 2))
		grow_container_sectors $((tf * FSIZE / 512 + 3))
		grow_and_check ${tf}
		cleanup
		TMP=
	done
}

main()
{
	testcase=${1:-}

	[ "$(id -u)" -eq 0 ] || fail "must be run as root"
	[ -n "${testcase}" ] || fail "missing test name"
	find_resize_ffs

	trap cleanup EXIT INT TERM HUP

	case "${testcase}" in
	grow-journal)
		run_grow_journal
		;;
	shrink-relocate-ffs1)
		run_shrink_relocate 1
		;;
	shrink-relocate-ffs2)
		run_shrink_relocate 2
		;;
	shrink-moves-parent-first)
		run_shrink_moves_parent_first
		;;
	shrink-ffs2-initediblk)
		run_shrink_ffs2_initediblk
		;;
	shrink-symlink-maxlen-ffs1)
		run_shrink_symlink_maxlen 1
		;;
	shrink-symlink-maxlen-ffs2)
		run_shrink_symlink_maxlen 2
		;;
	shrink-moves-checked)
		run_shrink_moves_checked
		;;
	shrink-moves-incomplete-ffs1)
		run_shrink_moves_incomplete 1
		;;
	shrink-moves-incomplete-ffs2)
		run_shrink_moves_incomplete 2
		;;
	shrink-ffs2-extattr)
		run_shrink_ffs2_extattr
		;;
	shrink-move-dry-run)
		run_shrink_move_dry_run
		;;
	push-forward-shrink-fails)
		run_push_forward_shrink_fails
		;;
	shrink-refused-ffs1)
		run_shrink_refused 1
		;;
	shrink-refused-ffs2)
		run_shrink_refused 2
		;;
	parse-overflow-fails)
		run_parse_overflow_fails
		;;
	truncated-journal-fails)
		run_truncated_journal_fails
		;;
	grow-ffs1-partial-cg)
		run_grow_partial_cg 1
		;;
	grow-ffs2-partial-cg)
		run_grow_partial_cg 2
		;;
	grow-header-only-cg)
		run_grow_header_only_cg
		;;
	grow-partial-cg-kept)
		run_grow_partial_cg_kept
		;;
	grow-whole-cgs)
		run_grow_whole_cgs
		;;
	grow-default-size)
		run_grow_default_size
		;;
	grow-dry-run-geometry)
		run_grow_dry_run_geometry
		;;
	unaligned-size-fails)
		run_unaligned_size_fails
		;;
	grow-no-gain-fails)
		run_grow_no_gain_fails
		;;
	noop-default-size-ffs1)
		run_noop_default_size 1
		;;
	noop-default-size-ffs2)
		run_noop_default_size 2
		;;
	noop-same-size-ffs1)
		run_noop_same_size 1
		;;
	noop-same-size-ffs2)
		run_noop_same_size 2
		;;
	grow-one-frag-ffs1)
		run_grow_one_frag 1
		;;
	grow-one-frag-ffs2)
		run_grow_one_frag 2
		;;
	legacy-image-grow)
		run_legacy_image_grow
		;;
	*)
		fail "unknown test case: ${testcase}"
		;;
	esac
}

main "$@"
