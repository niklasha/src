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

find_resize_ffs()
{
	if [ -n "${RESIZE_FFS}" ] && [ -x "${RESIZE_FFS}" ]; then
		return
	fi
	if [ -n "${OBJDIR:-}" ] &&
	    [ -x "${OBJDIR}/../../../usr.sbin/resize_ffs/resize_ffs" ]; then
		RESIZE_FFS="${OBJDIR}/../../../usr.sbin/resize_ffs/resize_ffs"
		return
	fi
	if [ -n "${SRCDIR:-}" ] &&
	    [ -x "${SRCDIR}/../../../usr.sbin/resize_ffs/resize_ffs" ]; then
		RESIZE_FFS="${SRCDIR}/../../../usr.sbin/resize_ffs/resize_ffs"
		return
	fi
	RESIZE_FFS=/usr/sbin/resize_ffs
	[ -x "${RESIZE_FFS}" ] || fail "resize_ffs binary not found"
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

create_image()
{
	size_mb=$1

	rm -f "${IMG}"
	dd if=/dev/zero of="${IMG}" bs=1m count=0 seek="${size_mb}" \
	    status=none || fail "dd create image failed"
	attach_vnd
	${NEWFS} -q /dev/r${VND}c >/dev/null || fail "newfs failed"
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

fs_bytes()
{
	${DUMPFS} /dev/r${VND}c | awk '
		/^ncg/ { size = $4 }
		/^fsize/ { fsize = $2 }
		END { print size * fsize }
	'
}

check_fs_state()
{
	expect_bytes=$1
	expect_cksum=$2
	actual_cksum=${TMP}/mounted.cksum
	actual_bytes=

	attach_vnd
	${FSCK_FFS} -fn /dev/r${VND}c >/dev/null ||
		fail "fsck_ffs reported damage"
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

run_shrink_relocate()
{
	setup_tmp
	create_image 32
	make_shrink_fixture

	"${RESIZE_FFS}" --verbose --check-invariants --size 16m \
	    --journal "${TMP}/shrink.journal" "${IMG}" \
	    > "${TMP}/shrink.out" 2> "${TMP}/shrink.err" ||
		fail "shrink resize failed"
	assert_contains "${TMP}/shrink.err" "auto-plan: generated"
	assert_contains "${TMP}/shrink.err" "phase: relocating ("
	check_fs_state 16777216 "${TMP}/ref.cksum"

	"${RESIZE_FFS}" --check-invariants --revert \
	    --journal "${TMP}/shrink.journal" "${IMG}" \
	    > "${TMP}/revert.out" 2> "${TMP}/revert.err" ||
		fail "shrink revert failed"
	check_fs_state 33554432 "${TMP}/ref.cksum"
}

run_shrink_move_dry_run()
{
	setup_tmp
	create_image 32

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
	shrink-relocate)
		run_shrink_relocate
		;;
	shrink-move-dry-run)
		run_shrink_move_dry_run
		;;
	push-forward-shrink-fails)
		run_push_forward_shrink_fails
		;;
	parse-overflow-fails)
		run_parse_overflow_fails
		;;
	truncated-journal-fails)
		run_truncated_journal_fails
		;;
	*)
		fail "unknown test case: ${testcase}"
		;;
	esac
}

main "$@"
