#!/bin/bash

set -u

die() { echo "Error: $*" >&2; exit 1; }

# Ensure the script is run as root
[ "$EUID" -eq 0 ] || die "Run as root."

ACTION=${1:-}
SIZE_MB=${2:-}
PARENT_DIR=${3:-/mnt} # Defaults to /mnt if the 3rd argument is empty
FILE_NAME=${4:-ublk_shmem_buf} # Name of the shared buffer file inside the mount

usage() {
  echo "Usage: $0 [alloc|free] [size_in_MB] [parent_dir] [file_name]"
  echo
  echo "  alloc N            mount hugetlbfs of size N MB and create an N MB"
  echo "                     hugetlbfs-backed file inside it. Multiple"
  echo "                     processes can mmap the file to share huge pages."
  echo "  free  N            remove the file, unmount, and release the pool."
  echo
  echo "Example: $0 alloc 128                            # /mnt/huge_128/ublk_shmem_buf"
  echo "Example: $0 alloc 128 /custom/dir                # /custom/dir/huge_128/ublk_shmem_buf"
  echo "Example: $0 alloc 128 /mnt my_buf                # /mnt/huge_128/my_buf"
  exit 1
}

# Validate required inputs
[[ "$ACTION" == "alloc" || "$ACTION" == "free" ]] || usage
[[ "$SIZE_MB" =~ ^[1-9][0-9]*$ ]] || usage

# Detect the running kernel's default huge page size (in MB).
PAGE_KB=$(awk '/^Hugepagesize:/ {print $2}' /proc/meminfo)
[ -n "$PAGE_KB" ] && [ "$PAGE_KB" -gt 0 ] || die "cannot read Hugepagesize from /proc/meminfo"
PAGE_MB=$((PAGE_KB / 1024))
[ "$PAGE_MB" -gt 0 ] || die "Hugepagesize ${PAGE_KB}kB < 1MB, unsupported"
(( SIZE_MB % PAGE_MB == 0 )) || die "size ${SIZE_MB}MB must be a multiple of hugepage size ${PAGE_MB}MB"

# Clean up trailing slashes and set final mount + file paths
PARENT_DIR="${PARENT_DIR%/}"
MOUNT_PATH="${PARENT_DIR}/huge_${SIZE_MB}"
FILE_PATH="${MOUNT_PATH}/${FILE_NAME}"

if [ "$ACTION" == "alloc" ]; then
  PAGES=$((SIZE_MB / PAGE_MB))

  echo "Allocating ${SIZE_MB}MB (${PAGES} x ${PAGE_MB}MB HugePages)..."
  echo $PAGES > /proc/sys/vm/nr_hugepages || die "cannot write /proc/sys/vm/nr_hugepages"

  # Kernel may grant fewer pages under fragmentation/pressure; check.
  GOT=$(cat /proc/sys/vm/nr_hugepages)
  [ "$GOT" -ge "$PAGES" ] || die "kernel only granted $GOT/$PAGES hugepages (memory fragmented?)"

  mkdir -p "$MOUNT_PATH" || die "mkdir $MOUNT_PATH failed"

  if ! mountpoint -q "$MOUNT_PATH"; then
    mount -t hugetlbfs -o size=${SIZE_MB}M none "$MOUNT_PATH" \
      || die "mount hugetlbfs at $MOUNT_PATH failed"
  fi

  # Create the shared hugetlbfs file so producer/consumer processes can
  # mmap it for zero-copy sharing of huge pages. fallocate on hugetlbfs
  # reserves the requested pages from the pool immediately.
  if [ ! -e "$FILE_PATH" ]; then
    fallocate -l ${SIZE_MB}M "$FILE_PATH" || die "fallocate $FILE_PATH failed"
  fi

  echo "Success. File: $FILE_PATH (${SIZE_MB}MB hugetlbfs-backed)"

elif [ "$ACTION" == "free" ]; then
  echo "Freeing HugePages and cleaning up..."

  # Remove the file before unmounting; umount would otherwise fail with
  # EBUSY if any open fd / mmap still references it, and rm releases the
  # pages back to the pool so the kernel will accept nr_hugepages=0.
  rm -f "$FILE_PATH" || die "rm $FILE_PATH failed"

  if mountpoint -q "$MOUNT_PATH"; then
    umount "$MOUNT_PATH" || die "umount $MOUNT_PATH failed (device busy?)"
  fi
  rmdir "$MOUNT_PATH" 2>/dev/null || true

  echo 0 > /proc/sys/vm/nr_hugepages || die "cannot write /proc/sys/vm/nr_hugepages"

  echo "Success. $MOUNT_PATH unmounted and memory freed."
fi
