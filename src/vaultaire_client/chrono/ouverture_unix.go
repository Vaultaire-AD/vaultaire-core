//go:build !windows

package chrono

import "syscall"

// sansLien : ne pas suivre un lien symbolique posé à la place du journal.
const sansLien = syscall.O_NOFOLLOW
