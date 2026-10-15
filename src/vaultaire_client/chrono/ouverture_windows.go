//go:build windows

package chrono

// sansLien n'existe pas sous Windows : syscall n'y définit pas O_NOFOLLOW, et
// son absence cassait la compilation de l'agent Windows, qui importe ce paquet
// par pamstate (relevé au TO-DO 195). Le dossier des journaux y est réservé à
// SYSTEM et aux administrateurs.
const sansLien = 0
