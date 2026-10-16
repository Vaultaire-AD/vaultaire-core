package paquet

// Le vecteur de référence du format signé — TO-DO 113.
//
// LE MÊME FICHIER, octet pour octet sous ses constantes, vit dans
// vaultaire_serveur/core/paquetagent et dans vaultaire_client/paquet. Le core
// signe, l'agent vérifie : si l'un change la composition du manifeste,
// l'enveloppe ou l'empreinte de clé sans l'autre, sa suite ne vérifie plus
// cette signature, et la divergence se voit ici plutôt que sur un parc qui
// refuse toutes ses mises à jour.
//
// La clé est une clé de TEST (3072 bits), sans autre usage ; sa partie privée
// n'a pas été conservée. Pour refaire le vecteur, il faut en tirer une autre
// et remplacer les trois constantes dans les deux fichiers.

const corpsReference = "" +
	"vaultaire-pkg-v1\n" +
	"2.3.0\n" +
	"linux-amd64-rocky\n" +
	"vaultaire_client 0000000000000000000000000000000000000000000000000000000000000001\n" +
	"pam_login_custom_module.so 0000000000000000000000000000000000000000000000000000000000000002\n" +
	"pam_logout_custom_module.so 0000000000000000000000000000000000000000000000000000000000000003\n" +
	"pam_ssh_auth_module.so 0000000000000000000000000000000000000000000000000000000000000004\n" +
	"libnss_vaultaire.so.2 0000000000000000000000000000000000000000000000000000000000000005\n"

const clePubliqueReference = "" +
	"-----BEGIN RSA PUBLIC KEY-----\n" +
	"MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsZWa2pUCDaUu1/X3SVd+\n" +
	"/LdivwNK0tAb7xx89vLwXZQoKiBpEoP49u8cFHFeLfpmY7EWQttjKN5BJrX3u+0w\n" +
	"SfOrNrjaKXdBOKCHvdjvdokSclt/iKEdpkO/AGbYjn5VfcXnxCeFJam2DP9QE/bM\n" +
	"9ogMkdPsWOSPpT3r5P7iH+eZSTiJ8TAvIRjgrzkixlzDqb+99Riqb13epUsp9CXv\n" +
	"efsLVsEJvb8b80ePcW09XW/m7U/6SD+tf8C/9qe683F+PiAD2x5STv1b9FpXTFr4\n" +
	"vM7llNimLxonOPreEsKGBeFoPnyMFlY6gusdP/LMS+najt9KomfGkcrv5fSqADjL\n" +
	"DVNJjR8OYaZ+2cdKOfCVsBs1Z02WVtn7pSfJFLFn883DSt2z6BBWauBHUgb6fQYP\n" +
	"h95WOPt2WIrECXb9dsi0NOqlIK5qeb9fB1YnD6MHDgyxe+n69IMcUqO4/Aca3N06\n" +
	"CCRAe5Vy3BLFMzg4xGbfcDnuIjMb1ei0J0wVy6U9xkeHAgMBAAE=\n" +
	"-----END RSA PUBLIC KEY-----\n"

const empreinteReference = "SHA256:v98kPLzuvDW7sAo7CoKrtwZjM5CGicbKYWslYPwWE/A"

const enveloppeReference = "" +
	"vaultaire-pkg-sig-v1\n" +
	"SHA256:v98kPLzuvDW7sAo7CoKrtwZjM5CGicbKYWslYPwWE/A\n" +
	"B4Y20L1MtgixvNQgHRWV0481bT8IHvbO6nEusJ+tBrt8ODNWmjUHvO3WTdxCn6HlKZNhC/18/s6Dq4GOR87uibf3JEdO2zlM2Fa7TgQIoAnfme6md6EeO0roiMgzfhWh0htZcNhgqxuMs/pfZqQq/MEtWQRPAKRm8lVfpek9qFB9k/g9ewPbqji1/VE9IJ8H1GKwNVwssvnhYL456xN9MQEW657mH60jPqCc0h/g57jB3RZlnsmv7XS+B6lKvjAyg/utgAhkwjOJnzIv6lfE7Ei7VU8hFG4cg0jN/n1WlfbAHYUuouzEVac0yflswENbB/6m9fWz//YTsBIkjyhv7UXRJ3DDkZa/PA6K3OrowT6a7GVi9yq/L7Xs5SazUj32TpIjgcDWt1FhKmAdbn+tY+LF0f6eRVVvnJUmSKEkdGV/A9PZsYbL1icFKDcFxu9YxvdNQb3McfPRpruAMXbzQFhVXZfw48WLGywz0eWSHI4x+WZVCLSyHT8kvQTpfmUL\n"
