package auth

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
)

// This file vendors the reference's browser assets and records where they came
// from.
//
// Until 0.9.0 this port served its own hand-written UI: an 18 KB auth.js and
// two HTML pages someone wrote by reading the reference rather than copying it.
// That was a standing bet that a re-implementation would stay in step with a
// tree it shared no bytes with, and the bet had already been lost once: the
// hand-written SDK called three routes — /auth/totp/setup, /auth/email/verify
// and /auth/metadata — that no adapter has ever mounted (the post-mortem is at
// the route-coverage check in ui_upstream_test.go). Every later divergence
// would have been just as silent, because nothing compared the two.
//
// So since 0.9.0 the assets are copies, and since v1.0.0 the copies are the
// whole of ui/. The reference's own files, at the revision this port targets,
// with a sha256 table and a test that re-hashes them on every `go test ./...`.
// The port cannot drift from the family's UI any more, because it no longer
// has a UI of its own to drift with; it has the family's.
//
// # Why the provenance is beside the bytes rather than in them
//
// Vendored files normally carry a "generated, do not edit" banner, and most of
// these formats would take one — HTML and CSS have comments, and so does JS.
// But a banner is bytes, and these files are pinned by their sha256 precisely
// so that they can be compared against the upstream blob. A file carrying a
// header this repository added is no longer byte for byte what the reference
// ships, and the drift check's first act would be to report all fourteen as
// differing from upstream. (ui-i18n-keys.json settles it on its own: JSON has
// no comment syntax at all, so a banner there would have to be a fake key,
// which every consumer of the file would then see.)
//
// The conflict is real and it is resolved in one direction: the bytes win. The
// provenance lives beside them instead —
//
//   - upstreamUIAssetTable below, one entry per file, naming the upstream path;
//   - ui/upstream/README.md, in the directory itself, which is what a person
//     browsing the tree reads before they touch anything;
//   - the drift test's failure message, which names the file, the expected
//     hash, and the exact `git cat-file` line that restores it — and which is
//     where someone who edited an asset in place actually ends up.
//
// An edit in place is the failure mode this whole design exists to prevent, so
// it is guarded by the thing that runs, not by a comment that can be read past.

// UpstreamUIAssetCommit is the full object name of the awesome-node-auth commit
// the files under ui/upstream/assets were taken from.
//
// ReferenceRevision in compatibility.go abbreviates the same commit and is what
// the deviation register's citations resolve against; this constant spells it
// out because the re-vendoring recipe in the README needs a full object name,
// and because an abbreviation cannot be pasted into `git cat-file` with any
// guarantee that it still resolves uniquely in a tree that has grown since.
// TestVendoredUIAssetsAgreeWithReferenceRevision holds the two together.
const UpstreamUIAssetCommit = "cc01e9975fe9e425dc6d938a9c5d0738b59c79d8"

// UpstreamUIAssetDir is the directory in the reference tree the assets were
// copied from, so that a reader can find the originals without already knowing
// the reference's layout.
const UpstreamUIAssetDir = "src/ui/assets"

// upstreamUIAssetRoot is where the copies live in this module. It is also the
// //go:embed pattern below, and the two must stay the same string: the drift
// check walks the embedded tree from here in order to notice files that were
// added to the directory without being added to the table.
const upstreamUIAssetRoot = "ui/upstream/assets"

// The whole directory is embedded, not a list of names. A pattern naming each
// file individually would make an added asset invisible to the drift check — it
// would not be embedded, so the walk would never see it, and the table would
// still agree with the (unchanged) embedded set. Embedding the directory means
// anything dropped in there shows up and has to be declared.
//
//go:embed ui/upstream/assets
var upstreamUIFS embed.FS

// UpstreamUIAsset is one vendored file and the provenance that makes it
// checkable: where it came from, and what it has to hash to.
type UpstreamUIAsset struct {
	// Name is the file's base name, which is both its name upstream and its
	// name under ui/upstream/assets.
	Name string `json:"name"`
	// UpstreamPath is the path in the reference tree, relative to that tree's
	// root, so the value carries enough to locate the original on its own.
	UpstreamPath string `json:"upstreamPath"`
	// Commit is UpstreamUIAssetCommit, carried per entry so that a caller which
	// serialises this table ships the revision the hashes belong to.
	Commit string `json:"commit"`
	// Size is the file's length in bytes.
	Size int `json:"size"`
	// SHA256 is the lowercase hex sha256 of the file's contents — of the LF
	// bytes the reference publishes, which is what `git cat-file blob` emits
	// and what the .gitattributes entry for these paths keeps on disk.
	SHA256 string `json:"sha256"`
}

// upstreamUIAssetCount is how many files are vendored, pinned separately from
// the table so that a change to the set has to be a change to a stated number
// rather than an unremarked edit inside a long literal.
const upstreamUIAssetCount = 14

// upstreamUIAssetTable is the SHA table: the bytes this port claims to be
// shipping, recorded independently of the bytes on disk so that the drift check
// has two things to compare rather than one thing to agree with itself.
//
// These values were computed from the upstream blobs, never from a checkout.
// See ui/upstream/README.md for why that distinction is the whole ballgame.
var upstreamUIAssetTable = []UpstreamUIAsset{
	{Name: "2fa.html", Size: 4769, SHA256: "fa12f865cf56326ec1951ed50ae06081e132809844ecb6a9ec24bd36b98e48f7"},
	{Name: "account-conflict.html", Size: 4363, SHA256: "b034c276c4494e25be52e454d8afee7ff10c7f9ec22c20deeec31b1546ef75e9"},
	{Name: "admin.css", Size: 10736, SHA256: "195b113c5f3c64119d9d79977a6790d9bd624d4b4d53ee61b991fb2a99702a9d"},
	{Name: "admin.js", Size: 105681, SHA256: "a96b7b3ad5a09ad2e7ecfc03ed4a8b76fdfa60191f85237928e226891147f401"},
	{Name: "auth.js", Size: 31277, SHA256: "ccc707ae777d5625150dca819bd7d1d15ade0db439e7329011d312e231d6698f"},
	{Name: "base.css", Size: 4150, SHA256: "7bd04180d2f24d73f8e0eb7062cd9f20bcbc8589177088c3e85960ca9807b11e"},
	{Name: "forgot-password.html", Size: 3912, SHA256: "d53cd0be448796737bb1b545316c7836a0fb06021a29aba0c50ede2646489443"},
	{Name: "link-verify.html", Size: 2674, SHA256: "79b267dcb52284fe12afed87d272646ad2c9fa15f1821244d4f4ff3e461726bc"},
	{Name: "login.html", Size: 7064, SHA256: "f22f3a3df2f06e8ee9490cbbb6479eaec89b2b34fe2c12d2bec99a54943fd85b"},
	{Name: "magic-link.html", Size: 4634, SHA256: "a38507a3baf17b8ac0f7642ef61ec63bdc21d00603455f2a336c537ee59efa41"},
	{Name: "register.html", Size: 4777, SHA256: "2180099418acde4f8297ba8b62c5a29ef0f3ef05a34b1ae953c77473691abe68"},
	{Name: "reset-password.html", Size: 4090, SHA256: "8a6a207bbf14c64a0137ce39bf7957e4a5a54559f963722bab0c7fbe98027a25"},
	{Name: "ui-i18n-keys.json", Size: 1659, SHA256: "85c7465bad486d9d77d942d5e1c969a268f344dfcb28f9d95233f37e1a542af2"},
	{Name: "verify-email.html", Size: 2321, SHA256: "316993628ddc66458eda50b854fa143c5e34f72225044803b16f95c33bc34060"},
}

// UpstreamUIAssets returns the provenance table: every vendored asset, where it
// came from, and what it hashes to.
//
// The result is freshly built on every call and shares nothing with the
// package, so a caller may sort, filter or edit it without affecting anyone
// else's view. UpstreamPath and Commit are filled in here rather than repeated
// on all fourteen rows of the literal above, because they are the same for
// every entry and a repeated constant is a constant that can be got wrong once.
func UpstreamUIAssets() []UpstreamUIAsset {
	out := make([]UpstreamUIAsset, len(upstreamUIAssetTable))
	for i, a := range upstreamUIAssetTable {
		a.UpstreamPath = UpstreamUIAssetDir + "/" + a.Name
		a.Commit = UpstreamUIAssetCommit
		out[i] = a
	}
	return out
}

// UpstreamUIAssetFS returns the vendored assets as a filesystem rooted at the
// asset directory, so that a caller opens "login.html" rather than the whole
// embedded path.
//
// This is the seam U11 mounts. Serving these files is deliberately not part of
// the change that vendors them, so that the bytes and their provenance can be
// reviewed on their own before anything depends on them being served.
func UpstreamUIAssetFS() fs.FS {
	sub, err := fs.Sub(upstreamUIFS, upstreamUIAssetRoot)
	if err != nil {
		// Unreachable: the argument is a constant and the directory is embedded
		// at build time, so a failure here means the embed pattern and
		// upstreamUIAssetRoot have been edited apart. That is a programming
		// error, and it must not be handed back as if it were a runtime
		// condition a caller could do anything about.
		panic("auth: vendored UI asset root is not a directory: " + err.Error())
	}
	return sub
}

// ReadUpstreamUIAsset returns the contents of one vendored asset by base name,
// for example "auth.js" or "login.html".
//
// The returned slice is a copy. embed.FS hands out the backing array of the
// embedded data itself, so a caller that wrote through an uncopied slice would
// corrupt the asset for every later reader in the process — including the drift
// check, which would then report a difference nobody made on disk.
func ReadUpstreamUIAsset(name string) ([]byte, error) {
	data, err := upstreamUIFS.ReadFile(upstreamUIAssetRoot + "/" + name)
	if err != nil {
		return nil, fmt.Errorf("auth: no vendored UI asset %q: %w", name, err)
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

// sha256Hex is the hash the table records, in the form it records it.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
