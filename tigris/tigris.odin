// =============================================================================
// Tigris S3 Object Storage & SHA-256 Manifest Library (`tigris/tigris.odin`)
//
// Standalone Odin package providing:
//   - Native SHA-256 asset manifest generation, formatting, parsing, and diffing
//   - Automatic `TIGRIS_ASSETS_BUCKET` resolution from flags, env, or `.env`/`.env.local`
//   - Programmatic wrappers around the `t3` / `tigris` CLI (`sync`, `pull`, `push`,
//     `status`, `ls`, `object_get`, `object_put`, `cp_recursive`, `rm_object`)
// =============================================================================

package tigris

import "core:crypto/hash"
import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:strings"

Config :: struct {
	bucket:    string   `json:"bucket"`,
	prefix:    string   `json:"prefix"`,
	local_dir: string   `json:"local_dir"`,
	subdirs:   []string `json:"subdirs"`,
}

Manifest_Entry :: struct {
	rel_path: string `json:"rel_path"`,
	sha256:   string `json:"sha256"`,
}

Manifest_Diff :: struct {
	in_sync:          []string `json:"in_sync"`,
	modified:         []string `json:"modified"`,
	missing_locally:  []string `json:"missing_locally"`,
	untracked_remote: []string `json:"untracked_remote"`,
}

Asset_Options :: struct {
	root_dir:     string,
	bucket:       string,
	prefix:       string,
	local_dir:    string,
	subdirs:      []string,
	force:        bool,
	delete_stale: bool,
	dry_run:      bool,
}

Asset_Report :: struct {
	command:          string        `json:"command"`,
	action:           string        `json:"action"`,
	status:           string        `json:"status"`,
	bucket:           string        `json:"bucket"`,
	prefix:           string        `json:"prefix"`,
	local_dir:        string        `json:"local_dir"`,
	dry_run:          bool          `json:"dry_run"`,
	in_sync_count:    int           `json:"in_sync_count"`,
	downloaded_count: int           `json:"downloaded_count"`,
	uploaded_count:   int           `json:"uploaded_count"`,
	deleted_count:    int           `json:"deleted_count"`,
	diff:             Manifest_Diff `json:"diff,omitempty"`,
	objects:          []string      `json:"objects,omitempty"`,
	telemetry_db:     string        `json:"telemetry_db,omitempty"`,
	message:          string        `json:"message,omitempty"`,
}

// Recursively create directories (`mkdir -p` equivalent).
make_directory_all :: proc(dir_path: string) -> os.Error {
	cleaned, _ := filepath.clean(dir_path, context.temp_allocator)
	if len(cleaned) == 0 || cleaned == "." || cleaned == "/" {
		return nil
	}
	if os.exists(cleaned) {
		return nil
	}
	parent := filepath.dir(cleaned)
	if parent != cleaned && parent != "." && parent != "/" {
		make_directory_all(parent) or_return
	}
	err := os.make_directory(cleaned)
	if err == .Exist {
		return nil
	}
	return err
}

// Resolve `TIGRIS_ASSETS_BUCKET` from explicit flag, config, process env,
// or `.env.local` / `.env` in `root_dir`.
resolve_bucket :: proc(root_dir: string, explicit_bucket := "", cfg_bucket := "", default_bucket := "nvestiv-website-assets-dev", allocator := context.temp_allocator) -> string {
	if len(explicit_bucket) > 0 {
		return strings.clone(explicit_bucket, allocator)
	}
	if len(cfg_bucket) > 0 {
		return strings.clone(cfg_bucket, allocator)
	}
	if env_b := os.get_env("TIGRIS_ASSETS_BUCKET", context.temp_allocator); len(env_b) > 0 {
		return strings.clone(env_b, allocator)
	}

	env_files := []string{".env.local", ".env"}
	for ef in env_files {
		ef_path, _ := filepath.join({root_dir, ef}, context.temp_allocator)
		data, rerr := os.read_entire_file(ef_path, context.temp_allocator)
		if rerr != nil do continue

		for raw_line in strings.split_lines(string(data), context.temp_allocator) {
			line := strings.trim_space(raw_line)
			if strings.has_prefix(line, "#") || !strings.has_prefix(line, "TIGRIS_ASSETS_BUCKET") {
				continue
			}
			eq_idx := strings.index_byte(line, '=')
			if eq_idx < 0 do continue
			val := strings.trim(strings.trim_space(line[eq_idx + 1:]), "\"'")
			if len(val) > 0 {
				return strings.clone(val, allocator)
			}
		}
	}

	return strings.clone(default_bucket, allocator)
}

// Compute a sorted local SHA-256 manifest (`[]Manifest_Entry`) for all files under
// `base_dir` (or specific `subdirs` inside `base_dir`).
build_local_manifest :: proc(
	base_dir: string,
	subdirs: []string = nil,
	allocator := context.temp_allocator,
) -> []Manifest_Entry {
	context.allocator = allocator
	entries := make([dynamic]Manifest_Entry, allocator)

	if !os.exists(base_dir) {
		return entries[:]
	}

	abs_base, abs_err := filepath.abs(base_dir, allocator)
	if abs_err != nil {
		abs_base = base_dir
	}

	search_roots := make([dynamic]string, allocator)
	if len(subdirs) > 0 {
		for sd in subdirs {
			sd_path, _ := filepath.join({abs_base, sd}, allocator)
			if os.exists(sd_path) {
				append(&search_roots, sd_path)
			}
		}
	} else {
		default_brand := []string{"backgrounds", "fonts", "logos"}
		found_brand := false
		for sd in default_brand {
			sd_path, _ := filepath.join({abs_base, sd}, allocator)
			if os.exists(sd_path) {
				append(&search_roots, sd_path)
				found_brand = true
			}
		}
		if !found_brand {
			append(&search_roots, abs_base)
		}
	}

	for sroot in search_roots {
		w := filepath.walker_create(sroot)
		defer filepath.walker_destroy(&w)

		for info in filepath.walker_walk(&w) {
			if _, werr := filepath.walker_error(&w); werr != nil do continue
			if info.type != .Regular do continue
			if info.name == "manifest.sha256" || strings.has_prefix(info.name, ".") do continue

			rel_raw, rel_err := filepath.rel(abs_base, info.fullpath, allocator)
			if rel_err != .None do continue
			rel_norm, _ := filepath.replace_separators(rel_raw, '/', allocator)

			file_bytes, rerr := os.read_entire_file(info.fullpath, context.temp_allocator)
			if rerr != nil do continue

			digest := hash.hash_bytes(.SHA256, file_bytes, context.temp_allocator)
			hex_bytes := hex.encode(digest, allocator)

			append(&entries, Manifest_Entry{
				rel_path = strings.clone(rel_norm, allocator),
				sha256   = string(hex_bytes),
			})
		}
	}

	slice.sort_by(entries[:], proc(a, b: Manifest_Entry) -> bool {
		return a.rel_path < b.rel_path
	})

	return entries[:]
}

// Format `[]Manifest_Entry` into standard `<sha256>  <rel_path>\n` text format.
format_manifest :: proc(entries: []Manifest_Entry, allocator := context.temp_allocator) -> string {
	sb := strings.builder_make(allocator)
	for e in entries {
		fmt.sbprintf(&sb, "%s  %s\n", e.sha256, e.rel_path)
	}
	return strings.to_string(sb)
}

// Parse a `<sha256>  <rel_path>` manifest string into `[]Manifest_Entry`.
parse_manifest :: proc(raw_manifest: string, allocator := context.temp_allocator) -> []Manifest_Entry {
	entries := make([dynamic]Manifest_Entry, allocator)
	for raw_line in strings.split_lines(raw_manifest, context.temp_allocator) {
		line := strings.trim_space(raw_line)
		if len(line) < 66 do continue
		sha := line[:64]
		rel := strings.trim_space(line[64:])
		if len(rel) == 0 do continue
		append(&entries, Manifest_Entry{
			rel_path = strings.clone(rel, allocator),
			sha256   = strings.clone(sha, allocator),
		})
	}
	return entries[:]
}

// Compare local manifest entries against remote manifest entries.
diff_manifests :: proc(
	local_entries: []Manifest_Entry,
	remote_entries: []Manifest_Entry,
	allocator := context.temp_allocator,
) -> Manifest_Diff {
	local_map  := make(map[string]string, context.temp_allocator)
	remote_map := make(map[string]string, context.temp_allocator)

	for e in local_entries {
		local_map[e.rel_path] = e.sha256
	}
	for e in remote_entries {
		remote_map[e.rel_path] = e.sha256
	}

	in_sync   := make([dynamic]string, allocator)
	modified  := make([dynamic]string, allocator)
	missing   := make([dynamic]string, allocator)
	untracked := make([dynamic]string, allocator)

	for r in remote_entries {
		l_sha, exists_locally := local_map[r.rel_path]
		if !exists_locally {
			append(&missing, strings.clone(r.rel_path, allocator))
		} else if l_sha == r.sha256 {
			append(&in_sync, strings.clone(r.rel_path, allocator))
		} else {
			append(&modified, strings.clone(r.rel_path, allocator))
		}
	}

	for l in local_entries {
		if _, exists_remotely := remote_map[l.rel_path]; !exists_remotely {
			append(&untracked, strings.clone(l.rel_path, allocator))
		}
	}

	return Manifest_Diff{
		in_sync          = in_sync[:],
		modified         = modified[:],
		missing_locally  = missing[:],
		untracked_remote = untracked[:],
	}
}

// Execute a `t3` (or `tigris`) CLI subcommand.
exec_t3 :: proc(args: []string, work_dir := ".", allocator := context.temp_allocator) -> (stdout_str: string, stderr_str: string, ok: bool) {
	cmd := make([dynamic]string, 0, len(args) + 1, context.temp_allocator)
	append(&cmd, "t3")
	for a in args {
		append(&cmd, a)
	}

	state, stdout, stderr, err := os.process_exec(
		os.Process_Desc{
			working_dir = work_dir,
			command     = cmd[:],
		},
		context.temp_allocator,
	)
	if err != nil {
		cmd[0] = "tigris"
		state, stdout, stderr, err = os.process_exec(
			os.Process_Desc{
				working_dir = work_dir,
				command     = cmd[:],
			},
			context.temp_allocator,
		)
		if err != nil {
			return "", fmt.aprintf("failed to execute 't3' or 'tigris' CLI: %v", err, allocator = allocator), false
		}
	}

	out_s := strings.clone(strings.trim_space(string(stdout)), allocator)
	err_s := strings.clone(strings.trim_space(string(stderr)), allocator)
	return out_s, err_s, state.success && state.exit_code == 0
}

// Fetch and parse `t3://<bucket>/<prefix>/manifest.sha256`.
fetch_remote_manifest :: proc(bucket: string, prefix: string, allocator := context.temp_allocator) -> (entries: []Manifest_Entry, ok: bool) {
	tmp_file, terr := os.create_temp_file("", "tigris_remote_manifest_*.sha256")
	if terr != nil {
		return nil, false
	}
	tmp_path := strings.clone(os.name(tmp_file), context.temp_allocator)
	_ = os.close(tmp_file)
	defer _ = os.remove(tmp_path)

	key := len(prefix) > 0 ? fmt.tprintf("%s/manifest.sha256", strings.trim(prefix, "/")) : "manifest.sha256"
	_, _, get_ok := exec_t3({"objects", "get", bucket, key, "--output", tmp_path}, ".", context.temp_allocator)
	if !get_ok {
		return nil, false
	}

	data, rerr := os.read_entire_file(tmp_path, context.temp_allocator)
	if rerr != nil || len(data) == 0 {
		return nil, false
	}

	return parse_manifest(string(data), allocator), true
}

// Run a Tigris asset command (`status`, `sync`, `pull`, `push`, `ls`).
run_assets :: proc(
	action: string,
	opts: Asset_Options,
	allocator := context.temp_allocator,
) -> (
	report: Asset_Report,
	ok: bool,
) {
	context.allocator = allocator

	root_dir  := len(opts.root_dir) > 0 ? opts.root_dir : "."
	bucket    := resolve_bucket(root_dir, opts.bucket, "", "nvestiv-website-assets-dev", allocator)
	prefix    := len(opts.prefix) > 0 ? strings.trim(opts.prefix, "/") : "brand"
	rel_local := len(opts.local_dir) > 0 ? opts.local_dir : "static/brand"
	local_dir, _ := filepath.join({root_dir, rel_local}, allocator)

	report = Asset_Report{
		command   = "assets",
		action    = action,
		status    = "ok",
		bucket    = bucket,
		prefix    = prefix,
		local_dir = local_dir,
		dry_run   = opts.dry_run,
	}

	switch action {
	case "ls":
		pref_arg := fmt.tprintf("%s/", prefix)
		stdout, stderr, ls_ok := exec_t3({"objects", "list", bucket, "--prefix", pref_arg}, root_dir, allocator)
		if !ls_ok {
			report.status  = "failed"
			report.message = len(stderr) > 0 ? stderr : "Failed to list objects via t3 CLI"
			return report, false
		}
		objs := make([dynamic]string, allocator)
		for line in strings.split_lines(stdout, allocator) {
			trimmed := strings.trim_space(line)
			if len(trimmed) > 0 {
				append(&objs, trimmed)
			}
		}
		report.objects = objs[:]
		return report, true

	case "status":
		local_mf := build_local_manifest(local_dir, opts.subdirs, allocator)
		remote_mf, rem_ok := fetch_remote_manifest(bucket, prefix, allocator)
		if !rem_ok {
			report.status  = "failed"
			report.message = fmt.aprintf("No remote manifest found at t3://%s/%s/manifest.sha256", bucket, prefix, allocator = allocator)
			return report, false
		}

		diff := diff_manifests(local_mf, remote_mf, allocator)
		report.diff          = diff
		report.in_sync_count = len(diff.in_sync)
		return report, true

	case "sync", "pull":
		_ = make_directory_all(local_dir)
		local_mf := build_local_manifest(local_dir, opts.subdirs, allocator)
		remote_mf, rem_ok := fetch_remote_manifest(bucket, prefix, allocator)

		if !opts.force && rem_ok {
			diff := diff_manifests(local_mf, remote_mf, allocator)
			report.diff          = diff
			report.in_sync_count = len(diff.in_sync)

			to_dl := make([dynamic]string, allocator)
			for m in diff.modified        do append(&to_dl, m)
			for m in diff.missing_locally do append(&to_dl, m)

			for rel in to_dl {
				if !opts.dry_run {
					dst_file, _ := filepath.join({local_dir, rel}, context.temp_allocator)
					_ = make_directory_all(filepath.dir(dst_file))
					r_key := fmt.tprintf("%s/%s", prefix, rel)
					_, stderr, dl_ok := exec_t3({"objects", "get", bucket, r_key, "--output", dst_file}, root_dir, allocator)
					if !dl_ok {
						report.status  = "failed"
						report.message = fmt.aprintf("Failed to download %s: %s", r_key, stderr, allocator = allocator)
						return report, false
					}
				}
				report.downloaded_count += 1
			}

			if opts.delete_stale {
				for rel in diff.untracked_remote {
					if !opts.dry_run {
						stale_path, _ := filepath.join({local_dir, rel}, context.temp_allocator)
						_ = os.remove(stale_path)
					}
					report.deleted_count += 1
				}
			}

			return report, true
		}

		subdirs := len(opts.subdirs) > 0 ? opts.subdirs : []string{"backgrounds", "fonts", "logos"}
		for sd in subdirs {
			if !opts.dry_run {
				remote_uri := fmt.tprintf("t3://%s/%s/%s", bucket, prefix, sd)
				_, stderr, cp_ok := exec_t3({"cp", "-r", remote_uri, fmt.tprintf("%s/", strings.trim_right(local_dir, "/"))}, root_dir, allocator)
				if !cp_ok {
					report.status  = "failed"
					report.message = fmt.aprintf("Failed to pull %s: %s", remote_uri, stderr, allocator = allocator)
					return report, false
				}
			}
			report.downloaded_count += 1
		}
		return report, true

	case "push":
		local_mf := build_local_manifest(local_dir, opts.subdirs, allocator)
		remote_mf, rem_ok := fetch_remote_manifest(bucket, prefix, allocator)

		diff := diff_manifests(local_mf, remote_mf, allocator)
		report.diff          = diff
		report.in_sync_count = opts.force ? 0 : len(diff.in_sync)

		to_up := make([dynamic]string, allocator)
		if opts.force || !rem_ok {
			for e in local_mf do append(&to_up, e.rel_path)
		} else {
			for m in diff.modified         do append(&to_up, m)
			for u in diff.untracked_remote do append(&to_up, u)
		}

		for rel in to_up {
			if !opts.dry_run {
				src_file, _ := filepath.join({local_dir, rel}, context.temp_allocator)
				r_key       := fmt.tprintf("%s/%s", prefix, rel)
				_, stderr, up_ok := exec_t3({"objects", "put", bucket, r_key, src_file}, root_dir, allocator)
				if !up_ok {
					report.status  = "failed"
					report.message = fmt.aprintf("Failed to upload %s: %s", r_key, stderr, allocator = allocator)
					return report, false
				}
			}
			report.uploaded_count += 1
		}

		if opts.delete_stale && rem_ok {
			for rel in diff.missing_locally {
				if !opts.dry_run {
					rem_uri := fmt.tprintf("t3://%s/%s/%s", bucket, prefix, rel)
					_, _, _ = exec_t3({"rm", "-y", rem_uri}, root_dir, allocator)
				}
				report.deleted_count += 1
			}
		}

		if !opts.dry_run && (report.uploaded_count > 0 || report.deleted_count > 0 || !rem_ok) {
			mf_text := format_manifest(local_mf, context.temp_allocator)
			tmp_mf, terr := os.create_temp_file("", "tigris_local_manifest_*.sha256")
			if terr == nil {
				tmp_mf_path := strings.clone(os.name(tmp_mf), context.temp_allocator)
				_, _ = os.write_string(tmp_mf, mf_text)
				_ = os.close(tmp_mf)
				defer _ = os.remove(tmp_mf_path)

				mf_key := fmt.tprintf("%s/manifest.sha256", prefix)
				_, _, _ = exec_t3({"objects", "put", bucket, mf_key, tmp_mf_path}, root_dir, allocator)
			}
		}

		return report, true

	case:
		report.status  = "failed"
		report.message = fmt.aprintf("Unknown assets action %q (expected sync, pull, push, status, or ls)", action, allocator = allocator)
		return report, false
	}
}
