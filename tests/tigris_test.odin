package tigris_tests

import "core:os"
import "core:path/filepath"
import "core:testing"
import "../tigris"

@(test)
test_manifest_generation_and_diff :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator

	tmp_dir := "/tmp/odin_tigris_test_manifest"
	_ = os.remove_all(tmp_dir)
	defer _ = os.remove_all(tmp_dir)

	bg_dir, _   := filepath.join({tmp_dir, "static", "brand", "backgrounds"}, context.temp_allocator)
	logo_dir, _ := filepath.join({tmp_dir, "static", "brand", "logos"}, context.temp_allocator)
	_ = tigris.make_directory_all(bg_dir)
	_ = tigris.make_directory_all(logo_dir)

	f1, _ := filepath.join({bg_dir, "hero.webp"}, context.temp_allocator)
	f2, _ := filepath.join({logo_dir, "brand.svg"}, context.temp_allocator)
	_ = os.write_entire_file(f1, "webp-binary-bytes-v1")
	_ = os.write_entire_file(f2, "<svg>logo</svg>")

	env_path, _ := filepath.join({tmp_dir, ".env"}, context.temp_allocator)
	_ = os.write_entire_file(env_path, "TIGRIS_ASSETS_BUCKET = \"custom-tigris-bucket\"\n")

	bucket := tigris.resolve_bucket(tmp_dir, "", "", "default-bucket", context.temp_allocator)
	testing.expect_value(t, bucket, "custom-tigris-bucket")

	brand_root, _ := filepath.join({tmp_dir, "static", "brand"}, context.temp_allocator)
	local_entries := tigris.build_local_manifest(brand_root, nil, context.temp_allocator)
	testing.expect_value(t, len(local_entries), 2)
	testing.expect_value(t, local_entries[0].rel_path, "backgrounds/hero.webp")
	testing.expect_value(t, local_entries[1].rel_path, "logos/brand.svg")

	manifest_str := tigris.format_manifest(local_entries, context.temp_allocator)
	parsed_entries := tigris.parse_manifest(manifest_str, context.temp_allocator)
	testing.expect_value(t, len(parsed_entries), 2)

	remote_entries := []tigris.Manifest_Entry{
		{rel_path = "backgrounds/hero.webp", sha256 = "0000000000000000000000000000000000000000000000000000000000000000"},
		{rel_path = "logos/brand.svg", sha256 = local_entries[1].sha256},
		{rel_path = "fonts/inter.woff2", sha256 = "1111111111111111111111111111111111111111111111111111111111111111"},
	}

	diff := tigris.diff_manifests(local_entries, remote_entries, context.temp_allocator)
	testing.expect_value(t, len(diff.in_sync), 1)
	testing.expect_value(t, diff.in_sync[0], "logos/brand.svg")
	testing.expect_value(t, len(diff.modified), 1)
	testing.expect_value(t, diff.modified[0], "backgrounds/hero.webp")
	testing.expect_value(t, len(diff.missing_locally), 1)
	testing.expect_value(t, diff.missing_locally[0], "fonts/inter.woff2")
}

@(test)
test_tigris_assets_e2e_with_fake_t3_cli :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator

	tmp_dir := "/tmp/odin_tigris_test_fake_t3"
	_ = os.remove_all(tmp_dir)
	defer _ = os.remove_all(tmp_dir)

	bin_dir, _         := filepath.join({tmp_dir, "fake_bin"}, context.temp_allocator)
	fake_remote_dir, _ := filepath.join({tmp_dir, "fake_s3"}, context.temp_allocator)
	ws_push, _         := filepath.join({tmp_dir, "ws_push"}, context.temp_allocator)
	ws_pull, _         := filepath.join({tmp_dir, "ws_pull"}, context.temp_allocator)
	_ = tigris.make_directory_all(bin_dir)
	_ = tigris.make_directory_all(fake_remote_dir)
	_ = tigris.make_directory_all(ws_push)
	_ = tigris.make_directory_all(ws_pull)

	fake_t3_path, _ := filepath.join({bin_dir, "t3"}, context.temp_allocator)
	fake_t3_script := `#!/usr/bin/env bash
set -e
STORE="/tmp/odin_tigris_test_fake_t3/fake_s3"
if [ "$1" = "objects" ] && [ "$2" = "put" ]; then
  BUCKET="$3"; KEY="$4"; SRC="$5"
  mkdir -p "$(dirname "$STORE/$BUCKET/$KEY")"
  cp "$SRC" "$STORE/$BUCKET/$KEY"
  exit 0
elif [ "$1" = "objects" ] && [ "$2" = "get" ]; then
  BUCKET="$3"; KEY="$4"; OUT="$6"
  if [ ! -f "$STORE/$BUCKET/$KEY" ]; then exit 1; fi
  mkdir -p "$(dirname "$OUT")"
  cp "$STORE/$BUCKET/$KEY" "$OUT"
  exit 0
elif [ "$1" = "objects" ] && [ "$2" = "list" ]; then
  BUCKET="$3"; PREFIX="$5"
  find "$STORE/$BUCKET/$PREFIX" -type f 2>/dev/null | sed "s|$STORE/$BUCKET/||" | sort
  exit 0
elif [ "$1" = "rm" ]; then
  URI="$3"
  REL="${URI#t3://}"
  rm -rf "$STORE/$REL"
  exit 0
fi
exit 1
`
	_ = os.write_entire_file(fake_t3_path, fake_t3_script)
	_, _, _, _ = os.process_exec({command = {"chmod", "+x", fake_t3_path}}, context.temp_allocator)

	old_path := os.get_env("PATH", context.temp_allocator)
	_ = os.set_env("PATH", "/tmp/odin_tigris_test_fake_t3/fake_bin:/usr/local/bin:/usr/bin:/bin")
	defer _ = os.set_env("PATH", old_path)

	push_bg, _   := filepath.join({ws_push, "static", "brand", "backgrounds"}, context.temp_allocator)
	push_logo, _ := filepath.join({ws_push, "static", "brand", "logos"}, context.temp_allocator)
	_ = tigris.make_directory_all(push_bg)
	_ = tigris.make_directory_all(push_logo)
	f_hero, _ := filepath.join({push_bg, "hero.webp"}, context.temp_allocator)
	f_logo, _ := filepath.join({push_logo, "mark.webp"}, context.temp_allocator)
	_ = os.write_entire_file(f_hero, "hero-v1")
	_ = os.write_entire_file(f_logo, "mark-v1")

	push_rep, push_ok := tigris.run_assets("push", {
		root_dir  = ws_push,
		bucket    = "test-bucket",
		prefix    = "brand",
		local_dir = "static/brand",
	}, context.temp_allocator)
	testing.expect(t, push_ok, "Expected tigris.run_assets('push') with fake t3 to succeed")
	testing.expect_value(t, push_rep.uploaded_count, 2)

	sync_rep, sync_ok := tigris.run_assets("sync", {
		root_dir  = ws_pull,
		bucket    = "test-bucket",
		prefix    = "brand",
		local_dir = "static/brand",
	}, context.temp_allocator)
	testing.expect(t, sync_ok, "Expected tigris.run_assets('sync') into ws_pull to succeed")
	testing.expect_value(t, sync_rep.downloaded_count, 2)

	pulled_hero, _ := filepath.join({ws_pull, "static", "brand", "backgrounds", "hero.webp"}, context.temp_allocator)
	testing.expect(t, os.exists(pulled_hero), "Expected pulled hero.webp to exist on disk")

	noop_rep, noop_ok := tigris.run_assets("sync", {
		root_dir  = ws_pull,
		bucket    = "test-bucket",
		prefix    = "brand",
		local_dir = "static/brand",
	}, context.temp_allocator)
	testing.expect(t, noop_ok, "Expected second sync to succeed")
	testing.expect_value(t, noop_rep.in_sync_count, 2)
	testing.expect_value(t, noop_rep.downloaded_count, 0)
}
