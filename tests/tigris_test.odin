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
