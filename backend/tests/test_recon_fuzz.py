from app.tools.recon.fuzz import DirectoryFuzzer


def test_build_paths_respects_max_paths():
    seeds = [f"path{i}" for i in range(300)]

    paths = DirectoryFuzzer._build_paths(
        seeds,
        max_paths=120,
        max_variants_per_seed=4,
    )

    assert len(paths) == 120
    assert len(set(paths)) == len(paths)
    assert paths[0] == "path0"


def test_build_paths_limits_variants_per_seed():
    seeds = ["admin", "login", "api"]

    paths = DirectoryFuzzer._build_paths(
        seeds,
        max_paths=100,
        max_variants_per_seed=2,
    )

    assert "admin" in paths
    assert "admin/" in paths
    assert "admin.php" not in paths
