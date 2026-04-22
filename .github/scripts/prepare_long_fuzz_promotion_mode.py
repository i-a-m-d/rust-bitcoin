#!/usr/bin/env python3
"""Prepare one target+mode for corpus promotion."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil


MODE_SLUGS = {
    1: "real",
    2: "secp256k1-fuzz",
    3: "hashes-fuzz-secp256k1-fuzz",
    4: "hashes-fuzz",
}


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_files(root: pathlib.Path):
    if not root.exists():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def copy_seed_file(src: pathlib.Path, dest_dir: pathlib.Path) -> bool:
    digest = sha256_file(src)
    dest = dest_dir / digest
    if dest.exists():
        return False
    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return True


def copy_named_dedup(src: pathlib.Path, dest_dir: pathlib.Path) -> bool:
    digest = sha256_file(src)
    dest_dir.mkdir(parents=True, exist_ok=True)
    candidate = dest_dir / src.name
    if candidate.exists():
        if sha256_file(candidate) == digest:
            return False
        candidate = dest_dir / f"{src.stem}-{digest[:12]}{src.suffix}"
        if candidate.exists() and sha256_file(candidate) == digest:
            return False
    shutil.copy2(src, candidate)
    return True


def count_files(root: pathlib.Path) -> int:
    return sum(1 for _ in iter_files(root))


def total_bytes(root: pathlib.Path) -> int:
    return sum(path.stat().st_size for path in iter_files(root))


def infer_mode_slug(meta: dict) -> str:
    return meta.get("mode_slug") or MODE_SLUGS.get(meta["mode_id"]) or meta["mode_name"].replace("_", "-").replace("+", "-")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", required=True, type=pathlib.Path)
    parser.add_argument("--corpus-store", required=True, type=pathlib.Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode-id", required=True, type=int)
    parser.add_argument("--compare-run-id", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    target = args.target
    mode_id = args.mode_id

    meta_paths = []
    for meta_path in sorted(args.artifacts.rglob("meta.json")):
        if "long-fuzz-result" not in meta_path.parts:
            continue
        meta = json.loads(meta_path.read_text())
        if meta["target"] == target and int(meta["mode_id"]) == mode_id:
            meta_paths.append(meta_path)

    if not meta_paths:
        raise SystemExit(f"no artifacts found for {target} mode {mode_id}")

    first_meta = json.loads(meta_paths[0].read_text())
    mode_name = first_meta["mode_name"]
    mode_slug = infer_mode_slug(first_meta)
    tested_commit = first_meta["tested_commit"]
    tested_commit_url = first_meta["tested_commit_url"]
    rustflags = first_meta.get("rustflags", "")

    mode_root = args.output / "corpus" / target / mode_slug
    seed_dir = mode_root / "seed"
    reproducers_dir = mode_root / "reproducers"
    quarantine_dir = mode_root / "quarantine"
    seed_before_dir = args.output / "work" / "seed-before"
    candidate_dir = args.output / "work" / "candidate"
    mode_root.mkdir(parents=True, exist_ok=True)
    seed_dir.mkdir(parents=True, exist_ok=True)
    reproducers_dir.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    seed_before_dir.mkdir(parents=True, exist_ok=True)
    candidate_dir.mkdir(parents=True, exist_ok=True)

    existing_mode_root = args.corpus_store / "corpus" / target / mode_slug
    existing_seed_dir = existing_mode_root / "seed"
    existing_reproducers_dir = existing_mode_root / "reproducers"
    existing_quarantine_dir = existing_mode_root / "quarantine"
    existing_manifest_path = existing_mode_root / "manifest.json"

    if existing_reproducers_dir.exists():
        shutil.copytree(existing_reproducers_dir, reproducers_dir, dirs_exist_ok=True)
    if existing_quarantine_dir.exists():
        shutil.copytree(existing_quarantine_dir, quarantine_dir, dirs_exist_ok=True)

    existing_seed_files = 0
    existing_seed_bytes = 0
    if existing_seed_dir.exists():
        for file_path in iter_files(existing_seed_dir):
            copy_seed_file(file_path, seed_before_dir)
            copy_seed_file(file_path, candidate_dir)
            existing_seed_files += 1
            existing_seed_bytes += file_path.stat().st_size

    successful_runs_considered = 0
    failed_runs_archived = 0
    candidate_added_from_success = 0
    reproducers_added = 0
    quarantine_runs_added = 0

    for meta_path in meta_paths:
        meta = json.loads(meta_path.read_text())
        artifact_root = args.artifacts / meta_path.relative_to(args.artifacts).parts[0]
        run_index = meta["run_index"]
        seed_value = meta.get("seed")
        run_label = f"run-{run_index}"
        if seed_value is not None:
            run_label = f"{run_label}-seed-{seed_value}"

        corpus_dir = artifact_root / "long-fuzz-corpus" / target / f"mode-{mode_id}" / f"run-{run_index}"
        artifacts_dir = meta_path.parent / "artifacts" / target

        if meta["status"] == "success":
            successful_runs_considered += 1
            for file_path in iter_files(corpus_dir):
                if copy_seed_file(file_path, candidate_dir):
                    candidate_added_from_success += 1
        else:
            failed_runs_archived += 1
            quarantine_run_dir = quarantine_dir / f"{args.compare_run_id}-{run_label}"
            is_new_quarantine = not quarantine_run_dir.exists()
            if corpus_dir.exists():
                shutil.copytree(corpus_dir, quarantine_run_dir, dirs_exist_ok=True)
                if is_new_quarantine:
                    quarantine_runs_added += 1
            for file_path in iter_files(artifacts_dir):
                if copy_named_dedup(file_path, reproducers_dir):
                    reproducers_added += 1

    stats = {
        "target": target,
        "mode_id": mode_id,
        "mode_name": mode_name,
        "mode_slug": mode_slug,
        "tested_commit": tested_commit,
        "tested_commit_url": tested_commit_url,
        "rustflags": rustflags,
        "compare_run_id": args.compare_run_id,
        "existing_seed_files": existing_seed_files,
        "existing_seed_bytes": existing_seed_bytes,
        "successful_runs_considered": successful_runs_considered,
        "failed_runs_archived": failed_runs_archived,
        "candidate_files_pre_cmin": count_files(candidate_dir),
        "candidate_bytes_pre_cmin": total_bytes(candidate_dir),
        "candidate_added_from_success": candidate_added_from_success,
        "reproducers_added": reproducers_added,
        "quarantine_runs_added": quarantine_runs_added,
        "seed_before_dir": str(seed_before_dir),
        "candidate_dir": str(candidate_dir),
        "mode_output_root": str(mode_root),
        "existing_manifest_path": str(existing_manifest_path) if existing_manifest_path.exists() else None,
    }

    stats_path = args.output / "work" / "prepare-stats.json"
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
