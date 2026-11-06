from pathlib import Path
from typing import List

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError


def validate_file(path: Path) -> List[str]:
    
    errors: List[str] = []
    try:
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    except SigmaError as e:
        errors.append(f"SigmaError: {e}")
        return errors
    except Exception as e:
        errors.append(f"Unexpected error: {type(e).__name__}: {e}")
        return errors

    if not collection.rules:
        errors.append("No rules found in file.")
    return errors


def print_validation(path: Path, errors: List[str]) -> None:
    print("=" * 60)
    print(f"  Validating: {path}")
    print("=" * 60)
    if not errors:
        print("  ✅ OK")
    else:
        for err in errors:
            print(f"  ❌ {err}")


def validate_directory(directory: Path) -> int:
    
    bad = 0
    for path in sorted(directory.rglob("*.yml")):
        errors = validate_file(path)
        print_validation(path, errors)
        if errors:
            bad += 1
    return bad