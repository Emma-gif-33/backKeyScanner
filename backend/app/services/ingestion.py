import hashlib
import io
import os
import shutil
import zipfile
from typing import List
from fastapi import HTTPException, status

# Safety Limits
MAX_UPLOAD_SIZE = 50 * 1024 * 1024       # 50 MB max zip upload
MAX_UNCOMPRESSED_SIZE = 250 * 1024 * 1024 # 250 MB max extracted content
MAX_FILES_COUNT = 5000                   # 5000 files max


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of byte content."""
    sha = hashlib.sha256()
    sha.update(data)
    return sha.hexdigest()


def validate_and_inspect_zip(content: bytes) -> int:
    """Validate zip file magic bytes, integrity and check against zip bombs and slip.
    Returns total uncompressed bytes.
    """
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is empty."
        )

    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File exceeds maximum allowed upload size of {MAX_UPLOAD_SIZE // (1024 * 1024)} MB."
        )

    # Magic bytes check for ZIP (PK\x03\x04 or PK\x05\x06 for empty zips)
    if not (content.startswith(b"PK\x03\x04") or content.startswith(b"PK\x05\x06")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid archive format. File must be a valid ZIP archive."
        )

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            file_list = zf.infolist()
            if len(file_list) > MAX_FILES_COUNT:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Zip bomb detected: contains {len(file_list)} files, exceeding limit of {MAX_FILES_COUNT}."
                )

            total_uncompressed = 0
            for item in file_list:
                total_uncompressed += item.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Zip bomb detected: uncompressed size exceeds maximum allowable limit."
                    )

                # Zip Slip protection: check for path traversal
                normalized = os.path.normpath(item.filename)
                if normalized.startswith("..") or os.path.isabs(normalized):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Malicious archive detected: Zip Slip path traversal attempt in '{item.filename}'."
                    )

            return total_uncompressed

    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Corrupted or invalid ZIP archive."
        )


def extract_zip_safely(content: bytes, destination_dir: str) -> List[str]:
    """Safely extract all files from zip content to destination_dir.
    Returns list of relative extracted file paths.
    """
    validate_and_inspect_zip(content)
    os.makedirs(destination_dir, exist_ok=True)
    canonical_dest = os.path.abspath(destination_dir)

    extracted_files: List[str] = []

    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        for member in zf.infolist():
            # Skip directories
            if member.is_dir():
                continue

            # Ensure extraction target is strictly within destination_dir (Zip Slip barrier)
            target_path = os.path.abspath(os.path.join(canonical_dest, member.filename))
            if not target_path.startswith(canonical_dest + os.sep) and target_path != canonical_dest:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Illegal path traversal attempt."
                )

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(member) as source, open(target_path, "wb") as target:
                shutil.copyfileobj(source, target)

            rel_path = os.path.relpath(target_path, canonical_dest)
            extracted_files.append(rel_path.replace("\\", "/"))

    return extracted_files


def cleanup_directory(path: str) -> None:
    """Safely remove a directory and its contents if it exists."""
    if os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)
