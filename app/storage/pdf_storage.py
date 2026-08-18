"""
MongoDB GridFS storage for forensic PDF reports.

Uses GridFS for efficient binary storage and retrieval of large PDF files.
"""
from datetime import UTC, datetime
from io import BytesIO

from app.core.config import settings
from app.core.logging import logger

# Lazy imports for GridFS
_gridfs_bucket = None


async def get_gridfs_bucket():
    """
    Lazily initialize and return GridFS bucket for PDF storage.

    Returns None if MongoDB is not configured.
    """
    global _gridfs_bucket

    if _gridfs_bucket is not None:
        return _gridfs_bucket

    uri = settings.mongodb_uri
    if not uri:
        logger.warning("MONGODB_URI not set - PDF storage disabled")
        return None

    try:
        from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket

        client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
        # Verify connection
        await client.admin.command("ping")

        db = client["scamshield_v2"]
        _gridfs_bucket = AsyncIOMotorGridFSBucket(db, bucket_name="forensic_pdfs")

        logger.info("GridFS bucket initialized for PDF storage")
        return _gridfs_bucket

    except Exception as exc:
        logger.error(f"GridFS initialization failed: {exc}")
        return None


async def store_pdf(
    session_id: str,
    pdf_bytes: bytes,
    case_id: str,
    metadata: dict | None = None
) -> str | None:
    """
    Store PDF in MongoDB GridFS.

    Args:
        session_id: Session identifier
        pdf_bytes: PDF content as bytes
        case_id: Case ID for the report
        metadata: Optional metadata dict

    Returns:
        GridFS file ID as string, or None on failure
    """
    bucket = await get_gridfs_bucket()
    if bucket is None:
        return None

    try:
        filename = f"CyberCrime_Report_{case_id}.pdf"

        # Prepare metadata
        file_metadata = {
            "sessionId": session_id,
            "caseId": case_id,
            "uploadedAt": datetime.now(UTC),
            "contentType": "application/pdf",
            "size": len(pdf_bytes),
        }
        if metadata:
            file_metadata.update(metadata)

        # Upload to GridFS
        file_id = await bucket.upload_from_stream(
            filename,
            BytesIO(pdf_bytes),
            metadata=file_metadata
        )

        logger.info(
            f"PDF stored in GridFS - Session: {session_id}, "
            f"FileID: {file_id}, Size: {len(pdf_bytes)} bytes"
        )
        return str(file_id)

    except Exception as exc:
        logger.error(f"Failed to store PDF in GridFS - Session: {session_id}, Error: {exc}")
        return None


async def retrieve_pdf(file_id: str) -> tuple[bytes, dict] | None:
    """
    Retrieve PDF from MongoDB GridFS.

    Args:
        file_id: GridFS file ID

    Returns:
        Tuple of (pdf_bytes, metadata) or None on failure
    """
    bucket = await get_gridfs_bucket()
    if bucket is None:
        return None

    try:
        from bson import ObjectId

        # Download from GridFS
        grid_out = await bucket.open_download_stream(ObjectId(file_id))

        # Read bytes
        pdf_bytes = await grid_out.read()

        # Get metadata
        metadata = {
            "filename": grid_out.filename,
            "uploadDate": grid_out.upload_date,
            "length": grid_out.length,
            "metadata": grid_out.metadata or {},
        }

        logger.info(f"PDF retrieved from GridFS - FileID: {file_id}, Size: {len(pdf_bytes)} bytes")
        return pdf_bytes, metadata

    except Exception as exc:
        logger.error(f"Failed to retrieve PDF from GridFS - FileID: {file_id}, Error: {exc}")
        return None


async def retrieve_pdf_by_session(session_id: str) -> tuple[bytes, dict] | None:
    """
    Retrieve PDF by session ID.

    Args:
        session_id: Session identifier

    Returns:
        Tuple of (pdf_bytes, metadata) or None on failure
    """
    bucket = await get_gridfs_bucket()
    if bucket is None:
        return None

    try:
        # Find file by session ID in metadata
        cursor = bucket.find({"metadata.sessionId": session_id})

        # Get first match
        files = await cursor.to_list(length=1)
        if not files:
            logger.warning(f"No PDF found for session: {session_id}")
            return None

        # Extract file_id from the GridFS file document
        file_id = files[0]["_id"]

        # Retrieve the file
        return await retrieve_pdf(str(file_id))

    except Exception as exc:
        logger.error(f"Failed to retrieve PDF by session - Session: {session_id}, Error: {exc}")
        return None


async def delete_pdf(file_id: str) -> bool:
    """
    Delete PDF from MongoDB GridFS.

    Args:
        file_id: GridFS file ID

    Returns:
        True if deleted successfully, False otherwise
    """
    bucket = await get_gridfs_bucket()
    if bucket is None:
        return False

    try:
        from bson import ObjectId

        await bucket.delete(ObjectId(file_id))

        logger.info(f"PDF deleted from GridFS - FileID: {file_id}")
        return True

    except Exception as exc:
        logger.error(f"Failed to delete PDF from GridFS - FileID: {file_id}, Error: {exc}")
        return False


async def check_pdf_exists(session_id: str) -> bool:
    """
    Check if PDF exists for a session.

    Args:
        session_id: Session identifier

    Returns:
        True if PDF exists, False otherwise
    """
    bucket = await get_gridfs_bucket()
    if bucket is None:
        return False

    try:
        cursor = bucket.find({"metadata.sessionId": session_id})
        files = await cursor.to_list(length=1)
        return len(files) > 0

    except Exception as exc:
        logger.error(f"Failed to check PDF existence - Session: {session_id}, Error: {exc}")
        return False
