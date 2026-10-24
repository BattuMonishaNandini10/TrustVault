
import sqlite3

import pytest
from werkzeug.security import generate_password_hash

import app as trustvault
original_log_event = trustvault.log_event


@pytest.fixture
def isolated_app(monkeypatch):
    """Use a temporary SQLite database, never the real project database."""
    database_uri = "file:trustvault_security_test?mode=memory&cache=shared"
    keeper = sqlite3.connect(database_uri, uri=True)
    keeper.row_factory = sqlite3.Row
    keeper.execute("PRAGMA foreign_keys = ON")

    keeper.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            account_status TEXT NOT NULL DEFAULT 'approved'
        );

        CREATE TABLE documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            owner TEXT NOT NULL,
            category TEXT NOT NULL,
            sha256 TEXT,
            stored_filename TEXT,
            owner_id INTEGER,
            uploaded_at TEXT,
            storage_backend TEXT NOT NULL DEFAULT 'local'
        );

        CREATE TABLE document_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            permission TEXT NOT NULL DEFAULT 'read',
            user_id INTEGER,
            expires_at TEXT,
            UNIQUE(document_id, username)
        );

        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            document_id INTEGER,
            details TEXT,
            result TEXT NOT NULL
        );
    """)

    keeper.execute(
        "INSERT INTO users "
        "(id, username, password_hash, role, account_status) "
        "VALUES (?, ?, ?, ?, ?)",
        (1, "test_owner", generate_password_hash("OwnerTest123!"),
         "owner", "approved"),
    )
    keeper.execute(
        "INSERT INTO users "
        "(id, username, password_hash, role, account_status) "
        "VALUES (?, ?, ?, ?, ?)",
        (2, "test_viewer", generate_password_hash("ViewerTest123!"),
         "viewer", "approved"),
    )
    keeper.execute(
        "INSERT INTO documents "
        "(id, filename, owner, category, owner_id, stored_filename) "
        "VALUES (1, 'sample.txt', 'test_owner', 'test', 1, 'sample.txt')"
    )
    keeper.execute(
        "INSERT INTO document_permissions "
        "(document_id, username, permission, user_id) "
        "VALUES (1, 'test_viewer', 'read', 2)"
    )
    keeper.execute(
        "INSERT INTO users "
        "(id, username, password_hash, role, account_status) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            3,
            "test_admin",
            generate_password_hash("AdminTest123!"),
            "admin",
            "approved",
        ),
    )
    keeper.commit()

    def test_connection():
        connection = sqlite3.connect(database_uri, uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    monkeypatch.setattr(trustvault, "get_db_connection", test_connection)
    monkeypatch.setattr(
        trustvault, "log_event", lambda *args, **kwargs: None
    )

    trustvault.app.config.update(
        TESTING=True,
        SECRET_KEY="test-only-secret",
    )

    yield trustvault.app

    keeper.close()


def test_download_route_requires_login(isolated_app):
    """Logged-out users must be redirected to login."""
    client = isolated_app.test_client()

    response = client.get("/download/1", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_viewer_without_permission_cannot_download(isolated_app):
    """A viewer without a document grant must receive 403."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    connection = trustvault.get_db_connection()
    try:
        connection.execute(
            "DELETE FROM document_permissions "
            "WHERE document_id = ? AND username = ?",
            (1, "test_viewer"),
        )
        connection.commit()
    finally:
        connection.close()

    response = client.get("/download/1", follow_redirects=False)

    assert response.status_code == 403

def test_viewer_with_read_permission_passes_access_check(isolated_app):
    """A viewer with read permission should pass the access check."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/download/1", follow_redirects=False)

    # The test database has a valid read grant.
    # A later file/S3 check may still fail because the fixture
    # intentionally doesn't create a real document file.
    assert response.status_code != 403
def test_viewer_with_revoked_permission_cannot_download(isolated_app):
    """A viewer must lose access after their read permission is revoked."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    # Simulate the owner revoking the viewer's read permission.
    connection = trustvault.get_db_connection()
    try:
        connection.execute(
            "DELETE FROM document_permissions "
            "WHERE document_id = ? AND username = ?",
            (1, "test_viewer"),
        )
        connection.commit()
    finally:
        connection.close()

    response = client.get("/download/1", follow_redirects=False)

    assert response.status_code == 403
def test_owner_can_pass_access_check_for_own_document(isolated_app):
    """The owner should not need a separate read grant for their document."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.get("/download/1", follow_redirects=False)

    # The test checks authorization, not whether a physical file exists.
    assert response.status_code != 403
def test_viewer_cannot_access_admin_audit(isolated_app):
    """A viewer must not access the admin audit page."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/admin/audit", follow_redirects=False)

    assert response.status_code == 403
def test_viewer_cannot_access_upload_route(isolated_app):
    """A viewer must not access the protected upload route."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/upload", follow_redirects=False)

    assert response.status_code == 403
def test_viewer_cannot_post_to_upload_route(isolated_app):
    """A viewer must not upload through a direct POST request."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.post("/upload", follow_redirects=False)

    assert response.status_code == 403

def test_unauthorized_download_is_recorded_in_audit_log(
    isolated_app, monkeypatch
):
    """Denied download attempts should be recorded in the audit log."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    # Remove the viewer's permission so the download is denied.
    connection = trustvault.get_db_connection()
    try:
        connection.execute(
            """
            DELETE FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_viewer"),
        )
        connection.commit()
    finally:
        connection.close()

    # Restore the original audit function for this test.
    monkeypatch.setattr(trustvault, "log_event", original_log_event)

    response = client.get("/download/1", follow_redirects=False)
    assert response.status_code == 403

    connection = trustvault.get_db_connection()
    try:
        event = connection.execute(
            """
            SELECT username, action, document_id, details, result
            FROM audit_logs
            WHERE username = ?
              AND action = ?
              AND document_id = ?
              AND result = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            ("test_viewer", "DOWNLOAD", 1, "DENIED"),
        ).fetchone()
    finally:
        connection.close()

    assert event is not None
    assert event["details"] == "Unauthorized download attempt"

def test_viewer_with_permission_can_download_actual_file(
    isolated_app, tmp_path, monkeypatch
):
    """An authorized viewer receives the actual file contents."""
    client = isolated_app.test_client()

    # Create a real test file.
    file_content = b"TrustVault authorized download test"
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(file_content)

    # Make the document route point to our temporary test file.
    monkeypatch.setattr(
        trustvault, "document_path", lambda filename: str(file_path)
    )

    # Log in as the authorized viewer.
    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/download/1")

    assert response.status_code == 200
    assert response.data == file_content
    assert "attachment" in response.headers.get("Content-Disposition", "")

def test_successful_download_is_recorded_in_audit_log(
    isolated_app, tmp_path, monkeypatch
):
    """A successful download must create a SUCCESS audit entry."""
    client = isolated_app.test_client()

    file_content = b"TrustVault audit success test"
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(file_content)

    monkeypatch.setattr(
        trustvault, "document_path", lambda filename: str(file_path)
    )
    monkeypatch.setattr(
        trustvault, "log_event", original_log_event
    )

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/download/1")

    assert response.status_code == 200
    assert response.data == file_content

    connection = trustvault.get_db_connection()
    try:
        event = connection.execute(
            """
            SELECT username, action, document_id, details, result
            FROM audit_logs
            WHERE username = ?
              AND action = ?
              AND document_id = ?
              AND result = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            ("test_viewer", "DOWNLOAD", 1, "SUCCESS"),
        ).fetchone()
    finally:
        connection.close()

    assert event is not None
    assert event["details"] == "Download authorized"

def test_download_rejects_file_with_wrong_sha256(
    isolated_app, tmp_path, monkeypatch
):
    """A file with a mismatched SHA-256 hash must be rejected."""
    import hashlib

    client = isolated_app.test_client()

    # Create a file whose content differs from the stored hash.
    file_content = b"Modified document content"
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(file_content)

    monkeypatch.setattr(
        trustvault, "document_path", lambda filename: str(file_path)
    )

    # Store the hash of the ORIGINAL content, not the modified file.
    original_hash = hashlib.sha256(
        b"Original document content"
    ).hexdigest()

    connection = trustvault.get_db_connection()
    try:
        connection.execute(
            "UPDATE documents SET sha256 = ? WHERE id = ?",
            (original_hash, 1),
        )
        connection.commit()
    finally:
        connection.close()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/download/1")

    assert response.status_code == 409

def test_sha256_integrity_failure_is_recorded_in_audit_log(
    isolated_app, tmp_path, monkeypatch
):
    """A file integrity failure must be recorded as DENIED."""
    import hashlib

    client = isolated_app.test_client()

    file_content = b"Modified document content"
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(file_content)

    monkeypatch.setattr(
        trustvault, "document_path", lambda filename: str(file_path)
    )
    monkeypatch.setattr(
        trustvault, "log_event", original_log_event
    )

    original_hash = hashlib.sha256(
        b"Original document content"
    ).hexdigest()

    connection = trustvault.get_db_connection()
    try:
        connection.execute(
            "UPDATE documents SET sha256 = ? WHERE id = ?",
            (original_hash, 1),
        )
        connection.commit()
    finally:
        connection.close()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/download/1")
    assert response.status_code == 409

    connection = trustvault.get_db_connection()
    try:
        event = connection.execute(
            """
            SELECT details, result
            FROM audit_logs
            WHERE username = ?
              AND action = ?
              AND document_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            ("test_viewer", "DOWNLOAD", 1),
        ).fetchone()
    finally:
        connection.close()

    assert event is not None
    assert event["result"] == "DENIED"
    assert event["details"] == "SHA-256 integrity check failed"

def test_revoked_permission_is_recorded_in_audit_log(
    isolated_app, monkeypatch
):
    """A download denied after revocation must be audited."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    # Simulate revoking the viewer's read permission.
    connection = trustvault.get_db_connection()
    try:
        connection.execute(
            """
            DELETE FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_viewer"),
        )
        connection.commit()
    finally:
        connection.close()

    # Enable the real audit function for this test.
    monkeypatch.setattr(
        trustvault, "log_event", original_log_event
    )

    response = client.get("/download/1", follow_redirects=False)
    assert response.status_code == 403

    connection = trustvault.get_db_connection()
    try:
        event = connection.execute(
            """
            SELECT username, action, document_id, details, result
            FROM audit_logs
            WHERE username = ?
              AND action = ?
              AND document_id = ?
              AND result = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            ("test_viewer", "DOWNLOAD", 1, "DENIED"),
        ).fetchone()
    finally:
        connection.close()

    assert event is not None
    assert event["details"] == "Unauthorized download attempt"

def test_missing_file_is_recorded_in_audit_log(
    isolated_app, tmp_path, monkeypatch
):
    """A missing stored file must return 404 and be audited."""
    client = isolated_app.test_client()

    # Point to a file that does not exist.
    missing_path = tmp_path / "missing.txt"
    monkeypatch.setattr(
        trustvault, "document_path", lambda filename: str(missing_path)
    )
    monkeypatch.setattr(
        trustvault, "log_event", original_log_event
    )

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/download/1", follow_redirects=False)
    assert response.status_code == 404

    connection = trustvault.get_db_connection()
    try:
        event = connection.execute(
            """
            SELECT details, result
            FROM audit_logs
            WHERE username = ?
              AND action = ?
              AND document_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            ("test_viewer", "DOWNLOAD", 1),
        ).fetchone()
    finally:
        connection.close()

    assert event is not None
    assert event["details"] == "Stored file not found"
    assert event["result"] == "DENIED"

def test_owner_can_access_upload_page(isolated_app):
    """An owner should be allowed to open the upload page."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.get("/upload", follow_redirects=False)

    assert response.status_code == 200
def test_admin_can_access_upload_page(isolated_app):
    """An admin should be allowed to open the upload page."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 3
        session["username"] = "test_admin"
        session["role"] = "admin"

    response = client.get("/upload")

    assert response.status_code == 200


def test_admin_can_access_audit_page(isolated_app):
    """An admin should be allowed to view audit logs."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 3
        session["username"] = "test_admin"
        session["role"] = "admin"

    response = client.get("/admin/audit")

    assert response.status_code == 200


def test_owner_cannot_access_admin_audit(isolated_app):
    """An owner without the admin role must be denied."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.get("/admin/audit")

    assert response.status_code == 403
def test_owner_can_upload_document_to_mock_s3(isolated_app, monkeypatch):
    """Verify secure upload behavior without contacting real AWS S3."""
    import io
    import hashlib

    client = isolated_app.test_client()
    uploaded_objects = []

    class FakeS3:
        def put_object(self, **kwargs):
            uploaded_objects.append(kwargs)

        def delete_object(self, **kwargs):
            pass

    monkeypatch.setattr(trustvault, "s3_client", FakeS3())

    file_content = b"TrustVault safe upload test"

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(file_content), "sample.txt"),
            "category": "Technical",
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert len(uploaded_objects) == 1

    uploaded = uploaded_objects[0]
    assert uploaded["Bucket"] == trustvault.S3_BUCKET
    assert uploaded["Body"] == file_content
    assert uploaded["ServerSideEncryption"] == "AES256"

    conn = trustvault.get_db_connection()
    try:
        doc = conn.execute(
            """
            SELECT * FROM documents
            WHERE filename = ?
              AND owner_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            ("sample.txt", 1),
        ).fetchone()
    finally:
        conn.close()

    assert doc is not None
    assert doc["storage_backend"] == "s3"
    assert doc["category"] == "Technical"
    assert doc["sha256"] == hashlib.sha256(file_content).hexdigest()
def test_upload_rejects_disallowed_file_type(isolated_app, monkeypatch):
    import io

    client = isolated_app.test_client()

    class FakeS3:
        def put_object(self, **kwargs):
            raise AssertionError("S3 must not be called for invalid files")

    monkeypatch.setattr(trustvault, "s3_client", FakeS3())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(b"not an allowed file"), "malware.exe"),
            "category": "Technical",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302


def test_upload_rejects_empty_file(isolated_app, monkeypatch):
    import io

    client = isolated_app.test_client()

    class FakeS3:
        def put_object(self, **kwargs):
            raise AssertionError("S3 must not be called for an empty file")

    monkeypatch.setattr(trustvault, "s3_client", FakeS3())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(b""), "empty.txt"),
            "category": "Technical",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302
def test_s3_upload_failure_does_not_create_document(isolated_app, monkeypatch):
    import io

    client = isolated_app.test_client()

    class FailingS3:
        def put_object(self, **kwargs):
            raise RuntimeError("Simulated S3 failure")

        def delete_object(self, **kwargs):
            pass

    monkeypatch.setattr(trustvault, "s3_client", FailingS3())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(b"Test upload failure"), "failure_test.txt"),
            "category": "Technical",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302

    conn = trustvault.get_db_connection()
    try:
        doc = conn.execute(
            "SELECT id FROM documents WHERE filename = ?",
            ("failure_test.txt",),
        ).fetchone()
    finally:
        conn.close()

    assert doc is None

def test_database_failure_triggers_s3_cleanup(isolated_app, monkeypatch):
    import io

    client = isolated_app.test_client()
    uploaded_objects = []
    deleted_objects = []

    class FakeS3:
        def put_object(self, **kwargs):
            uploaded_objects.append(kwargs)

        def delete_object(self, **kwargs):
            deleted_objects.append(kwargs)

    monkeypatch.setattr(trustvault, "s3_client", FakeS3())

    original_connection = trustvault.get_db_connection

    class FailingInsertConnection:
        def __init__(self, real_connection):
            self.real_connection = real_connection

        def execute(self, sql, params=()):
            if "INSERT INTO documents" in sql:
                raise RuntimeError("Simulated database insert failure")
            return self.real_connection.execute(sql, params)

        def rollback(self):
            return self.real_connection.rollback()

        def close(self):
            return self.real_connection.close()

    def connection_failing_only_document_insert():
        return FailingInsertConnection(original_connection())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    monkeypatch.setattr(
        trustvault,
        "get_db_connection",
        connection_failing_only_document_insert,
    )

    response = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(b"Cleanup test content"), "cleanup_test.txt"),
            "category": "Technical",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302
    assert len(uploaded_objects) == 1
    assert len(deleted_objects) == 1
    assert deleted_objects[0]["Key"] == uploaded_objects[0]["Key"]

    monkeypatch.setattr(
        trustvault, "get_db_connection", original_connection
    )

    conn = original_connection()
    try:
        doc = conn.execute(
            "SELECT id FROM documents WHERE filename = ?",
            ("cleanup_test.txt",),
        ).fetchone()
    finally:
        conn.close()

    assert doc is None

def test_revoking_access_removes_viewer_permission(isolated_app):
    client = isolated_app.test_client()

    # Confirm the viewer initially has read permission.
    conn = trustvault.get_db_connection()
    try:
        before = conn.execute(
            """
            SELECT id FROM document_permissions
            WHERE document_id = ? AND username = ?
              AND permission = 'read'
            """,
            (1, "test_viewer"),
        ).fetchone()
    finally:
        conn.close()

    assert before is not None

    # Log in as the document owner.
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    # Revoke the viewer's access.
    response = client.post("/revoke/1/test_viewer")

    assert response.status_code == 302

    # Confirm the viewer's permission has been removed.
    conn = trustvault.get_db_connection()
    try:
        after = conn.execute(
            """
            SELECT id FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_viewer"),
        ).fetchone()

        # The document itself must still exist.
        document = conn.execute(
            "SELECT id FROM documents WHERE id = ?", (1,)
        ).fetchone()
    finally:
        conn.close()

    assert after is None
    assert document is not None

def test_real_revoke_route_blocks_viewer_download_and_preview(isolated_app):
    """Revoking access through the real route blocks downloads and previews."""
    client = isolated_app.test_client()

    # Log in as the owner and revoke the viewer's access.
    with client.session_transaction() as session:
        session.clear()
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    revoke_response = client.post("/revoke/1/test_viewer")
    assert revoke_response.status_code == 302

    # Switch to the viewer account.
    with client.session_transaction() as session:
        session.clear()
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    # The viewer must no longer be able to download the document.
    download_response = client.get(
        "/download/1",
        follow_redirects=False,
    )
    assert download_response.status_code == 403

    # The viewer must also be denied access to the preview endpoint.
    preview_response = client.get(
        "/preview-pdf/1",
        follow_redirects=False,
    )
    assert preview_response.status_code == 403

    # Confirm the viewer's permission was actually removed.
    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT id FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_viewer"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is None
def test_viewer_cannot_open_share_page(isolated_app):
    """A viewer must not manage another user's document permissions."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/share/1", follow_redirects=False)

    assert response.status_code == 403


def test_viewer_cannot_grant_document_access(isolated_app):
    """A viewer must not grant another user access to a document."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.post(
        "/share/1",
        data={"username": "test_admin"},
        follow_redirects=False,
    )

    assert response.status_code == 403

    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT id FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_admin"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is None
def test_viewer_cannot_revoke_document_access(isolated_app):
    """A viewer must not revoke permissions on a document they cannot manage."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.post(
        "/revoke/1/test_viewer",
        follow_redirects=False,
    )

    assert response.status_code == 403

    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT id
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_viewer"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is not None
def test_owner_can_grant_read_access(isolated_app):
    """An owner should be able to grant read access to another user."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/share/1",
        data={"username": "test_admin"},
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT permission
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_admin"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is not None
    assert permission["permission"] == "read"

def test_owner_can_grant_edit_access(isolated_app):
    """An owner can grant edit permission and it is stored correctly."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/share/1",
        data={"username": "test_admin", "permission": "edit"},
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT permission
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_admin"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is not None
    assert permission["permission"] == "edit"

def test_owner_cannot_share_with_nonexistent_user(isolated_app):
    """Sharing with an unknown username must not create a permission."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/share/1",
        data={"username": "ghost_user_999"},
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT id
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "ghost_user_999"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is None

def test_owner_cannot_share_document_with_self(isolated_app):
    """An owner should not create a redundant permission for themselves."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/share/1",
        data={"username": "test_owner"},
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT id
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_owner"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is None


def test_cannot_share_nonexistent_document(isolated_app):
    """Sharing a document ID that does not exist must return 404."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/share/999999",
        data={"username": "test_admin"},
        follow_redirects=False,
    )

    assert response.status_code == 404


def test_cannot_revoke_access_for_nonexistent_document(isolated_app):
    """Revoking access on a nonexistent document must return 404."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/revoke/999999/test_viewer",
        follow_redirects=False,
    )

    assert response.status_code == 404

def test_revoke_nonexistent_permission_is_handled_safely(isolated_app):
    """Revoking a nonexistent permission must not crash or create access."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/revoke/1/test_admin",
        follow_redirects=False,
    )

    # The route should redirect back to the sharing page.
    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT id
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_admin"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is None

def test_viewer_cannot_revoke_another_users_permission(isolated_app):
    """A viewer cannot revoke another user's document permission."""
    client = isolated_app.test_client()

    # Set the session to the viewer account.
    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    # Attempt to revoke the admin's permission.
    response = client.post(
        "/revoke/1/test_admin",
        follow_redirects=False,
    )

    assert response.status_code == 403

    # Verify no permission was accidentally created or modified.
    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT id
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_admin"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is None
def test_preview_pdf_rejects_unsupported_file_type(isolated_app):
    """PDF preview must reject unsupported file types with HTTP 415."""
    client = isolated_app.test_client()

    # The isolated fixture creates document 1 as sample.txt.
    # Log in as its owner so the request passes the permission check.
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.get("/preview-pdf/1")

    assert response.status_code == 415



def test_viewer_without_permission_cannot_view_or_preview(isolated_app):
    """A viewer without permission cannot view or preview a document."""
    client = isolated_app.test_client()

    # Remove the fixture's default read permission for this viewer.
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "DELETE FROM document_permissions "
            "WHERE document_id = ? AND username = ?",
            (1, "test_viewer"),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    view_response = client.get("/view/1")
    preview_response = client.get("/preview-pdf/1")

    assert view_response.status_code == 403
    assert preview_response.status_code == 403


def test_owner_can_preview_valid_pdf_with_security_headers(
    isolated_app, tmp_path, monkeypatch
):
    """Authorized PDF previews return PDF data with security headers."""
    import hashlib

    client = isolated_app.test_client()
    pdf_data = b"%PDF-1.4\nTrustVault preview test\n%%EOF"
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(pdf_data)

    monkeypatch.setattr(
        trustvault, "document_path", lambda filename: str(pdf_path)
    )

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE documents SET filename = ?, sha256 = ? WHERE id = ?",
            ("sample.pdf", hashlib.sha256(pdf_data).hexdigest(), 1),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.get("/preview-pdf/1")

    assert response.status_code == 200
    assert response.data == pdf_data
    assert response.mimetype == "application/pdf"
    assert response.headers["Content-Disposition"] == "inline"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Content-Security-Policy"] == "sandbox"



    """Direct view and PDF preview URLs must enforce document permissions."""
    client = isolated_app.test_client()

    # Remove the viewer's existing read permission in the test database.
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            """
            DELETE FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_viewer"),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    # Test both endpoints directly, not just the preview page.
    view_response = client.get("/view/1")
    preview_response = client.get("/preview-pdf/1")

    assert view_response.status_code == 403
    assert preview_response.status_code == 403

def test_owner_cannot_view_another_owners_document(isolated_app):
    """An owner must not view another owner's document without permission."""
    client = isolated_app.test_client()

    # Simulate document 1 belonging to the admin instead.
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE documents SET owner_id = ? WHERE id = ?",
            (3, 1),
        )
        conn.commit()
    finally:
        conn.close()

    # Log in as the original owner.
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    # The owner has no read permission for this document.
    view_response = client.get("/view/1")
    preview_response = client.get("/preview-pdf/1")

    assert view_response.status_code == 403
    assert preview_response.status_code == 403

def test_owner_cannot_download_another_owners_document(isolated_app):
    """An owner must not download another owner's document without permission."""
    client = isolated_app.test_client()

    # Change ownership only in the isolated test database.
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE documents SET owner_id = ? WHERE id = ?",
            (3, 1),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.get("/download/1")


    assert response.status_code == 403


def test_logout_clears_session_and_blocks_protected_pages(isolated_app):
    """After logout, the previous session must not access protected pages."""
    client = isolated_app.test_client()

    # Start with an authenticated viewer session.
    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    # Log out.
    response = client.get("/logout", follow_redirects=False)

    assert response.status_code in (302, 303)
    assert "/login" in response.headers["Location"]

    # Confirm the session identity has been cleared.
    with client.session_transaction() as session:
        assert "user_id" not in session
        assert "username" not in session
        assert "role" not in session

    # A protected page must reject the logged-out user.
    protected_response = client.get("/", follow_redirects=False)
    assert protected_response.status_code in (302, 303)
    assert "/login" in protected_response.headers["Location"]


def test_invalid_login_does_not_create_authenticated_session(isolated_app):
    """Incorrect credentials must not establish an authenticated session."""
    client = isolated_app.test_client()

    response = client.post(
        "/login",
        data={
            "username": "test_viewer",
            "password": "DefinitelyWrongPassword123!",
        },
        follow_redirects=False,
    )

    # Invalid credentials should keep the user on the login page.
    assert response.status_code == 200

    # No authenticated identity should be stored in the session.
    with client.session_transaction() as session:
        assert "user_id" not in session
        assert "username" not in session
        assert "role" not in session

    # The protected dashboard must still reject the client.
    protected_response = client.get("/", follow_redirects=False)
    assert protected_response.status_code in (302, 303)
    assert "/login" in protected_response.headers["Location"]

def test_unknown_username_cannot_login(isolated_app):
    """A username that does not exist must not authenticate."""
    client = isolated_app.test_client()

    response = client.post(
        "/login",
        data={
            "username": "user_that_does_not_exist_987",
            "password": "AnyPassword123!",
        },
        follow_redirects=False,
    )

    # Invalid login should return the login page.
    assert response.status_code == 200

    # No authenticated identity should be created.
    with client.session_transaction() as session:
        assert "user_id" not in session
        assert "username" not in session
        assert "role" not in session

    # The protected dashboard must still redirect to login.
    protected_response = client.get("/", follow_redirects=False)

    assert protected_response.status_code in (302, 303)
    assert "/login" in protected_response.headers["Location"]

def test_successful_login_creates_correct_session(isolated_app):
    """Successful login must establish the correct user's identity and role."""
    client = isolated_app.test_client()

    response = client.post(
        "/login",
        data={
            "username": "test_viewer",
            "password": "ViewerTest123!",
        },
        follow_redirects=False,
    )

    # Successful login should redirect to the next page.
    assert response.status_code in (302, 303)

    # Verify that the session contains the correct identity and role.
    with client.session_transaction() as session:
        assert session.get("user_id") == 2
        assert session.get("username") == "test_viewer"
        assert session.get("role") == "viewer"

    # A successfully authenticated user should reach the dashboard.
    dashboard_response = client.get("/", follow_redirects=False)
    assert dashboard_response.status_code not in (401, 403)

def test_pending_user_cannot_login(isolated_app):
    """A user awaiting admin approval must not be authenticated."""
    client = isolated_app.test_client()

    # Update the user in the isolated test database.
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET account_status = ? WHERE username = ?",
            ("pending", "test_viewer"),
        )
        conn.commit()
    finally:
        conn.close()

    response = client.post(
        "/login",
        data={
            "username": "test_viewer",
            "password": "ViewerTest123!",
        },
        follow_redirects=False,
    )

    # Pending users should remain on the login page.
    assert response.status_code == 200

    # A pending user must not receive an authenticated session.
    with client.session_transaction() as session:
        assert "user_id" not in session
        assert "username" not in session
        assert "role" not in session


def test_suspended_user_cannot_login(isolated_app):
    """A suspended account must not establish an authenticated session."""
    client = isolated_app.test_client()

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET account_status = ? WHERE username = ?",
            ("suspended", "test_viewer"),
        )
        conn.commit()
    finally:
        conn.close()

    response = client.post(
        "/login",
        data={
            "username": "test_viewer",
            "password": "ViewerTest123!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 200

    with client.session_transaction() as session:
        assert "user_id" not in session
        assert "username" not in session
        assert "role" not in session
def test_suspended_user_existing_session_is_blocked(isolated_app):
    """Suspending an account must invalidate its existing session."""
    client = isolated_app.test_client()

    # Simulate a viewer who is already logged in.
    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    # Suspend the account in the isolated test database.

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET account_status = ? WHERE id = ?",
            ("suspended", 2),
        )
        conn.commit()
    finally:
        conn.close()

    # A suspended user's existing session must be rejected.
    response = client.get("/", follow_redirects=False)

    assert response.status_code in (302, 303)
    assert "/login" in response.headers["Location"]

    # Confirm that authentication details were cleared.
    with client.session_transaction() as session:
        assert "user_id" not in session
        assert "username" not in session
        assert "role" not in session

@pytest.mark.parametrize(
    "user_id,username,role",
    [
        (1, "test_owner", "owner"),
        (2, "test_viewer", "viewer"),
    ],
)
def test_non_admin_cannot_change_account_status(
    isolated_app, user_id, username, role
):
    """Only admins may change account statuses."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = username
        session["role"] = role

    response = client.post(
        "/admin/users/2/status",
        data={"status": "rejected"},
        follow_redirects=False,
    )

    assert response.status_code == 403

    conn = trustvault.get_db_connection()
    try:
        user = conn.execute(
            "SELECT account_status FROM users WHERE id = 2"
        ).fetchone()
    finally:
        conn.close()

    assert user["account_status"] == "approved"


def test_admin_cannot_submit_invalid_account_status(isolated_app):
    """Only approved and rejected are accepted status values."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 3
        session["username"] = "test_admin"
        session["role"] = "admin"

    response = client.post(
        "/admin/users/2/status",
        data={"status": "suspended"},
        follow_redirects=False,
    )

    assert response.status_code == 400

    conn = trustvault.get_db_connection()
    try:
        user = conn.execute(
            "SELECT account_status FROM users WHERE id = 2"
        ).fetchone()
    finally:
        conn.close()

    assert user["account_status"] == "approved"


def test_admin_cannot_change_own_account_status(isolated_app):
    """An admin cannot change their own account status."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 3
        session["username"] = "test_admin"
        session["role"] = "admin"

    response = client.post(
        "/admin/users/3/status",
        data={"status": "rejected"},
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        user = conn.execute(
            "SELECT account_status FROM users WHERE id = 3"
        ).fetchone()
    finally:
        conn.close()

    assert user["account_status"] == "approved"


def test_admin_cannot_change_nonexistent_user_status(isolated_app):
    """Changing a nonexistent account must return 404."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 3
        session["username"] = "test_admin"
        session["role"] = "admin"

    response = client.post(
        "/admin/users/999999/status",
        data={"status": "rejected"},
        follow_redirects=False,
    )

    assert response.status_code == 404


@pytest.mark.parametrize("status", ["approved", "rejected"])
def test_admin_can_update_another_users_status(
    isolated_app, status
):
    """An admin can set a valid status on another account."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 3
        session["username"] = "test_admin"
        session["role"] = "admin"

    response = client.post(
        "/admin/users/2/status",
        data={"status": status},
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        user = conn.execute(
            "SELECT account_status FROM users WHERE id = 2"
        ).fetchone()
    finally:
        conn.close()

    assert user["account_status"] == status

def test_viewer_cannot_delete_document_they_can_only_read(isolated_app):
    """A viewer must not delete a document owned by someone else."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.post(
        "/delete/1",
        follow_redirects=False,
    )

    # The viewer must be denied.
    assert response.status_code == 403

    # The owner's document must still exist.
    conn = trustvault.get_db_connection()
    try:
        document = conn.execute(
            "SELECT id, filename FROM documents WHERE id = ?",
            (1,),
        ).fetchone()
    finally:
        conn.close()

    assert document is not None
    assert document["id"] == 1

def test_registration_rejects_empty_fields(isolated_app):
    client = isolated_app.test_client()

    response = client.post(
        "/register",
        data={
            "username": "",
            "password": "",
            "confirm_password": "",
        },
    )

    assert response.status_code == 200
    assert b"Please enter a username and password." in response.data


def test_registration_rejects_short_username(isolated_app):
    client = isolated_app.test_client()

    response = client.post(
        "/register",
        data={
            "username": "ab",
            "password": "StrongPass123!",
            "confirm_password": "StrongPass123!",
        },
    )

    assert response.status_code == 200
    assert b"Username must contain at least 3 characters." in response.data


def test_registration_rejects_short_password(isolated_app):
    client = isolated_app.test_client()

    response = client.post(
        "/register",
        data={
            "username": "new_viewer",
            "password": "short",
            "confirm_password": "short",
        },
    )

    assert response.status_code == 200
    assert b"Password must contain at least 8 characters." in response.data


def test_registration_rejects_password_mismatch(isolated_app):
    client = isolated_app.test_client()

    response = client.post(
        "/register",
        data={
            "username": "new_viewer",
            "password": "StrongPass123!",
            "confirm_password": "DifferentPass123!",
        },
    )

    assert response.status_code == 200
    assert b"Passwords do not match." in response.data


def test_registration_rejects_duplicate_username(isolated_app):
    client = isolated_app.test_client()

    response = client.post(
        "/register",
        data={
            "username": "test_owner",
            "password": "StrongPass123!",
            "confirm_password": "StrongPass123!",
        },
    )

    assert response.status_code == 200
    assert b"That username is already registered." in response.data


def test_successful_registration_creates_pending_viewer(isolated_app):
    client = isolated_app.test_client()

    response = client.post(
        "/register",
        data={
            "username": "new_viewer",
            "password": "StrongPass123!",
            "confirm_password": "StrongPass123!",
        },
    )

    assert response.status_code == 200
    assert b"Registration submitted" in response.data
    assert b"administrator approval" in response.data

    conn = trustvault.get_db_connection()
    try:
        user = conn.execute(
            """
            SELECT username, password_hash, role, account_status
            FROM users
            WHERE username = ?
            """,
            ("new_viewer",),
        ).fetchone()
    finally:
        conn.close()

    assert user is not None
    assert user["role"] == "viewer"
    assert user["account_status"] == "pending"
    assert user["password_hash"] != "StrongPass123!"


def test_owner_can_delete_own_local_document(isolated_app, tmp_path, monkeypatch):
    """The owner can delete their document and its database record."""
    client = isolated_app.test_client()

    stored_file = tmp_path / "sample.txt"
    stored_file.write_text("TrustVault test document", encoding="utf-8")

    monkeypatch.setattr(
        trustvault,
        "UPLOAD_FOLDER",
        str(tmp_path),
    )

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post("/delete/1", follow_redirects=False)

    assert response.status_code in (302, 303)
    assert not stored_file.exists()

    conn = trustvault.get_db_connection()
    try:
        document = conn.execute(
            "SELECT id FROM documents WHERE id = ?", (1,)
        ).fetchone()
    finally:
        conn.close()

    assert document is None


def test_owner_delete_failure_preserves_database_record(
    isolated_app, tmp_path, monkeypatch
):
    """A storage deletion failure must not remove the database record."""
    client = isolated_app.test_client()

    monkeypatch.setattr(
        trustvault,
        "UPLOAD_FOLDER",
        str(tmp_path),
    )

    # Simulate an operating-system error while deleting the local file.
    def fail_remove(path):
        raise OSError("Simulated storage deletion failure")

    monkeypatch.setattr(trustvault.os, "remove", fail_remove)

    stored_file = tmp_path / "sample.txt"
    stored_file.write_text("TrustVault test document", encoding="utf-8")

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post("/delete/1", follow_redirects=False)

    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        document = conn.execute(
            "SELECT id FROM documents WHERE id = ?", (1,)
        ).fetchone()
    finally:
        conn.close()

    assert document is not None
    assert stored_file.exists()

def test_upload_rejects_request_without_file(isolated_app):
    """Uploading without selecting a file must not create a document."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    conn = trustvault.get_db_connection()
    try:
        before_count = conn.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()[0]
    finally:
        conn.close()

    response = client.post(
        "/upload",
        data={},
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        after_count = conn.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()[0]
    finally:
        conn.close()

    assert after_count == before_count
def test_owner_cannot_share_another_owners_document(isolated_app):
    """An owner cannot grant access to another owner's document."""
    client = isolated_app.test_client()

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE documents SET owner_id = ? WHERE id = ?",
            (3, 1),
        )
        conn.commit()

        before_count = conn.execute(
            "SELECT COUNT(*) FROM document_permissions "
            "WHERE document_id = ? AND username = ?",
            (1, "test_viewer"),
        ).fetchone()[0]
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/share/1",
        data={"username": "test_viewer"},
        follow_redirects=False,
    )

    assert response.status_code == 403

    conn = trustvault.get_db_connection()
    try:
        after_count = conn.execute(
            "SELECT COUNT(*) FROM document_permissions "
            "WHERE document_id = ? AND username = ?",
            (1, "test_viewer"),
        ).fetchone()[0]
    finally:
        conn.close()

    assert after_count == before_count


def test_owner_cannot_revoke_access_from_another_owners_document(
    isolated_app,
):
    """An owner cannot revoke access to another owner's document."""
    client = isolated_app.test_client()

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE documents SET owner_id = ? WHERE id = ?",
            (3, 1),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/revoke/1/test_viewer",
        follow_redirects=False,
    )

    assert response.status_code == 403

    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            "SELECT permission FROM document_permissions "
            "WHERE document_id = ? AND username = ?",
            (1, "test_viewer"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is not None

def test_owner_can_download_document_from_mock_s3(
    isolated_app, monkeypatch
):
    """An authorized owner can download a document from mocked S3."""
    import hashlib
    import io

    client = isolated_app.test_client()
    content = b"TrustVault private S3 document"

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            """
            UPDATE documents
            SET storage_backend = 's3',
                stored_filename = 'private/sample.txt',
                sha256 = ?
            WHERE id = 1
            """,
            (hashlib.sha256(content).hexdigest(),),
        )
        conn.commit()
    finally:
        conn.close()

    class FakeS3:
        def get_object(self, **kwargs):
            assert kwargs["Bucket"] == trustvault.S3_BUCKET
            assert kwargs["Key"] == "private/sample.txt"
            return {
                "Body": io.BytesIO(content),
                "ContentType": "text/plain",
            }

    monkeypatch.setattr(trustvault, "s3_client", FakeS3())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.get("/download/1")

    assert response.status_code == 200
    assert response.data == content
    assert "attachment" in response.headers["Content-Disposition"]


def test_s3_download_rejects_wrong_sha256(
    isolated_app, monkeypatch
):
    """S3 content that fails the SHA-256 check must be rejected."""
    import hashlib
    import io

    client = isolated_app.test_client()
    actual_content = b"Altered document content"
    expected_hash = hashlib.sha256(
        b"Original document content"
    ).hexdigest()

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            """
            UPDATE documents
            SET storage_backend = 's3',
                stored_filename = 'private/sample.txt',
                sha256 = ?
            WHERE id = 1
            """,
            (expected_hash,),
        )
        conn.commit()
    finally:
        conn.close()

    class FakeS3:
        def get_object(self, **kwargs):
            return {
                "Body": io.BytesIO(actual_content),
                "ContentType": "text/plain",
            }

    monkeypatch.setattr(trustvault, "s3_client", FakeS3())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.get("/download/1")

    assert response.status_code == 409


def test_s3_download_returns_404_when_object_is_unavailable(
    isolated_app, monkeypatch
):
    """An S3 ClientError must not expose a missing object."""
    from botocore.exceptions import ClientError

    client = isolated_app.test_client()

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            """
            UPDATE documents
            SET storage_backend = 's3',
                stored_filename = 'private/missing.txt'
            WHERE id = 1
            """
        )
        conn.commit()
    finally:
        conn.close()

    class FailingS3:
        def get_object(self, **kwargs):
            raise ClientError(
                {
                    "Error": {
                        "Code": "NoSuchKey",
                        "Message": "Object not found",
                    }
                },
                "GetObject",
            )

    monkeypatch.setattr(trustvault, "s3_client", FailingS3())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.get("/download/1")

    assert response.status_code == 404


def test_s3_delete_failure_preserves_database_record(
    isolated_app, monkeypatch
):
    """If S3 deletion fails, preserve the document database record."""
    from botocore.exceptions import ClientError

    client = isolated_app.test_client()
    attempted_deletions = []

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            """
            UPDATE documents
            SET storage_backend = 's3',
                stored_filename = 'private/sample.txt'
            WHERE id = 1
            """
        )
        conn.commit()
    finally:
        conn.close()

    class FailingS3:
        def delete_object(self, **kwargs):
            attempted_deletions.append(kwargs)
            raise ClientError(
                {
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "Simulated S3 deletion failure",
                    }
                },
                "DeleteObject",
            )

    monkeypatch.setattr(trustvault, "s3_client", FailingS3())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post("/delete/1", follow_redirects=False)

    assert response.status_code in (302, 303)
    assert len(attempted_deletions) == 1
    assert attempted_deletions[0]["Bucket"] == trustvault.S3_BUCKET
    assert attempted_deletions[0]["Key"] == "private/sample.txt"

    conn = trustvault.get_db_connection()
    try:
        document = conn.execute(
            "SELECT id FROM documents WHERE id = ?", (1,)
        ).fetchone()
    finally:
        conn.close()

    assert document is not None


def test_sharing_same_document_twice_does_not_create_duplicate_permissions(
    isolated_app,
):
    """Sharing twice should keep one permission and preserve read access."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    # Grant access for the first time.
    first_response = client.post(
        "/share/1",
        data={"username": "test_viewer"},
        follow_redirects=False,
    )
    assert first_response.status_code in (302, 303)

    # Grant access to the same user again.
    second_response = client.post(
        "/share/1",
        data={"username": "test_viewer"},
        follow_redirects=False,
    )
    assert second_response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        permissions = conn.execute(
            """
            SELECT permission
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_viewer"),
        ).fetchall()
    finally:
        conn.close()

    assert len(permissions) == 1
    assert permissions[0]["permission"] == "read"

def test_owner_cannot_grant_invalid_permission(isolated_app):
    """Invalid permission values must not be stored."""
    client = isolated_app.test_client()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/share/1",
        data={"username": "test_admin", "permission": "admin"},
        follow_redirects=False,
    )

    assert response.status_code in (302, 303)

    conn = trustvault.get_db_connection()
    try:
        permission = conn.execute(
            """
            SELECT permission
            FROM document_permissions
            WHERE document_id = ? AND username = ?
            """,
            (1, "test_admin"),
        ).fetchone()
    finally:
        conn.close()

    assert permission is None


def test_init_db_adds_expiry_column_without_removing_existing_shares(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "trustvault_legacy.db"
    connection = sqlite3.connect(database_path)
    connection.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer'
        );
        CREATE TABLE documents (
            id INTEGER PRIMARY KEY,
            filename TEXT NOT NULL,
            owner TEXT NOT NULL,
            category TEXT NOT NULL
        );
        CREATE TABLE document_permissions (
            id INTEGER PRIMARY KEY,
            document_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            permission TEXT NOT NULL DEFAULT 'read',
            UNIQUE(document_id, username)
        );
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            document_id INTEGER,
            details TEXT,
            result TEXT NOT NULL
        );
        INSERT INTO users VALUES (1, 'owner', 'hash', 'owner');
        INSERT INTO documents VALUES (1, 'legacy.pdf', 'owner', 'Legal');
        INSERT INTO document_permissions
            (id, document_id, username, permission)
            VALUES (1, 1, 'viewer', 'read');
    """)
    connection.commit()
    connection.close()

    monkeypatch.setattr(trustvault, "DATABASE", str(database_path))

    trustvault.init_db()
    trustvault.init_db()

    connection = sqlite3.connect(database_path)
    try:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(document_permissions)"
            )
        }
        grant = connection.execute(
            "SELECT document_id, username, permission, expires_at "
            "FROM document_permissions WHERE id = 1"
        ).fetchone()
    finally:
        connection.close()

    assert "expires_at" in columns
    assert grant == (1, "viewer", "read", None)


def test_owner_can_set_expiry_for_a_share(isolated_app):
    client = isolated_app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/share/1",
        data={
            "username": "test_admin",
            "permission": "read",
            "expires_at": "2099-01-01T00:00",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    conn = trustvault.get_db_connection()
    try:
        grant = conn.execute(
            "SELECT expires_at FROM document_permissions "
            "WHERE document_id = 1 AND username = 'test_admin'"
        ).fetchone()
    finally:
        conn.close()

    assert grant["expires_at"] == "2099-01-01T00:00:00+00:00"


@pytest.mark.parametrize("expiry", ["2000-01-01T00:00", "not-a-date"])
def test_owner_cannot_create_share_with_invalid_or_past_expiry(
    isolated_app, expiry
):
    client = isolated_app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/share/1",
        data={"username": "test_admin", "expires_at": expiry},
        follow_redirects=False,
    )

    assert response.status_code == 302
    conn = trustvault.get_db_connection()
    try:
        grant = conn.execute(
            "SELECT id FROM document_permissions "
            "WHERE document_id = 1 AND username = 'test_admin'"
        ).fetchone()
    finally:
        conn.close()
    assert grant is None


@pytest.mark.parametrize(
    ("path", "permission"),
    [
        ("/view/1", "read"),
        ("/preview-pdf/1", "read"),
        ("/download/1", "read"),
        ("/edit/1", "edit"),
    ],
)
def test_expired_share_denies_direct_access_and_is_audited(
    isolated_app, monkeypatch, path, permission
):
    client = isolated_app.test_client()
    events = []
    monkeypatch.setattr(
        trustvault, "log_event",
        lambda *args, **kwargs: events.append(args),
    )
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE document_permissions "
            "SET permission = ?, expires_at = ? "
            "WHERE document_id = 1 AND username = 'test_viewer'",
            (permission, "2000-01-01T00:00:00+00:00"),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get(path, follow_redirects=False)

    assert response.status_code == 403
    assert events
    assert events[0][1] == "SHARE_EXPIRED"
    assert events[0][-1] == "DENIED"


def test_active_share_still_allows_access_check(isolated_app):
    client = isolated_app.test_client()
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE document_permissions SET expires_at = ? "
            "WHERE document_id = 1 AND username = 'test_viewer'",
            ("2099-01-01T00:00:00+00:00",),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    response = client.get("/download/1", follow_redirects=False)

    # The test fixture has no file on disk, but the active grant passes
    # authorization and reaches the file-not-found check.
    assert response.status_code == 404


def test_expired_share_is_hidden_from_shared_list_and_search(isolated_app):
    client = isolated_app.test_client()
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE document_permissions SET expires_at = ? "
            "WHERE document_id = 1 AND username = 'test_viewer'",
            ("2000-01-01T00:00:00+00:00",),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    shared_response = client.get("/shared")
    search_response = client.get("/document-search?name=sample")
    api_response = client.get("/api/document-search?name=sample")

    assert shared_response.status_code == 200
    assert b"sample.txt" not in shared_response.data
    assert search_response.status_code == 200
    assert b"sample.txt" not in search_response.data
    assert api_response.status_code == 200
    assert api_response.get_json() == {"count": 0, "documents": []}


def test_document_lists_filter_by_name_and_category_without_crossing_roles(
    isolated_app
):
    client = isolated_app.test_client()
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO documents
                (id, filename, owner, category, owner_id, stored_filename)
            VALUES (2, 'finance-plan.txt', 'test_owner', 'Finance', 1,
                    'finance-plan.txt')
            """
        )
        conn.execute(
            """
            INSERT INTO document_permissions
                (document_id, username, permission, user_id)
            VALUES (2, 'test_viewer', 'read', 2)
            """
        )
        conn.execute(
            """
            INSERT INTO documents
                (id, filename, owner, category, owner_id, stored_filename)
            VALUES (3, 'secret-payroll.txt', 'test_admin', 'Finance', 3,
                    'secret-payroll.txt')
            """
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    owner_response = client.get("/my-docs?name=finance&category=finance")

    assert owner_response.status_code == 200
    assert b"finance-plan.txt" in owner_response.data
    assert b"sample.txt" not in owner_response.data
    assert b"secret-payroll.txt" not in owner_response.data

    with client.session_transaction() as session:
        session.clear()
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    shared_response = client.get("/shared?category=finance")
    viewer_response = client.get("/shared?name=secret-payroll")
    api_response = client.get("/api/document-search?name=secret-payroll")

    assert shared_response.status_code == 200
    assert b"finance-plan.txt" in shared_response.data
    assert b"sample.txt" not in shared_response.data
    assert viewer_response.status_code == 200
    assert b"secret-payroll.txt" not in viewer_response.data
    assert api_response.status_code == 200
    assert api_response.get_json() == {"count": 0, "documents": []}


@pytest.mark.parametrize(
    ("user_id", "username", "role"),
    [
        (1, "test_owner", "owner"),
        (2, "test_viewer", "viewer"),
    ],
)
def test_security_dashboard_is_admin_only(
    isolated_app, user_id, username, role
):
    client = isolated_app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = username
        session["role"] = role

    response = client.get("/admin/security-dashboard")

    assert response.status_code == 403
    assert b"Sensitive audit" not in response.data


def test_admin_security_dashboard_shows_counts_and_recent_activity(
    isolated_app
):
    client = isolated_app.test_client()
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO audit_logs
                (timestamp, username, action, document_id, details, result)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-10-23T12:00:00+00:00",
                "test_viewer",
                "DOWNLOAD",
                1,
                "Denied download for dashboard test",
                "DENIED",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 3
        session["username"] = "test_admin"
        session["role"] = "admin"

    home_response = client.get("/")
    response = client.get("/admin/security-dashboard")

    assert home_response.status_code == 200
    assert b"Security Dashboard" in home_response.data
    assert response.status_code == 200
    assert b"Security Dashboard" in response.data
    assert b"Total Documents" in response.data
    assert b"Documents With Active Shares" in response.data
    assert b"Access-Denied Attempts" in response.data
    assert b"Recent Audit Activity" in response.data
    assert b"Denied download for dashboard test" in response.data
    assert b"/admin/security-dashboard" in response.data
    assert (
        b'<div class="stat-number">1</div>\n'
        b'        <div class="stat-label">Total Documents</div>'
    ) in response.data
    assert (
        b'<div class="stat-number">1</div>\n'
        b'        <div class="stat-label">Documents With Active Shares</div>'
    ) in response.data
    assert (
        b'<div class="stat-number">1</div>\n'
        b'        <div class="stat-label">Access-Denied Attempts</div>'
    ) in response.data


def test_document_search_filters_owner_category_and_dates_without_leaks(
    isolated_app
):
    client = isolated_app.test_client()
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE documents SET uploaded_at = ? WHERE id = 1",
            ("2026-10-02T10:15:00+00:00",),
        )
        conn.execute(
            """
            INSERT INTO documents
                (id, filename, owner, category, owner_id, uploaded_at,
                 stored_filename)
            VALUES (2, 'private-plan.txt', 'test_admin', 'Finance', 3,
                    '2026-10-03T10:15:00+00:00', 'private-plan.txt')
            """
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    filters = (
        "owner=test_owner&category=test"
        "&date_from=2026-10-01&date_to=2026-10-02"
    )
    page = client.get("/document-search?" + filters)
    api = client.get("/api/document-search?" + filters)
    private_owner_search = client.get(
        "/document-search?owner=test_admin"
    )

    assert page.status_code == 200
    assert b"sample.txt" in page.data
    assert b"private-plan.txt" not in page.data
    assert api.status_code == 200
    assert api.get_json()["count"] == 1
    assert api.get_json()["documents"][0]["filename"] == "sample.txt"
    assert private_owner_search.status_code == 200
    assert b"private-plan.txt" not in private_owner_search.data


def test_ungranted_owner_cannot_read_change_or_delete_another_owners_document(
    isolated_app
):
    client = isolated_app.test_client()
    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE documents SET owner = ?, owner_id = ? WHERE id = 1",
            ("test_admin", 3),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    responses = [
        client.get("/view/1"),
        client.get("/preview-pdf/1"),
        client.get("/download/1"),
        client.get("/edit/1"),
        client.post("/edit/1", data={
            "filename": "changed.txt",
            "category": "Changed",
        }),
        client.post("/share/1", data={
            "username": "test_viewer",
            "permission": "read",
        }),
        client.post("/revoke/1/test_viewer"),
        client.post("/delete/1"),
    ]

    assert [response.status_code for response in responses] == [403] * 8

    conn = trustvault.get_db_connection()
    try:
        document = conn.execute(
            "SELECT filename, category, owner_id FROM documents WHERE id = 1"
        ).fetchone()
    finally:
        conn.close()

    assert document["filename"] == "sample.txt"
    assert document["category"] == "test"
    assert document["owner_id"] == 3


def test_admin_can_access_and_manage_all_document_content_routes(
    isolated_app, tmp_path, monkeypatch
):
    import hashlib

    client = isolated_app.test_client()
    file_data = b"%PDF-1.7\nTrustVault admin access test\n"
    stored_file = tmp_path / "sample.pdf"
    stored_file.write_bytes(file_data)
    monkeypatch.setattr(trustvault, "UPLOAD_FOLDER", str(tmp_path))
    monkeypatch.setattr(trustvault, "log_event", original_log_event)

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            """
            UPDATE documents
            SET filename = ?, stored_filename = ?, sha256 = ?
            WHERE id = 1
            """,
            (
                "sample.pdf",
                "sample.pdf",
                hashlib.sha256(file_data).hexdigest(),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 3
        session["username"] = "test_admin"
        session["role"] = "admin"

    view_response = client.get("/view/1")
    preview_response = client.get("/preview-pdf/1")
    download_response = client.get("/download/1")
    edit_page = client.get("/edit/1")
    edit_response = client.post(
        "/edit/1",
        data={"filename": "renamed.pdf", "category": "Legal"},
    )
    delete_response = client.post("/delete/1", follow_redirects=False)

    assert view_response.status_code == 200
    assert preview_response.status_code == 200
    assert preview_response.data == file_data
    assert download_response.status_code == 200
    assert download_response.data == file_data
    assert edit_page.status_code == 200
    assert edit_response.status_code == 302
    assert delete_response.status_code == 302
    assert not stored_file.exists()

    conn = trustvault.get_db_connection()
    try:
        document = conn.execute(
            "SELECT id FROM documents WHERE id = 1"
        ).fetchone()
        actions = {
            row["action"]
            for row in conn.execute(
                "SELECT action FROM audit_logs WHERE document_id = 1"
            ).fetchall()
        }
    finally:
        conn.close()

    assert document is None
    assert {"VIEW", "DOWNLOAD", "EDIT", "DELETE"} <= actions


def test_edit_grant_allows_preview_and_metadata_change_not_delete(
    isolated_app, tmp_path, monkeypatch
):
    client = isolated_app.test_client()
    file_data = b"%PDF-1.7\nEdit-grantee preview test\n"
    stored_file = tmp_path / "sample.pdf"
    stored_file.write_bytes(file_data)
    monkeypatch.setattr(trustvault, "UPLOAD_FOLDER", str(tmp_path))

    conn = trustvault.get_db_connection()
    try:
        conn.execute(
            "UPDATE documents SET filename = ?, stored_filename = ? "
            "WHERE id = 1",
            ("sample.pdf", "sample.pdf"),
        )
        conn.execute(
            "UPDATE document_permissions SET permission = 'edit' "
            "WHERE document_id = 1 AND username = 'test_viewer'"
        )
        conn.commit()
    finally:
        conn.close()

    with client.session_transaction() as session:
        session["user_id"] = 2
        session["username"] = "test_viewer"
        session["role"] = "viewer"

    preview = client.get("/preview-pdf/1")
    edit = client.post(
        "/edit/1",
        data={"filename": "updated.pdf", "category": "Finance"},
    )
    delete = client.post("/delete/1")

    assert preview.status_code == 200
    assert preview.data == file_data
    assert edit.status_code == 302
    assert delete.status_code == 403
    assert stored_file.exists()

    conn = trustvault.get_db_connection()
    try:
        document = conn.execute(
            "SELECT filename, category FROM documents WHERE id = 1"
        ).fetchone()
    finally:
        conn.close()

    assert document["filename"] == "updated.pdf"
    assert document["category"] == "Finance"


def test_document_permission_grants_and_revocations_are_audited(
    isolated_app, monkeypatch
):
    client = isolated_app.test_client()
    monkeypatch.setattr(trustvault, "log_event", original_log_event)

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    grant_response = client.post(
        "/share/1",
        data={"username": "test_admin", "permission": "edit"},
    )
    revoke_response = client.post("/revoke/1/test_admin")

    assert grant_response.status_code == 302
    assert revoke_response.status_code == 302

    conn = trustvault.get_db_connection()
    try:
        events = conn.execute(
            """
            SELECT action, details, result
            FROM audit_logs
            WHERE document_id = 1 AND action IN ('SHARE', 'REVOKE')
            ORDER BY id
            """
        ).fetchall()
    finally:
        conn.close()

    assert [event["action"] for event in events] == ["SHARE", "REVOKE"]
    assert "edit access" in events[0]["details"].lower()
    assert "test_admin" in events[1]["details"]
    assert all(event["result"] == "SUCCESS" for event in events)


def test_upload_over_request_size_limit_is_rejected_before_storage(
    isolated_app, monkeypatch
):
    import io

    client = isolated_app.test_client()

    class FakeS3:
        def put_object(self, **kwargs):
            raise AssertionError("Oversized files must not reach S3")

    monkeypatch.setattr(trustvault, "s3_client", FakeS3())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    oversized_file = b"x" * (10 * 1024 * 1024 + 1)
    response = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(oversized_file), "oversized.txt"),
            "category": "Technical",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 413

    conn = trustvault.get_db_connection()
    try:
        document_count = conn.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()[0]
    finally:
        conn.close()

    assert document_count == 1


def test_upload_content_validator_checks_supported_formats():
    import io
    import zipfile

    docx_data = io.BytesIO()
    with zipfile.ZipFile(docx_data, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")

    valid_files = [
        ("report.pdf", b"%PDF-1.7\nreport\n"),
        ("image.png", b"\x89PNG\r\n\x1a\nimage"),
        ("photo.jpg", b"\xff\xd8\xffimage"),
        ("document.docx", docx_data.getvalue()),
        ("notes.txt", "Résumé".encode("utf-8")),
        ("table.csv", b"name,amount\nTrustVault,1\n"),
    ]

    for filename, file_data in valid_files:
        assert trustvault.validate_upload_content(
            filename, file_data
        ), filename

    invalid_files = [
        ("spoofed.pdf", b"not a PDF"),
        ("spoofed.png", b"not a PNG"),
        ("spoofed.jpg", b"not a JPEG"),
        ("spoofed.docx", b"not a DOCX archive"),
        ("binary.txt", b"\xff\x00\xfe"),
        ("unsupported.exe", b"executable"),
    ]

    for filename, file_data in invalid_files:
        assert not trustvault.validate_upload_content(
            filename, file_data
        ), filename


def test_upload_rejects_mislabeled_file_before_storage(
    isolated_app, monkeypatch
):
    import io

    client = isolated_app.test_client()
    uploaded_objects = []

    class FakeS3:
        def put_object(self, **kwargs):
            uploaded_objects.append(kwargs)

    monkeypatch.setattr(trustvault, "s3_client", FakeS3())

    with client.session_transaction() as session:
        session["user_id"] = 1
        session["username"] = "test_owner"
        session["role"] = "owner"

    response = client.post(
        "/upload",
        data={
            "file": (io.BytesIO(b"this is not a PDF"), "mislabelled.pdf"),
            "category": "Technical",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302
    assert uploaded_objects == []

    conn = trustvault.get_db_connection()
    try:
        document_count = conn.execute(
            "SELECT COUNT(*) FROM documents"
        ).fetchone()[0]
    finally:
        conn.close()

    assert document_count == 1

