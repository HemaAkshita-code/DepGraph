import re
from datetime import date
from typing import Optional

import oracledb
from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field

from app import database
from app.auth import get_current_user, require_admin, require_role
from app.users import _raise_db_error, _rows_as_dicts

router = APIRouter()

PACKAGE_NAME_PATTERN = r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$"
VERSION_PATTERN = r"^\d{1,5}(\.\d{1,5}){0,2}$"
SHA_PATTERN = r"^[0-9a-f]{40}$"
REQUIREMENT_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*==\s*(\S+)$")
MAX_REQUIREMENTS_BYTES = 200_000

VIEW_ALL_ROLES = ("ADMIN", "SECURITY_ANALYST", "AUDITOR")
EDIT_ALL_ROLES = ("ADMIN", "SECURITY_ANALYST")

require_catalog_editor = require_role("ADMIN", "SECURITY_ANALYST", "DEVELOPER")
require_reporting = require_role("ADMIN", "SECURITY_ANALYST", "AUDITOR")

VISIBLE_PROJECTS_FILTER = """
    (:see_all = 1 OR pr.owner_team_id IN (
        SELECT tm.team_id FROM team_members tm WHERE tm.user_id = :user_id
    ))
"""


class ProjectRequest(BaseModel):
    project_name: str = Field(min_length=1, max_length=100)
    description: Optional[str] = Field(default=None, max_length=500)
    repo_url: Optional[str] = Field(default=None, max_length=300, pattern=r"^https://\S+$")
    owner_team_id: int


class PackageRequest(BaseModel):
    package_name: str = Field(max_length=100, pattern=PACKAGE_NAME_PATTERN)
    license: Optional[str] = Field(default=None, max_length=50)


class VersionRequest(BaseModel):
    version: str = Field(pattern=VERSION_PATTERN)
    released_on: Optional[date] = None


class DependencyRequest(BaseModel):
    package_name: str = Field(max_length=100, pattern=PACKAGE_NAME_PATTERN)
    version: str = Field(pattern=VERSION_PATTERN)


class PackageDepRequest(BaseModel):
    parent_package: str = Field(max_length=100, pattern=PACKAGE_NAME_PATTERN)
    parent_version: str = Field(pattern=VERSION_PATTERN)
    child_package: str = Field(max_length=100, pattern=PACKAGE_NAME_PATTERN)
    child_version: str = Field(pattern=VERSION_PATTERN)


# ------------------------------------------------------------------ Helpers

def normalize_package_name(name: str) -> str:
    """PyPI treats Jinja2, jinja2 and jinja_2 style variants as one name."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def parse_version(text: str) -> tuple:
    """'3.1.2' -> (3, 1, 2); '3.1' -> (3, 1, 0); '3' -> (3, 0, 0)."""
    parts = [int(part) for part in text.strip().split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def version_text(parts: tuple) -> str:
    return ".".join(str(part) for part in parts)


def parse_requirements(text: str):
    """
    Read exact pins (name==version) from a requirements.txt.
    Returns ({package_name: (major, minor, patch)}, [skipped lines with reasons]).
    """
    pinned = {}
    skipped = []

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        line = re.sub(r"\s+#.*$", "", line).split(";", 1)[0].strip()

        if line.startswith("-"):
            skipped.append({"line": line_no, "text": raw_line.strip(),
                            "reason": "pip option lines are not scanned"})
            continue

        match = REQUIREMENT_LINE.match(line)
        if match is None:
            skipped.append({"line": line_no, "text": raw_line.strip(),
                            "reason": "only exact pins (name==version) are supported"})
            continue

        name = normalize_package_name(match.group(1))
        version = match.group(3)

        if not re.fullmatch(VERSION_PATTERN, version):
            skipped.append({"line": line_no, "text": raw_line.strip(),
                            "reason": "version format not supported"})
            continue

        parts = parse_version(version)
        if name in pinned and pinned[name] != parts:
            skipped.append({"line": line_no, "text": raw_line.strip(),
                            "reason": "package listed again with a different version"})
            continue

        pinned[name] = parts

    return pinned, skipped


def _db_error(exc: oracledb.DatabaseError):
    if "ORA-02292" in str(exc):
        raise HTTPException(status_code=409, detail="This record is still used by other records") from exc
    _raise_db_error(exc)


def _ensure_package(cursor, package_name: str, license_name: Optional[str] = None) -> int:
    cursor.execute(
        """
        MERGE INTO packages p
        USING (SELECT :package_name AS package_name FROM dual) s
        ON (p.ecosystem = 'PyPI' AND p.package_name = s.package_name)
        WHEN NOT MATCHED THEN
            INSERT (package_name, license) VALUES (s.package_name, :license_name)
        """,
        {"package_name": package_name, "license_name": license_name},
    )
    cursor.execute(
        """
        SELECT package_id FROM packages
        WHERE ecosystem = 'PyPI' AND package_name = :package_name
        """,
        {"package_name": package_name},
    )
    return cursor.fetchone()[0]


def _ensure_version(cursor, package_id: int, parts: tuple) -> int:
    major, minor, patch = parts
    cursor.execute(
        """
        MERGE INTO package_versions v
        USING (SELECT :package_id AS package_id, :major AS major_no,
                      :minor AS minor_no, :patch AS patch_no FROM dual) s
        ON (v.package_id = s.package_id AND v.major_no = s.major_no
            AND v.minor_no = s.minor_no AND v.patch_no = s.patch_no)
        WHEN NOT MATCHED THEN
            INSERT (package_id, major_no, minor_no, patch_no)
            VALUES (s.package_id, s.major_no, s.minor_no, s.patch_no)
        """,
        {"package_id": package_id, "major": major, "minor": minor, "patch": patch},
    )
    cursor.execute(
        """
        SELECT version_id FROM package_versions
        WHERE package_id = :package_id
          AND major_no = :major AND minor_no = :minor AND patch_no = :patch
        """,
        {"package_id": package_id, "major": major, "minor": minor, "patch": patch},
    )
    return cursor.fetchone()[0]


def _is_member(cursor, team_id: int, user_id: int) -> bool:
    cursor.execute(
        "SELECT 1 FROM team_members WHERE team_id = :team_id AND user_id = :user_id",
        {"team_id": team_id, "user_id": user_id},
    )
    return cursor.fetchone() is not None


def _check_team_write(cursor, team_id: int, user: dict):
    if user["role"] in EDIT_ALL_ROLES:
        return
    if user["role"] == "DEVELOPER" and _is_member(cursor, team_id, user["user_id"]):
        return
    raise HTTPException(status_code=403, detail="You can only manage projects of your own teams")


def _project_owner(cursor, project_id: int, lock: bool = False) -> int:
    sql = "SELECT owner_team_id FROM projects WHERE project_id = :project_id"
    if lock:
        sql += " FOR UPDATE"
    cursor.execute(sql, {"project_id": project_id})
    row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return row[0]


def _check_project_read(cursor, project_id: int, user: dict):
    owner_team_id = _project_owner(cursor, project_id)
    if user["role"] not in VIEW_ALL_ROLES and not _is_member(cursor, owner_team_id, user["user_id"]):
        raise HTTPException(status_code=403, detail="You can only view projects of your own teams")


def _check_project_write(cursor, project_id: int, user: dict, lock: bool = False) -> int:
    owner_team_id = _project_owner(cursor, project_id, lock)
    _check_team_write(cursor, owner_team_id, user)
    return owner_team_id


def _visibility(user: dict) -> dict:
    return {"see_all": 1 if user["role"] in VIEW_ALL_ROLES else 0, "user_id": user["user_id"]}


# ------------------------------------------------------------------ Projects

@router.post("/projects", status_code=201, tags=["Projects"])
def create_project(data: ProjectRequest, request: Request):
    user = get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        _check_team_write(cursor, data.owner_team_id, user)

        new_project_id = cursor.var(int)
        cursor.execute(
            """
            INSERT INTO projects (project_name, description, repo_url, owner_team_id, created_by)
            VALUES (:project_name, :description, :repo_url, :owner_team_id, :created_by)
            RETURNING project_id INTO :new_project_id
            """,
            {
                "project_name": data.project_name.strip(),
                "description": data.description,
                "repo_url": data.repo_url,
                "owner_team_id": data.owner_team_id,
                "created_by": user["user_id"],
                "new_project_id": new_project_id,
            },
        )
        connection.commit()

        return {
            "message": "Project created successfully",
            "project_id": new_project_id.getvalue()[0],
        }

    except oracledb.DatabaseError as exc:
        connection.rollback()
        message = str(exc)
        if "ORA-00001" in message:
            raise HTTPException(status_code=409, detail="A project with this name or repository already exists") from exc
        if "ORA-02291" in message:
            raise HTTPException(status_code=404, detail="Team not found") from exc
        _db_error(exc)

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@router.get("/projects", tags=["Projects"])
def list_projects(request: Request):
    user = get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            f"""
            SELECT pr.project_id, pr.project_name, pr.description, pr.repo_url,
                   pr.scanned_commit_sha, pr.scanned_at,
                   pr.owner_team_id, t.team_name,
                   u.full_name AS created_by_name, pr.created_at,
                   (SELECT COUNT(*) FROM dependencies d
                    WHERE d.project_id = pr.project_id) AS direct_dependencies
            FROM projects pr
            JOIN teams t ON t.team_id = pr.owner_team_id
            JOIN users u ON u.user_id = pr.created_by
            WHERE {VISIBLE_PROJECTS_FILTER}
            ORDER BY pr.project_name
            """,
            _visibility(user),
        )
        return {"projects": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()


@router.get("/projects/{project_id}", tags=["Projects"])
def get_project(project_id: int, request: Request):
    user = get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        _check_project_read(cursor, project_id, user)

        cursor.execute(
            """
            SELECT pr.project_id, pr.project_name, pr.description, pr.repo_url,
                   pr.scanned_commit_sha, pr.scanned_at,
                   pr.owner_team_id, t.team_name,
                   u.full_name AS created_by_name, pr.created_at
            FROM projects pr
            JOIN teams t ON t.team_id = pr.owner_team_id
            JOIN users u ON u.user_id = pr.created_by
            WHERE pr.project_id = :project_id
            """,
            {"project_id": project_id},
        )
        project = _rows_as_dicts(cursor)[0]

        cursor.execute(
            """
            SELECT COUNT(DISTINCT CASE WHEN depth = 1 THEN version_id END) AS direct_dependencies,
                   COUNT(DISTINCT version_id) AS total_packages,
                   NVL(MAX(depth), 0) AS max_depth
            FROM project_all_dependencies
            WHERE project_id = :project_id
            """,
            {"project_id": project_id},
        )
        project.update(_rows_as_dicts(cursor)[0])

        return {"project": project}

    finally:
        cursor.close()
        connection.close()


@router.put("/projects/{project_id}", tags=["Projects"])
def update_project(project_id: int, data: ProjectRequest, request: Request):
    user = get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        current_team_id = _check_project_write(cursor, project_id, user, lock=True)
        if data.owner_team_id != current_team_id:
            _check_team_write(cursor, data.owner_team_id, user)

        cursor.execute(
            """
            UPDATE projects
            SET project_name = :project_name,
                description = :description,
                repo_url = :repo_url,
                owner_team_id = :owner_team_id
            WHERE project_id = :project_id
            """,
            {
                "project_name": data.project_name.strip(),
                "description": data.description,
                "repo_url": data.repo_url,
                "owner_team_id": data.owner_team_id,
                "project_id": project_id,
            },
        )
        connection.commit()
        return {"message": "Project updated successfully"}

    except oracledb.DatabaseError as exc:
        connection.rollback()
        message = str(exc)
        if "ORA-00001" in message:
            raise HTTPException(status_code=409, detail="A project with this name or repository already exists") from exc
        if "ORA-02291" in message:
            raise HTTPException(status_code=404, detail="Team not found") from exc
        _db_error(exc)

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@router.delete("/projects/{project_id}", tags=["Projects"])
def delete_project(project_id: int, request: Request):
    require_admin(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "DELETE FROM projects WHERE project_id = :project_id",
            {"project_id": project_id},
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Project not found")

        connection.commit()
        return {"message": "Project deleted"}

    except oracledb.DatabaseError as exc:
        connection.rollback()
        if "ORA-02292" in str(exc):
            raise HTTPException(
                status_code=409,
                detail="This project has exposures or fix tasks linked to it and cannot be deleted",
            ) from exc
        _db_error(exc)

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


# ------------------------------------------------------------------ Packages

@router.post("/packages", status_code=201, tags=["Packages"])
def create_package(data: PackageRequest, request: Request):
    require_catalog_editor(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        new_package_id = cursor.var(int)
        cursor.execute(
            """
            INSERT INTO packages (package_name, license)
            VALUES (:package_name, :license_name)
            RETURNING package_id INTO :new_package_id
            """,
            {
                "package_name": normalize_package_name(data.package_name),
                "license_name": data.license,
                "new_package_id": new_package_id,
            },
        )
        connection.commit()
        return {"message": "Package created", "package_id": new_package_id.getvalue()[0]}

    except oracledb.DatabaseError as exc:
        connection.rollback()
        if "ORA-00001" in str(exc):
            raise HTTPException(status_code=409, detail="This package already exists") from exc
        _db_error(exc)

    finally:
        cursor.close()
        connection.close()


@router.get("/packages", tags=["Packages"])
def list_packages(request: Request, search: Optional[str] = None):
    get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT p.package_id, p.package_name, p.ecosystem, p.license,
                   (SELECT COUNT(*) FROM package_versions v
                    WHERE v.package_id = p.package_id) AS version_count
            FROM packages p
            WHERE :search IS NULL OR p.package_name LIKE '%' || :search || '%'
            ORDER BY p.package_name
            """,
            {"search": normalize_package_name(search) if search and search.strip() else None},
        )
        return {"packages": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()


@router.post("/packages/{package_id}/versions", status_code=201, tags=["Packages"])
def create_version(package_id: int, data: VersionRequest, request: Request):
    require_catalog_editor(request)
    major, minor, patch = parse_version(data.version)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        new_version_id = cursor.var(int)
        cursor.execute(
            """
            INSERT INTO package_versions (package_id, major_no, minor_no, patch_no, released_on)
            VALUES (:package_id, :major, :minor, :patch, :released_on)
            RETURNING version_id INTO :new_version_id
            """,
            {
                "package_id": package_id,
                "major": major,
                "minor": minor,
                "patch": patch,
                "released_on": data.released_on,
                "new_version_id": new_version_id,
            },
        )
        connection.commit()
        return {
            "message": "Version added",
            "version_id": new_version_id.getvalue()[0],
            "version": version_text((major, minor, patch)),
        }

    except oracledb.DatabaseError as exc:
        connection.rollback()
        message = str(exc)
        if "ORA-00001" in message:
            raise HTTPException(status_code=409, detail="This version already exists") from exc
        if "ORA-02291" in message:
            raise HTTPException(status_code=404, detail="Package not found") from exc
        _db_error(exc)

    finally:
        cursor.close()
        connection.close()


@router.get("/packages/{package_id}/versions", tags=["Packages"])
def list_versions(package_id: int, request: Request):
    get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT package_name FROM packages WHERE package_id = :package_id",
            {"package_id": package_id},
        )
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Package not found")

        cursor.execute(
            """
            SELECT v.version_id,
                   v.major_no || '.' || v.minor_no || '.' || v.patch_no AS version_text,
                   v.released_on,
                   (SELECT COUNT(*) FROM dependencies d
                    WHERE d.version_id = v.version_id) AS direct_project_count
            FROM package_versions v
            WHERE v.package_id = :package_id
            ORDER BY v.major_no, v.minor_no, v.patch_no
            """,
            {"package_id": package_id},
        )
        return {"package_id": package_id, "package_name": row[0], "versions": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()


@router.post("/package-deps", status_code=201, tags=["Packages"])
def create_package_dep(data: PackageDepRequest, request: Request):
    require_catalog_editor(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        parent_id = _ensure_version(
            cursor,
            _ensure_package(cursor, normalize_package_name(data.parent_package)),
            parse_version(data.parent_version),
        )
        child_id = _ensure_version(
            cursor,
            _ensure_package(cursor, normalize_package_name(data.child_package)),
            parse_version(data.child_version),
        )
        if parent_id == child_id:
            raise HTTPException(status_code=400, detail="A package version cannot depend on itself")

        cursor.execute(
            """
            INSERT INTO package_deps (parent_version_id, child_version_id)
            VALUES (:parent_id, :child_id)
            """,
            {"parent_id": parent_id, "child_id": child_id},
        )
        connection.commit()
        return {
            "message": "Package dependency added",
            "parent_version_id": parent_id,
            "child_version_id": child_id,
        }

    except oracledb.DatabaseError as exc:
        connection.rollback()
        if "ORA-00001" in str(exc):
            raise HTTPException(status_code=409, detail="This package dependency already exists") from exc
        _db_error(exc)

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@router.delete("/package-deps/{parent_version_id}/{child_version_id}", tags=["Packages"])
def delete_package_dep(parent_version_id: int, child_version_id: int, request: Request):
    require_catalog_editor(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            DELETE FROM package_deps
            WHERE parent_version_id = :parent_id AND child_version_id = :child_id
            """,
            {"parent_id": parent_version_id, "child_id": child_version_id},
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Package dependency not found")

        connection.commit()
        return {"message": "Package dependency removed"}

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


# ------------------------------------------------------------------ Project dependencies

@router.post("/projects/{project_id}/dependencies", status_code=201, tags=["Graph"])
def add_dependency(project_id: int, data: DependencyRequest, request: Request):
    user = get_current_user(request)
    package_name = normalize_package_name(data.package_name)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        _check_project_write(cursor, project_id, user, lock=True)

        version_id = cursor.var(int)
        cursor.callproc(
            "register_dependency",
            [project_id, package_name, *parse_version(data.version), version_id],
        )
        connection.commit()
        return {"message": "Dependency added", "version_id": version_id.getvalue()}

    except oracledb.DatabaseError as exc:
        connection.rollback()
        error = exc.args[0]
        if getattr(error, "code", None) == 20001:
            message = error.message.split("\n")[0].replace("ORA-20001: ", "")
            raise HTTPException(status_code=409, detail=message) from exc
        if "ORA-00001" in str(exc):
            raise HTTPException(status_code=409, detail="This project already uses this version") from exc
        _db_error(exc)

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@router.delete("/projects/{project_id}/dependencies/{version_id}", tags=["Graph"])
def remove_dependency(project_id: int, version_id: int, request: Request):
    user = get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        _check_project_write(cursor, project_id, user, lock=True)

        cursor.execute(
            "DELETE FROM dependencies WHERE project_id = :project_id AND version_id = :version_id",
            {"project_id": project_id, "version_id": version_id},
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="This project does not use this version directly")

        connection.commit()
        return {"message": "Dependency removed"}

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@router.post("/projects/{project_id}/requirements", tags=["Graph"])
def upload_requirements(
    project_id: int,
    request: Request,
    file: UploadFile = File(...),
    commit_sha: Optional[str] = Form(None),
):
    """
    Replace the project's direct dependencies with the exact pins in a requirements.txt.
    Indirect dependencies come from package_deps through the recursive view.
    """
    user = get_current_user(request)

    sha = commit_sha.strip().lower() if commit_sha and commit_sha.strip() else None
    if sha is not None and not re.fullmatch(SHA_PATTERN, sha):
        raise HTTPException(status_code=400, detail="Commit SHA must be 40 hexadecimal characters")

    raw = file.file.read(MAX_REQUIREMENTS_BYTES + 1)
    if len(raw) > MAX_REQUIREMENTS_BYTES:
        raise HTTPException(status_code=413, detail="File is too large")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text")

    pinned, skipped = parse_requirements(text)
    if not pinned:
        raise HTTPException(
            status_code=400,
            detail={"message": "No exact pins (name==version) found", "skipped_lines": skipped},
        )

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        _check_project_write(cursor, project_id, user, lock=True)

        cursor.execute(
            "DELETE FROM dependencies WHERE project_id = :project_id",
            {"project_id": project_id},
        )
        removed = cursor.rowcount

        added = []
        for package_name, parts in sorted(pinned.items()):
            version_id = _ensure_version(cursor, _ensure_package(cursor, package_name), parts)
            cursor.execute(
                "INSERT INTO dependencies (project_id, version_id) VALUES (:project_id, :version_id)",
                {"project_id": project_id, "version_id": version_id},
            )
            added.append({
                "package_name": package_name,
                "version": version_text(parts),
                "version_id": version_id,
            })

        cursor.execute(
            """
            UPDATE projects
            SET scanned_commit_sha = :sha,
                scanned_at = SYSDATE
            WHERE project_id = :project_id
            """,
            {"sha": sha, "project_id": project_id},
        )

        connection.commit()
        return {
            "message": "Requirements scanned",
            "previous_dependencies_removed": removed,
            "dependencies_added": len(added),
            "dependencies": added,
            "skipped_lines": skipped,
        }

    except oracledb.DatabaseError as exc:
        connection.rollback()
        _db_error(exc)

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


@router.get("/projects/{project_id}/dependencies", tags=["Graph"])
def project_dependency_graph(
    project_id: int,
    request: Request,
    max_depth: int = Query(20, ge=1, le=20),
):
    user = get_current_user(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        _check_project_read(cursor, project_id, user)

        cursor.execute(
            """
            SELECT root_version_id, root_package_name, version_id, package_id,
                   package_name, version_text, depth, path_text
            FROM project_all_dependencies
            WHERE project_id = :project_id
              AND depth <= :max_depth
            ORDER BY root_package_name, path_text
            """,
            {"project_id": project_id, "max_depth": max_depth},
        )
        rows = _rows_as_dicts(cursor)

        return {
            "project_id": project_id,
            "summary": {
                "direct_dependencies": len({r["version_id"] for r in rows if r["depth"] == 1}),
                "total_packages": len({r["version_id"] for r in rows}),
                "max_depth": max((r["depth"] for r in rows), default=0),
            },
            "dependencies": rows,
        }

    finally:
        cursor.close()
        connection.close()


@router.get("/packages/{package_id}/used-by", tags=["Graph"])
def package_used_by(package_id: int, request: Request, version: Optional[str] = None):
    """Every project that reaches this package, directly or through other packages."""
    user = get_current_user(request)

    if version is not None and not re.fullmatch(VERSION_PATTERN, version.strip()):
        raise HTTPException(status_code=400, detail="Version must look like 3.1.2")
    major, minor, patch = parse_version(version) if version else (0, 0, 0)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            "SELECT package_name FROM packages WHERE package_id = :package_id",
            {"package_id": package_id},
        )
        row = cursor.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Package not found")

        cursor.execute(
            f"""
            SELECT a.project_id, pr.project_name, t.team_name,
                   a.version_text, a.depth,
                   a.root_package_name,
                   rv.major_no || '.' || rv.minor_no || '.' || rv.patch_no AS root_version_text,
                   a.path_text
            FROM project_all_dependencies a
            JOIN package_versions v  ON v.version_id  = a.version_id
            JOIN package_versions rv ON rv.version_id = a.root_version_id
            JOIN projects pr         ON pr.project_id = a.project_id
            JOIN teams t             ON t.team_id     = pr.owner_team_id
            WHERE a.package_id = :package_id
              AND (:has_version = 0
                   OR (v.major_no = :major AND v.minor_no = :minor AND v.patch_no = :patch))
              AND {VISIBLE_PROJECTS_FILTER}
            ORDER BY pr.project_name, a.depth, a.path_text
            """,
            {
                "package_id": package_id,
                "has_version": 1 if version else 0,
                "major": major,
                "minor": minor,
                "patch": patch,
                **_visibility(user),
            },
        )
        rows = _rows_as_dicts(cursor)

        return {
            "package_name": row[0],
            "version": version_text((major, minor, patch)) if version else None,
            "affected_projects": len({r["project_id"] for r in rows}),
            "paths": rows,
        }

    finally:
        cursor.close()
        connection.close()


# ------------------------------------------------------------------ Analytics

@router.get("/analytics/most-used-packages", tags=["Analytics"])
def most_used_packages(request: Request, limit: int = Query(10, ge=1, le=100)):
    require_reporting(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT package_id, package_name,
                   COUNT(DISTINCT project_id) AS project_count,
                   COUNT(DISTINCT CASE WHEN depth = 1 THEN project_id END) AS used_directly_by,
                   COUNT(DISTINCT CASE WHEN depth > 1 THEN project_id END) AS used_indirectly_by,
                   COUNT(DISTINCT version_id) AS versions_in_use
            FROM project_all_dependencies
            GROUP BY package_id, package_name
            ORDER BY project_count DESC, package_name
            FETCH FIRST :row_limit ROWS ONLY
            """,
            {"row_limit": limit},
        )
        return {"packages": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()


@router.get("/analytics/shared-dependencies", tags=["Analytics"])
def shared_dependencies(request: Request):
    require_reporting(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            WITH used AS (
                SELECT DISTINCT project_id, version_id, package_name, version_text
                FROM project_all_dependencies
            )
            SELECT a.project_id AS project_a_id, pa.project_name AS project_a,
                   b.project_id AS project_b_id, pb.project_name AS project_b,
                   COUNT(*) AS shared_count,
                   LISTAGG(a.package_name || ' ' || a.version_text, ', ' ON OVERFLOW TRUNCATE)
                       WITHIN GROUP (ORDER BY a.package_name) AS shared_packages
            FROM used a
            JOIN used b      ON b.version_id = a.version_id AND b.project_id > a.project_id
            JOIN projects pa ON pa.project_id = a.project_id
            JOIN projects pb ON pb.project_id = b.project_id
            GROUP BY a.project_id, pa.project_name, b.project_id, pb.project_name
            ORDER BY shared_count DESC, pa.project_name
            """
        )
        return {"project_pairs": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()


@router.get("/analytics/dependency-depth", tags=["Analytics"])
def dependency_depth(request: Request):
    require_reporting(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            WITH totals AS (
                SELECT project_id,
                       COUNT(DISTINCT CASE WHEN depth = 1 THEN version_id END) AS direct_count,
                       COUNT(DISTINCT version_id) AS total_count,
                       MAX(depth) AS max_depth
                FROM project_all_dependencies
                GROUP BY project_id
            ),
            ranked AS (
                SELECT project_id, path_text,
                       ROW_NUMBER() OVER (PARTITION BY project_id
                                          ORDER BY depth DESC, path_text) AS rn
                FROM project_all_dependencies
            )
            SELECT p.project_id, p.project_name,
                   NVL(t.direct_count, 0) AS direct_dependencies,
                   NVL(t.total_count, 0) AS total_packages,
                   NVL(t.total_count, 0) - NVL(t.direct_count, 0) AS indirect_only,
                   NVL(t.max_depth, 0) AS max_depth,
                   r.path_text AS deepest_path
            FROM projects p
            LEFT JOIN totals t ON t.project_id = p.project_id
            LEFT JOIN ranked r ON r.project_id = p.project_id AND r.rn = 1
            ORDER BY max_depth DESC, p.project_name
            """
        )
        return {"projects": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()


@router.get("/analytics/version-drift", tags=["Analytics"])
def version_drift(request: Request):
    """Packages that different projects use at different versions."""
    require_reporting(request)

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            WITH used AS (
                SELECT a.package_id, a.package_name, a.version_text,
                       v.major_no, v.minor_no, v.patch_no,
                       COUNT(DISTINCT a.project_id) AS project_count
                FROM project_all_dependencies a
                JOIN package_versions v ON v.version_id = a.version_id
                GROUP BY a.package_id, a.package_name, a.version_text,
                         v.major_no, v.minor_no, v.patch_no
            )
            SELECT package_id, package_name,
                   COUNT(*) AS distinct_versions,
                   LISTAGG(version_text || ' (' || project_count || ')', ', ')
                       WITHIN GROUP (ORDER BY major_no, minor_no, patch_no) AS versions_with_project_count
            FROM used
            GROUP BY package_id, package_name
            HAVING COUNT(*) > 1
            ORDER BY distinct_versions DESC, package_name
            """
        )
        return {"packages": _rows_as_dicts(cursor)}

    finally:
        cursor.close()
        connection.close()
