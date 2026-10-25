-- DepGraph PL/SQL objects (Oracle)
-- Run after depgraph_schema.sql

CREATE OR REPLACE TRIGGER trg_packages_normalize
BEFORE INSERT OR UPDATE OF package_name ON packages
FOR EACH ROW
BEGIN
    :NEW.package_name := LOWER(REGEXP_REPLACE(TRIM(:NEW.package_name), '[-_.]+', '-'));
END;
/

CREATE OR REPLACE FUNCTION version_cmp (
    a_major IN NUMBER, a_minor IN NUMBER, a_patch IN NUMBER,
    b_major IN NUMBER, b_minor IN NUMBER, b_patch IN NUMBER
) RETURN NUMBER DETERMINISTIC
IS
BEGIN
    IF a_major <> b_major THEN
        RETURN SIGN(a_major - b_major);
    END IF;
    IF a_minor <> b_minor THEN
        RETURN SIGN(a_minor - b_minor);
    END IF;
    RETURN SIGN(a_patch - b_patch);
END;
/

CREATE OR REPLACE PROCEDURE register_dependency (
    p_project_id   IN  NUMBER,
    p_package_name IN  VARCHAR2,
    p_major        IN  NUMBER,
    p_minor        IN  NUMBER,
    p_patch        IN  NUMBER,
    p_version_id   OUT NUMBER
)
IS
    v_name       packages.package_name%TYPE :=
                     LOWER(REGEXP_REPLACE(TRIM(p_package_name), '[-_.]+', '-'));
    v_package_id packages.package_id%TYPE;
    v_existing   VARCHAR2(40);
BEGIN
    BEGIN
        SELECT package_id INTO v_package_id
        FROM packages
        WHERE ecosystem = 'PyPI' AND package_name = v_name;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            INSERT INTO packages (package_name)
            VALUES (v_name)
            RETURNING package_id INTO v_package_id;
    END;

    BEGIN
        SELECT version_id INTO p_version_id
        FROM package_versions
        WHERE package_id = v_package_id
          AND major_no = p_major AND minor_no = p_minor AND patch_no = p_patch;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            INSERT INTO package_versions (package_id, major_no, minor_no, patch_no)
            VALUES (v_package_id, p_major, p_minor, p_patch)
            RETURNING version_id INTO p_version_id;
    END;

    SELECT MAX(v.major_no || '.' || v.minor_no || '.' || v.patch_no)
    INTO v_existing
    FROM dependencies d
    JOIN package_versions v ON v.version_id = d.version_id
    WHERE d.project_id = p_project_id
      AND v.package_id = v_package_id
      AND d.version_id <> p_version_id;

    IF v_existing IS NOT NULL THEN
        RAISE_APPLICATION_ERROR(-20001,
            'This project already uses ' || v_name || ' ' || v_existing || '. Remove it first');
    END IF;

    INSERT INTO dependencies (project_id, version_id)
    VALUES (p_project_id, p_version_id);
END;
/

CREATE OR REPLACE PROCEDURE show_dependency_tree (p_project_id IN NUMBER)
IS
    CURSOR c_tree IS
        SELECT depth, package_name, version_text
        FROM project_all_dependencies
        WHERE project_id = p_project_id
        ORDER BY root_package_name, path_text;

    v_row c_tree%ROWTYPE;
BEGIN
    OPEN c_tree;
    LOOP
        FETCH c_tree INTO v_row;
        EXIT WHEN c_tree%NOTFOUND;
        DBMS_OUTPUT.PUT_LINE(
            LPAD(' ', (v_row.depth - 1) * 4) || v_row.package_name || ' ' || v_row.version_text);
    END LOOP;

    IF c_tree%ROWCOUNT = 0 THEN
        DBMS_OUTPUT.PUT_LINE('No dependencies found for project ' || p_project_id);
    ELSE
        DBMS_OUTPUT.PUT_LINE(c_tree%ROWCOUNT || ' packages in total');
    END IF;

    CLOSE c_tree;
END;
/
