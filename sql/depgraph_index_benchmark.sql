-- DepGraph index benchmark (Oracle)
-- Builds a synthetic dependency graph of 200,000 package versions in a separate
-- table, then times recursive traversals with and without indexes.
-- Run as the depgraph user with Run Script (F5). Real tables are not touched.

SET SERVEROUTPUT ON;

DROP TABLE IF EXISTS bench_deps PURGE;

CREATE TABLE bench_deps (
    parent_version_id NUMBER NOT NULL,
    child_version_id  NUMBER NOT NULL
);

-- Tree with about 3 children per version: version i depends on versions 3i-1, 3i, 3i+1
INSERT INTO bench_deps (parent_version_id, child_version_id)
SELECT FLOOR((LEVEL + 2) / 3), LEVEL + 1
FROM dual
CONNECT BY LEVEL <= 199999;
COMMIT;

BEGIN
    DBMS_STATS.GATHER_TABLE_STATS(USER, 'BENCH_DEPS');
END;
/

SELECT COUNT(*) AS edges,
       COUNT(DISTINCT parent_version_id) AS parents
FROM bench_deps;

CREATE OR REPLACE PROCEDURE bench_run (p_label IN VARCHAR2)
IS
    v_count   NUMBER;
    v_start   TIMESTAMP;
    v_ms      NUMBER;

    c_forward CONSTANT VARCHAR2(1000) :=
        'WITH t (v, d) AS (
             SELECT 1, 1 FROM dual
             UNION ALL
             SELECT b.child_version_id, t.d + 1
             FROM t JOIN bench_deps b ON b.parent_version_id = t.v
             WHERE t.d < 20)
         CYCLE v SET is_cycle TO ''Y'' DEFAULT ''N''
         SELECT COUNT(*) FROM t';

    c_subtree CONSTANT VARCHAR2(1000) :=
        'WITH t (v, d) AS (
             SELECT 2000, 1 FROM dual
             UNION ALL
             SELECT b.child_version_id, t.d + 1
             FROM t JOIN bench_deps b ON b.parent_version_id = t.v
             WHERE t.d < 20)
         CYCLE v SET is_cycle TO ''Y'' DEFAULT ''N''
         SELECT COUNT(*) FROM t';

    c_reverse CONSTANT VARCHAR2(1000) :=
        'WITH t (v, d) AS (
             SELECT 200000, 1 FROM dual
             UNION ALL
             SELECT b.parent_version_id, t.d + 1
             FROM t JOIN bench_deps b ON b.child_version_id = t.v
             WHERE t.d < 20)
         CYCLE v SET is_cycle TO ''Y'' DEFAULT ''N''
         SELECT COUNT(*) FROM t';

    PROCEDURE run_one (p_name IN VARCHAR2, p_sql IN VARCHAR2, p_reps IN PLS_INTEGER)
    IS
    BEGIN
        EXECUTE IMMEDIATE p_sql INTO v_count;
        v_start := SYSTIMESTAMP;
        FOR i IN 1 .. p_reps LOOP
            EXECUTE IMMEDIATE p_sql INTO v_count;
        END LOOP;
        v_ms := (EXTRACT(SECOND FROM (SYSTIMESTAMP - v_start))
                 + 60 * EXTRACT(MINUTE FROM (SYSTIMESTAMP - v_start))) * 1000 / p_reps;
        DBMS_OUTPUT.PUT_LINE(RPAD(p_label, 16) || RPAD(p_name, 34)
            || LPAD(v_count, 8) || ' rows ' || LPAD(TO_CHAR(v_ms, 'FM99990.000'), 12) || ' ms');
    END;
BEGIN
    run_one('full tree from root',          c_forward, 3);
    run_one('subtree of one package',       c_subtree, 50);
    run_one('reverse: who uses a package',  c_reverse, 200);
END;
/

-- Run 1: no indexes
EXEC bench_run('NO INDEX');

EXPLAIN PLAN SET STATEMENT_ID = 'rev_noidx' FOR
WITH t (v, d) AS (
    SELECT 200000, 1 FROM dual
    UNION ALL
    SELECT b.parent_version_id, t.d + 1
    FROM t JOIN bench_deps b ON b.child_version_id = t.v
    WHERE t.d < 20)
CYCLE v SET is_cycle TO 'Y' DEFAULT 'N'
SELECT COUNT(*) FROM t;

SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY(NULL, 'rev_noidx', 'BASIC'));

-- Run 2: same indexes as the real schema
-- (pk_package_deps starts with parent_version_id; idx_pdeps_child is on child_version_id)
CREATE INDEX bench_parent_idx ON bench_deps (parent_version_id, child_version_id);
CREATE INDEX bench_child_idx  ON bench_deps (child_version_id);

BEGIN
    DBMS_STATS.GATHER_TABLE_STATS(USER, 'BENCH_DEPS', cascade => TRUE);
END;
/

EXEC bench_run('WITH INDEX');

EXPLAIN PLAN SET STATEMENT_ID = 'rev_idx' FOR
WITH t (v, d) AS (
    SELECT 200000, 1 FROM dual
    UNION ALL
    SELECT b.parent_version_id, t.d + 1
    FROM t JOIN bench_deps b ON b.child_version_id = t.v
    WHERE t.d < 20)
CYCLE v SET is_cycle TO 'Y' DEFAULT 'N'
SELECT COUNT(*) FROM t;

SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY(NULL, 'rev_idx', 'BASIC'));

-- Clean up
DROP PROCEDURE bench_run;
DROP TABLE bench_deps PURGE;
