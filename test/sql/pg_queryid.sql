SHOW shared_preload_libraries;
SHOW compute_query_id;

CREATE EXTENSION pg_stat_statements;

CREATE SCHEMA ns1;
CREATE TABLE ns1.tbl1 AS SELECT 'ns1' AS val;

CREATE SCHEMA ns2;
CREATE TABLE ns2.tbl1 AS SELECT 'ns2' AS val;

CREATE TEMPORARY TABLE tmptbl(val text);

SET pg_queryid.use_object_names = on;
SET pg_queryid.ignore_schema = on;
SET pg_queryid.ignore_temp_tables = on;

SELECT * FROM pg_stat_statements_reset();

SET search_path to ns1;
SELECT * FROM tbl1;

SET search_path to ns2;
SELECT * FROM tbl1;

RESET search_path;
SELECT * FROM tmptbl;

SELECT queryid, query, calls FROM public.pg_stat_statements WHERE query LIKE '%tbl%';

SELECT * FROM pg_stat_statements_reset();

SET pg_queryid.ignore_temp_tables = off;
SELECT * FROM tmptbl;

SELECT queryid, query, calls FROM public.pg_stat_statements WHERE query LIKE '%tbl%';
