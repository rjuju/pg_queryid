CREATE EXTENSION pg_stat_statements;
CREATE EXTENSION pg_queryid;

CREATE SCHEMA ns1;
CREATE TABLE ns1.tbl1(id integer);
CREATE SCHEMA ns2;
CREATE TABLE ns2.tbl1(id integer);

SHOW shared_preload_libraries;
SHOW compute_query_id;
SHOW pg_queryid.use_object_names;
SHOW pg_queryid.ignore_schema;

SELECT pg_stat_statements_reset();

SET search_path TO ns1;
SELECT count(*) from tbl1;
SELECT public.pg_queryid('SELECT count(*) from tbl1');

SET search_path TO ns2;
SELECT count(*) from tbl1;
SELECT public.pg_queryid('SELECT count(*) from tbl1');

SELECT queryid, query, calls FROM public.pg_stat_statements WHERE query LIKE '%tbl%';
