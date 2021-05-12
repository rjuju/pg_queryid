pg_queryid
==========

/!\ This extension is a POC, not ready for production. /!\

External query fingerprinting module for PostgreSQL with configurable
heuristics for the query identifiers calculation.

Installation
------------

- Compatible with PostgreSQL 14 and above
- Needs PostgreSQL header files
- Decompress the tarball or clone the repository
- `sudo make install`
- add "pg_queryid" as the last element in shared_preload_libraries
- make sure to disable compute_query_id
- restart PostgreSQL
- optionally, create the extension "pg_queryid"

Configuration
-------------

The following configuration options are available:

- pg_queryid.use_object_names: Compute a query identifier based on object names
  rather than Oids.

- pg_queryid.ignore_schema: Requires use_object_names to be enabled.  Compute a
  query ifentifier based on unqualified object names.

/!\ Using object names rather than Oids can add a big overhead. /!\

Note that changing any of those options will have side effects on any extension
using the query identifiers.  If you're using pg_stat_statements, you should
call `pg_stat_statements_reset()` after changing this parameter, and similarly
for any other third-party extensions.

Usage
-----

Once the module is loaded in shared_preload_libraries, it will automatically be
used to compute query identifiers.

An SQL function to compute query identifier for any given query text is also
provided if you create the extension.  This function can be used to compute
either this extension's query identifier, or postgres core one if the module
isn't loaded with shared_preload_libraries.

Example
-------

```
rjuju=# CREATE EXTENSION pg_stat_statements;
CREATE EXTENSION

rjuju=# CREATE EXTENSION pg_queryid;
CREATE EXTENSION

rjuju=# CREATE SCHEMA ns1;
CREATE SCHEMA

rjuju=# CREATE TABLE ns1.tbl1 AS SELECT 'ns1' AS val;
CREATE TABLE

rjuju=# CREATE SCHEMA ns2;
CREATE SCHEMA

rjuju=# CREATE TABLE ns2.tbl1 AS SELECT 'ns2' AS val;
CREATE TABLE

rjuju=# SHOW shared_preload_libraries;
    shared_preload_libraries
-------------------------------
 pg_stat_statements,pg_queryid
(1 row)

rjuju=# SHOW compute_query_id;
 compute_query_id
------------------
 off
(1 row)

rjuju=# SHOW pg_queryid.use_object_names;
 pg_queryid.use_object_names
-----------------------------
 on
(1 row)

rjuju=# SHOW pg_queryid.ignore_schema;
 pg_queryid.ignore_schema
--------------------------
 on
(1 row)

rjuju=# SELECT pg_stat_statements_reset();
 pg_stat_statements_reset
--------------------------

(1 row)

rjuju=# SET search_path TO ns1;
SET

rjuju=# SELECT * from tbl1;
 val 
-----
 ns1
(1 row)

rjuju=# SELECT public.pg_queryid('SELECT * from tbl1');
     pg_queryid
---------------------
 8597862845229905026
(1 row)

rjuju=# SET search_path TO ns2;
SET

rjuju=# SELECT * from tbl1;
 val 
-----
 ns2
(1 row)

rjuju=# SELECT public.pg_queryid('SELECT * from tbl1');
     pg_queryid
---------------------
 8597862845229905026
(1 row)

rjuju=# SELECT queryid, query, calls FROM public.pg_stat_statements WHERE query LIKE '%tbl%';
       queryid       |       query        | calls 
---------------------+--------------------+-------
 8597862845229905026 | SELECT * FROM tbl1 |     2
(1 row)

rjuju=# RESET search_path;
RESET

rjuju=# CREATE TEMPORARY TABLE tmptbl(val text);
CREATE TABLE

rjuju=# SET pg_queryid.ignore_temp_tables = on;
SET

rjuju=# SELECT COUNT(*) FROM tmptbl;
 count
-------
     0
(1 row)

rjuju=# SELECT COUNT(*) public.pg_stat_statements WHERE query LIKE '%tmptbl%';
 count
-------
     0
(1 row)

```
