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
provided if you create the extension.

Example
-------

```
rjuju=# CREATE EXTENSION pg_stat_statements;
CREATE EXTENSION

rjuju=# CREATE EXTENSION pg_queryid;
CREATE EXTENSION

rjuju=# CREATE SCHEMA ns1;
CREATE SCHEMA

rjuju=# CREATE TABLE ns1.tbl1(id integer);
CREATE TABLE

rjuju=# CREATE SCHEMA ns2;
CREATE SCHEMA

rjuju=# CREATE TABLE ns2.tbl1(id integer);
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

rjuju=# SELECT count(*) from tbl1;
 count
-------
     0
(1 row)

rjuju=# SELECT public.pg_queryid('SELECT count(*) from tbl1');
     pg_queryid
---------------------
 4629593225724429059
(1 row)

rjuju=# SET search_path TO ns2;
SET

rjuju=# SELECT count(*) from tbl1;
 count
-------
     0
(1 row)

rjuju=# SELECT public.pg_queryid('SELECT count(*) from tbl1');
     pg_queryid
---------------------
 4629593225724429059
(1 row)

rjuju=# SELECT queryid, query, calls FROM public.pg_stat_statements WHERE query LIKE '%tbl%';
       queryid       |           query           | calls
---------------------+---------------------------+-------
 4629593225724429059 | SELECT count(*) from tbl1 |     2
(1 row)
```
