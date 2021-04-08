/* contrib/pg_stat_statements/pg_stat_statements--1.4.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_queryid" to load this file. \quit

-- Register functions.
CREATE FUNCTION pg_queryid(IN querytext text)
RETURNS bigint
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;
