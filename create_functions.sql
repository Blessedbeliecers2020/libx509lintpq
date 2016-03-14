CREATE OR REPLACE FUNCTION x509lint_embedded(bytea,integer) RETURNS SETOF text
	AS '$libdir/libx509lintpq.so' LANGUAGE c IMMUTABLE;
