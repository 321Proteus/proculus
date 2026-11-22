-- What a saved run needs beyond the initial tables, so that a run can be stored
-- and read back completely (see libs/pgstore).
--
--  * scan_runs: where the run came from and its counters.
--  * observations: the host name goes on the host-level row (port IS NULL).
--  * http_observations: the parts of a web result that have no column yet
--    (URL, server, content type, detections), sealed like the rest, and one row
--    per service per run.

ALTER TABLE scan_runs
    ADD COLUMN source           text    NOT NULL DEFAULT '',
    ADD COLUMN chunks           integer NOT NULL DEFAULT 0,
    ADD COLUMN pauses           integer NOT NULL DEFAULT 0,
    ADD COLUMN cancelled_chunks integer NOT NULL DEFAULT 0;

ALTER TABLE observations
    ADD COLUMN hostname text;

ALTER TABLE http_observations
    ADD COLUMN meta_enc       bytea,
    ADD COLUMN detections_enc bytea;

CREATE UNIQUE INDEX http_observations_run_key ON http_observations (run_id, ip, port);
