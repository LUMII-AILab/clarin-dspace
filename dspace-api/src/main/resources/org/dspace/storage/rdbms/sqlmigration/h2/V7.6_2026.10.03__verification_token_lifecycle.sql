--
-- The contents of this file are subject to the license and copyright
-- detailed in the LICENSE and NOTICE files at the root of the source
-- tree and available online at
--
-- http://www.dspace.org/license/
--

ALTER TABLE verification_token ADD COLUMN request_token varchar(64);
ALTER TABLE verification_token ADD COLUMN expires timestamp;
