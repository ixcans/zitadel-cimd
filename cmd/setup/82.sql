ALTER TABLE IF EXISTS projections.security_policies3
ADD COLUMN IF NOT EXISTS client_id_metadata_document_allowed_audiences TEXT[];
