CREATE TABLE favourite_organisations (
  human_id TEXT NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  organisation_id TEXT NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (human_id, organisation_id)
);
