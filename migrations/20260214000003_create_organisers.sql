CREATE TABLE organisers (
  id TEXT PRIMARY KEY,
  human_id TEXT NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  organisation_id TEXT NOT NULL REFERENCES organisations(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (human_id, organisation_id)
);

CREATE INDEX idx_organisers_human_id ON organisers(human_id);
CREATE INDEX idx_organisers_organisation_id ON organisers(organisation_id);
