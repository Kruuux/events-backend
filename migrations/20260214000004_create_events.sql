CREATE TABLE events (
  id TEXT PRIMARY KEY,
  human_id TEXT NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  organisation_id TEXT REFERENCES organisations(id) ON DELETE SET NULL,
  title VARCHAR(256) NOT NULL,
  description TEXT NOT NULL,
  latitude DOUBLE PRECISION NOT NULL,
  longitude DOUBLE PRECISION NOT NULL,
  start_date TIMESTAMPTZ NOT NULL,
  end_date TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_human_id ON events(human_id);
CREATE INDEX idx_events_organisation_id ON events(organisation_id);
