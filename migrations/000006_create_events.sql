CREATE TABLE events (
  id TEXT PRIMARY KEY,
  human_id TEXT NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  organisation_id TEXT REFERENCES organisations(id) ON DELETE SET NULL,
  place_id TEXT NOT NULL REFERENCES places(id) ON DELETE RESTRICT,
  start_date TIMESTAMPTZ NOT NULL,
  end_date TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_events_human_id ON events(human_id);
CREATE INDEX idx_events_organisation_id ON events(organisation_id);
CREATE INDEX idx_events_place_id ON events(place_id);
