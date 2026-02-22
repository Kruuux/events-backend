CREATE TABLE favourite_places (
  human_id TEXT NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  place_id TEXT NOT NULL REFERENCES places(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (human_id, place_id)
);
