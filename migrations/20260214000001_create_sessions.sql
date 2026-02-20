CREATE TABLE sessions (
  id SERIAL PRIMARY KEY,
  human_id INTEGER NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_human_id ON sessions(human_id);
