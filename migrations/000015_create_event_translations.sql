CREATE TABLE event_translations (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  language_id TEXT NOT NULL REFERENCES languages(id) ON DELETE CASCADE,
  title VARCHAR(256) NOT NULL,
  description TEXT NOT NULL,
  UNIQUE(event_id, language_id)
);

CREATE INDEX idx_event_translations_event_id ON event_translations(event_id);
