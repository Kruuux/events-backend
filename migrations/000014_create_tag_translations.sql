CREATE TABLE tag_translations (
  id TEXT PRIMARY KEY,
  tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  language_id TEXT NOT NULL REFERENCES languages(id) ON DELETE CASCADE,
  name VARCHAR(256) NOT NULL,
  UNIQUE(tag_id, language_id)
);

CREATE INDEX idx_tag_translations_tag_id ON tag_translations(tag_id);
