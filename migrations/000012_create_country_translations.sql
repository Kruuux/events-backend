CREATE TABLE country_translations (
  id TEXT PRIMARY KEY,
  country_id TEXT NOT NULL REFERENCES countries(id) ON DELETE CASCADE,
  language_id TEXT NOT NULL REFERENCES languages(id) ON DELETE CASCADE,
  name VARCHAR(256) NOT NULL,
  UNIQUE(country_id, language_id)
);

CREATE INDEX idx_country_translations_country_id ON country_translations(country_id);
