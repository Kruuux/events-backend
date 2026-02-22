CREATE TABLE city_translations (
  id TEXT PRIMARY KEY,
  city_id TEXT NOT NULL REFERENCES cities(id) ON DELETE CASCADE,
  language_id TEXT NOT NULL REFERENCES languages(id) ON DELETE CASCADE,
  name VARCHAR(256) NOT NULL,
  UNIQUE(city_id, language_id)
);

CREATE INDEX idx_city_translations_city_id ON city_translations(city_id);
