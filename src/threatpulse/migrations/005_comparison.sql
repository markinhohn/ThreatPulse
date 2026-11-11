-- A study is a fully validated, frozen collection, separate from dashboard CVEs.
CREATE TABLE comparison_studies (
    study_id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_start DATE NOT NULL,
    published_end DATE NOT NULL,
    score_date DATE NOT NULL,
    dataset JSONB NOT NULL CHECK (jsonb_typeof(dataset) = 'object'),
    CHECK (published_end > published_start AND published_end - published_start <= 120)
);
CREATE INDEX comparison_studies_dates ON comparison_studies (published_start, published_end);
