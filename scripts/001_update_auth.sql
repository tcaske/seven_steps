-- =============================================================================
-- Oracle Database Script voor Authenticatie-uitbreiding
-- =============================================================================
-- Dit script past de bestaande SEV_APP_USERS tabel aan om ondersteuning
-- voor traditionele (wachtwoord) en Google-aanmeldingen toe te voegen.
--
-- Aangemaakt op: 2026-01-01
-- =============================================================================

-- Voeg een kolom toe voor de password hash
-- Deze is nullable, omdat gebruikers ook via social media (Google) kunnen aanmelden.
ALTER TABLE SEV_APP_USERS ADD password_hash VARCHAR2(255) NULL;

COMMENT ON COLUMN SEV_APP_USERS.password_hash IS 'Gehashte versie van het wachtwoord van de gebruiker voor traditionele login.';

-- Voeg een kolom toe voor de unieke Google User ID
-- Deze is nullable en uniek, voor gebruikers die via Google aanmelden.
ALTER TABLE SEV_APP_USERS ADD google_user_id VARCHAR2(255) NULL;

COMMENT ON COLUMN SEV_APP_USERS.google_user_id IS 'Unieke identifier van de gebruiker bij Google.';

-- Voeg een unieke constraint toe op de google_user_id kolom
ALTER TABLE SEV_APP_USERS ADD CONSTRAINT uq_sev_google_user_id UNIQUE (google_user_id);


-- =============================================================================
-- Einde van het script
-- =============================================================================
