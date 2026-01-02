-- =============================================================================
-- Oracle Package voor Authenticatie (SEV_AUTH_PKG)
-- =============================================================================
-- Dit package bevat de logica voor het registreren en aanmelden van gebruikers,
-- inclusief veilig hashen van wachtwoorden en Google Sign-In.
--
-- Vereist dat de 'EXECUTE' grant op DBMS_CRYPTO is gegeven aan de schema owner:
-- GRANT EXECUTE ON SYS.DBMS_CRYPTO TO your_schema_name;
--
-- Aangemaakt op: 2026-01-01
-- =============================================================================

CREATE OR REPLACE PACKAGE SEV_AUTH_PKG AS

    -- Registreert een nieuwe gebruiker met e-mail en wachtwoord
    PROCEDURE register_user (
        p_username IN VARCHAR2,
        p_email    IN VARCHAR2,
        p_password IN VARCHAR2
    );

    -- Valideert de inloggegevens en retourneert de user_id bij succes
    FUNCTION login_user (
        p_email    IN VARCHAR2,
        p_password IN VARCHAR2
    ) RETURN NUMBER;

    -- Handelt de aanmelding via Google af.
    -- Creëert een nieuwe gebruiker als deze niet bestaat, anders logt het de gebruiker in.
    FUNCTION handle_google_signin (
        p_google_user_id IN VARCHAR2,
        p_email          IN VARCHAR2,
        p_username       IN VARCHAR2
    ) RETURN NUMBER;

END SEV_AUTH_PKG;
/

CREATE OR REPLACE PACKAGE BODY SEV_AUTH_PKG AS

    -- Private constant voor de salt.
    -- !! SECURITY BEST PRACTICE !!
    -- In een productie-omgeving, gebruik een unieke, willekeurige salt per gebruiker
    -- en sla deze op in een aparte kolom in de SEV_APP_USERS tabel.
    G_SALT CONSTANT VARCHAR2(100) := 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0';

    -- Private functie voor het hashen van wachtwoorden
    FUNCTION hash_password (
        p_password IN VARCHAR2
    ) RETURN VARCHAR2 AS
    BEGIN
        IF p_password IS NULL THEN
            RETURN NULL;
        END IF;

        RETURN DBMS_CRYPTO.HASH(
            src => UTL_RAW.CAST_TO_RAW(p_password || G_SALT),
            typ => DBMS_CRYPTO.HASH_SH512
        );
    END;

    -- Implementatie van de register_user procedure
    PROCEDURE register_user (
        p_username IN VARCHAR2,
        p_email    IN VARCHAR2,
        p_password IN VARCHAR2
    ) AS
        l_user_count NUMBER;
    BEGIN
        -- Validatie: controleer of e-mail al in gebruik is
        SELECT COUNT(*) INTO l_user_count FROM SEV_APP_USERS WHERE email = p_email;
        IF l_user_count > 0 THEN
            RAISE_APPLICATION_ERROR(-20001, 'E-mailadres is al in gebruik.');
        END IF;

        -- Validatie: controleer of gebruikersnaam al in gebruik is
        SELECT COUNT(*) INTO l_user_count FROM SEV_APP_USERS WHERE username = p_username;
        IF l_user_count > 0 THEN
            RAISE_APPLICATION_ERROR(-20002, 'Gebruikersnaam is al in gebruik.');
        END IF;
        
        -- Voeg de nieuwe gebruiker toe
        INSERT INTO SEV_APP_USERS (
            username,
            email,
            password_hash
        ) VALUES (
            p_username,
            p_email,
            hash_password(p_password)
        );
    END register_user;


    -- Implementatie van de login_user functie
    FUNCTION login_user (
        p_email    IN VARCHAR2,
        p_password IN VARCHAR2
    ) RETURN NUMBER AS
        l_user_rec SEV_APP_USERS%ROWTYPE;
    BEGIN
        -- Zoek gebruiker op basis van e-mail
        BEGIN
            SELECT * INTO l_user_rec FROM SEV_APP_USERS WHERE email = p_email;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                RETURN NULL; -- Gebruiker niet gevonden
        END;

        -- Vergelijk de gehashte wachtwoorden
        IF l_user_rec.password_hash = hash_password(p_password) THEN
            RETURN l_user_rec.id; -- Succesvolle login
        ELSE
            RETURN NULL; -- Ongeldig wachtwoord
        END IF;
    EXCEPTION
        WHEN OTHERS THEN
            RETURN NULL; -- Fout tijdens het proces
    END login_user;


    -- Implementatie van de handle_google_signin functie
    FUNCTION handle_google_signin (
        p_google_user_id IN VARCHAR2,
        p_email          IN VARCHAR2,
        p_username       IN VARCHAR2
    ) RETURN NUMBER AS
        l_user_id NUMBER;
        l_user_rec SEV_APP_USERS%ROWTYPE;
    BEGIN
        -- 1. Controleer of de Google gebruiker al bestaat
        BEGIN
            SELECT id INTO l_user_id FROM SEV_APP_USERS WHERE google_user_id = p_google_user_id;
            RETURN l_user_id; -- Gebruiker bestaat, login succesvol
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                NULL; -- Ga verder naar de volgende stap
        END;

        -- 2. Controleer of het e-mailadres al bestaat (en koppel het account)
        BEGIN
            SELECT * INTO l_user_rec FROM SEV_APP_USERS WHERE email = p_email;

            -- E-mailadres bestaat, koppel het Google account
            UPDATE SEV_APP_USERS
            SET google_user_id = p_google_user_id
            WHERE id = l_user_rec.id;

            RETURN l_user_rec.id;
        EXCEPTION
            WHEN NO_DATA_FOUND THEN
                NULL; -- Ga verder naar de volgende stap
        END;
        
        -- 3. Gebruiker bestaat nog niet, maak een nieuwe aan
        INSERT INTO SEV_APP_USERS (
            username,
            email,
            google_user_id
        ) VALUES (
            p_username,
            p_email,
            p_google_user_id
        ) RETURNING id INTO l_user_id;
        
        RETURN l_user_id;

    EXCEPTION
        WHEN OTHERS THEN
            -- Vang mogelijke duplicate key errors op username/email voor het geval er een race condition is
            RETURN NULL;
    END handle_google_signin;

END SEV_AUTH_PKG;
/
-- =============================================================================
-- Einde van het script
-- =============================================================================
