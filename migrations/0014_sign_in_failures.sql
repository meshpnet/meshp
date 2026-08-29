-- +goose Up

-- What ADR-0024 asked for and did not build (#148, ADR-0027).
--
-- Sign-in is throttled per address by the same limiter the enrolment endpoints use, which is
-- deliberately generous and bounds a flood from one host. It does nothing about a patient
-- attempt on one account spread across many hosts, and Argon2id at 64 MiB makes each guess
-- cost a tenth of a second rather than making it impossible.
--
-- Here rather than in memory because the control plane is meant to run as more than one
-- instance. A counter held in one process is one an attacker walks around by spreading
-- attempts across replicas, and each would see a count of one.
CREATE TABLE sign_in_failures (
    -- SHA-256 of the lowercased address, not the address.
    --
    -- Failures are counted for addresses that have no account, because a known address that
    -- is throttled and an unknown one that is not would answer "does this person have an
    -- account here" to anybody who cares to measure — the question the single shared refusal
    -- message exists to avoid answering.
    --
    -- Which means an attacker chooses what goes in this table. A hash is a fixed-size key
    -- that answers the only question this table is asked, and it keeps the addresses of
    -- people who have no account here from accumulating in a deployment's database.
    email_hash      bytea PRIMARY KEY,

    -- Consecutive failures. Reset by a success, and by an hour of quiet.
    failures        integer NOT NULL DEFAULT 1,

    -- When this run of failures started, so a log line can say how long an account has been
    -- guessed at rather than only that it is being guessed at now.
    first_failed_at timestamptz NOT NULL DEFAULT now(),
    last_failed_at  timestamptz NOT NULL DEFAULT now()
);

-- The sweep's access path. Rows are read by primary key and deleted by age, and there is no
-- third question anybody asks this table.
CREATE INDEX sign_in_failures_last_failed_idx ON sign_in_failures (last_failed_at);

-- +goose Down

DROP TABLE IF EXISTS sign_in_failures;
