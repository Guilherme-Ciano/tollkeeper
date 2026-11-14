CREATE TABLE IF NOT EXISTS tollkeeper_audit (
    chain_id text        NOT NULL,
    seq      bigint      NOT NULL CHECK (seq > 0),
    ts       timestamptz NOT NULL,
    kind     text        NOT NULL CHECK (kind IN ('event', 'checkpoint')),
    hash     char(64)    NOT NULL,
    prev     char(64)    NOT NULL,
    body     jsonb       NOT NULL,
    raw      text        NOT NULL,
    PRIMARY KEY (chain_id, seq)
);

CREATE INDEX IF NOT EXISTS tollkeeper_audit_ts ON tollkeeper_audit (ts);

CREATE OR REPLACE FUNCTION tollkeeper_audit_reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'tollkeeper_audit is append-only: % is not allowed', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE OR REPLACE FUNCTION tollkeeper_audit_check_chain() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.hash <> encode(sha256(decode(NEW.prev, 'hex') || convert_to(NEW.raw, 'UTF8')), 'hex') THEN
        RAISE EXCEPTION 'chain % record %: hash does not match its content', NEW.chain_id, NEW.seq
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.seq = 1 THEN
        IF NEW.prev <> repeat('0', 64) THEN
            RAISE EXCEPTION 'chain % must start from the zero hash', NEW.chain_id
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NOT EXISTS (
        SELECT 1 FROM tollkeeper_audit
        WHERE chain_id = NEW.chain_id AND seq = NEW.seq - 1 AND hash = NEW.prev
    ) THEN
        RAISE EXCEPTION 'chain % record % does not link to record %', NEW.chain_id, NEW.seq, NEW.seq - 1
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE TRIGGER tollkeeper_audit_chain
    BEFORE INSERT ON tollkeeper_audit
    FOR EACH ROW EXECUTE FUNCTION tollkeeper_audit_check_chain();

CREATE OR REPLACE TRIGGER tollkeeper_audit_no_update
    BEFORE UPDATE OR DELETE ON tollkeeper_audit
    FOR EACH ROW EXECUTE FUNCTION tollkeeper_audit_reject_change();

CREATE OR REPLACE TRIGGER tollkeeper_audit_no_truncate
    BEFORE TRUNCATE ON tollkeeper_audit
    FOR EACH STATEMENT EXECUTE FUNCTION tollkeeper_audit_reject_change();
