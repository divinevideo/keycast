-- The NIP-46 client that proved the connection secret with a connect, or the
-- nostr-login client the person approved when the authorization was created.
-- The relay signer serves a client only when connected_client_pubkey equals
-- this value, so a binding that exists before this column is not trusted and
-- its app connects again with the secret.
-- Team authorizations need no such column: their bindings were only ever made
-- by a connect that presented the secret.
SET LOCAL lock_timeout = '5s';

ALTER TABLE oauth_authorizations ADD COLUMN verified_client_pubkey TEXT;

-- Deployments run migrations before the new revision serves, so a revision that
-- predates this column can still change connected_client_pubkey during a
-- mixed-version rollout or after a rollback. Whatever revision writes the row,
-- verified_client_pubkey stays either NULL or equal to connected_client_pubkey,
-- so a binding changed any other way is not trusted.
CREATE FUNCTION public.keep_verified_client_with_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.verified_client_pubkey IS DISTINCT FROM NEW.connected_client_pubkey THEN
        NEW.verified_client_pubkey := NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER oauth_authorizations_verified_client_trigger
    BEFORE INSERT OR UPDATE OF connected_client_pubkey, verified_client_pubkey
    ON public.oauth_authorizations
    FOR EACH ROW EXECUTE FUNCTION public.keep_verified_client_with_binding();
