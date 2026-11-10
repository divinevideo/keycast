-- Environments without CREATEROLE must provision this NOLOGIN role before migrating.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'support_reader') THEN
        BEGIN
            CREATE ROLE support_reader NOLOGIN;
        EXCEPTION WHEN duplicate_object OR unique_violation THEN
            -- Roles are cluster-wide; another database may be migrating concurrently.
            NULL;
        END;
    END IF;
END
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO support_reader;

-- Keep these lists explicit: new columns must be classified before becoming readable.
GRANT SELECT (version, description, installed_on, success, checksum, execution_time)
    ON public._sqlx_migrations TO support_reader;
GRANT SELECT (id, user_pubkey, expires_at, used_at, created_at, created_by_pubkey,
    tenant_id, invalidated_at, invalidated_by, invalidation_reason, pending_email,
    confirmation_expires_at, confirmation_sent_at, confirmation_send_count)
    ON public.account_claim_tokens TO support_reader;
GRANT SELECT (id, occurred_at, tenant_id, actor_pubkey, action, target_resource_type,
    target_resource_id, target_client_id, metadata_json)
    ON public.admin_audit_events TO support_reader;
GRANT SELECT (id, user_pubkey, tenant_id, public_key_pem, key_type, created_at, updated_at)
    ON public.ap_actor_keys TO support_reader;
GRANT SELECT (id, tenant_id, client_id, redirect_uri, scope, state, code_challenge,
    code_challenge_method, request_uri, par_expires_at, user_pubkey, atproto_did,
    approved_at, authorization_code_expires_at, access_token_jti, access_token_expires_at,
    refresh_token_expires_at, refresh_token_revoked_at, revoked_at, dpop_jkt, created_at,
    updated_at, dpop_nonce, client_auth_method, client_auth_jkt, client_auth_alg, client_auth_kid)
    ON public.atproto_oauth_sessions TO support_reader;
GRANT SELECT (id, occurred_at, request_id, tenant_id, endpoint, event_type, outcome,
    reason_code, http_status, email, email_hash, pubkey, pubkey_prefix, client_id,
    redirect_origin, user_agent, metadata_json)
    ON public.auth_events TO support_reader;
GRANT SELECT (id, stored_key_id, bunker_public_key, relays, policy_id, max_uses,
    expires_at, created_at, updated_at, tenant_id, connected_client_pubkey, connected_at, label)
    ON public.authorizations TO support_reader;
GRANT SELECT (id, tenant_id, email, deleted_at, expires_at)
    ON public.email_marketing_deletions TO support_reader;
GRANT SELECT (id, tenant_id, pubkey, old_email, new_email, changed_at, expires_at, global_optout)
    ON public.email_marketing_email_changes TO support_reader;
GRANT SELECT (id, user_pubkey, expires_at, created_at)
    ON public.email_verification_tokens TO support_reader;
GRANT SELECT (id, tenant_id, group_id, admin_pubkey, action, event_id, session_id, created_at)
    ON public.group_audit TO support_reader;
GRANT SELECT (tenant_id, group_id, admin_pubkey, request_id, backup_request_id,
    installation_epoch, created_at)
    ON public.group_backup_restores TO support_reader;
GRANT SELECT (tenant_id, group_id, admin_pubkey, request_id, membership_version,
    key_version, roster_version, content_hash, created_at)
    ON public.group_backups TO support_reader;
GRANT SELECT (tenant_id, group_id, participant_id, commitment_hash, session_id, created_at)
    ON public.group_frost_commitments TO support_reader;
GRANT SELECT (tenant_id, group_id, id, session_kind, state, aborted, created_at, expires_at)
    ON public.group_frost_sessions TO support_reader;
GRANT SELECT (authorization_id, tenant_id, group_id, admin_pubkey, membership_version,
    key_version, installation_epoch, revoked_at)
    ON public.group_grants TO support_reader;
GRANT SELECT (tenant_id, group_id, admin_pubkey, status, version, participant_id, installation_epoch)
    ON public.group_memberships TO support_reader;
GRANT SELECT (id, tenant_id, name, pubkey, signing_key_id, policy_id, mode, key_version,
    roster_version, creator_pubkey, request_id, created_at)
    ON public.identity_groups TO support_reader;
GRANT SELECT (id, user_pubkey, redirect_origin, client_id, bunker_public_key, relays,
    created_at, updated_at, policy_id, expires_at, tenant_id, client_pubkey,
    connected_client_pubkey, connected_at, last_activity, activity_count, revoked_at,
    authorization_handle, handle_expires_at, is_first_party, verified_client_pubkey)
    ON public.oauth_authorizations TO support_reader;
GRANT SELECT (user_pubkey, client_id, redirect_uri, scope, expires_at, created_at,
    tenant_id, code_challenge, code_challenge_method, pending_email, previous_auth_id,
    state, is_headless, pin_attempts, pin_failed_total, pin_sent_at, pin_resend_at,
    consumed_at, pending_email_marketing_consent, pending_email_marketing_app_version)
    ON public.oauth_codes TO support_reader;
GRANT SELECT (id, authorization_id, tenant_id, created_at, expires_at, consumed_at)
    ON public.oauth_refresh_tokens TO support_reader;
GRANT SELECT (id, user_pubkey, expires_at, used, created_at)
    ON public.password_reset_tokens TO support_reader;
GRANT SELECT (id, identifier, config, created_at, updated_at)
    ON public.permissions TO support_reader;
GRANT SELECT (id, user_pubkey, created_at, updated_at, tenant_id)
    ON public.personal_keys TO support_reader;
GRANT SELECT (id, name, team_id, slug, display_name, description, created_at, updated_at)
    ON public.policies TO support_reader;
GRANT SELECT (id, policy_id, permission_id, created_at, updated_at)
    ON public.policy_permissions TO support_reader;
GRANT SELECT (id, tenant_id, client_id, name, allowed_redirect_uris, created_at, updated_at)
    ON public.registered_clients TO support_reader;
GRANT SELECT (hold_id, tenant_id, scope_kind, scope_key, authorizing_role, reason_reference,
    started_at, review_at, expires_at, released_at)
    ON public.retention_legal_holds TO support_reader;
GRANT SELECT (deletion_request_id, tenant_id, outcome, completed_at, binding_digest,
    digest_key_version, compacted_at)
    ON public.service_account_deletion_tombstones TO support_reader;
GRANT SELECT (deletion_request_id, tenant_id, user_pubkey, outcome, teams_removed,
    oauth_authorizations_deleted, bunkers_notified, completed_at)
    ON public.service_account_deletions TO support_reader;
GRANT SELECT (provisioning_operation_id, tenant_id, request_fingerprint_digest,
    binding_digest, digest_key_version, outcome, completed_at, compacted_at)
    ON public.service_provisioning_operation_tombstones TO support_reader;
GRANT SELECT (provisioning_operation_id, tenant_id, request_fingerprint, user_pubkey,
    outcome, created_at, deleted_at)
    ON public.service_provisioning_operations TO support_reader;
GRANT SELECT (instance_id, started_at, last_heartbeat)
    ON public.signer_instances TO support_reader;
GRANT SELECT (id, name, team_id, pubkey, created_at, updated_at, tenant_id)
    ON public.stored_keys TO support_reader;
GRANT SELECT (tenant_id, pubkey, added_by_pubkey, created_at)
    ON public.support_admins TO support_reader;
GRANT SELECT (id, team_id, user_pubkey, role, created_at, updated_at)
    ON public.team_users TO support_reader;
GRANT SELECT (id, name, created_at, updated_at, tenant_id)
    ON public.teams TO support_reader;
GRANT SELECT (id, domain, name, settings, created_at, updated_at)
    ON public.tenants TO support_reader;
GRANT SELECT (pubkey, profile_json, updated_at)
    ON public.user_profiles TO support_reader;
GRANT SELECT (pubkey, created_at, updated_at, email_verified, email,
    email_verification_expires_at, email_verification_sent_at, password_reset_expires_at,
    username, tenant_id, display_name, vine_id, atproto_enabled, atproto_state, atproto_did,
    atproto_error, atproto_updated_at, status, suspended_reason, suspended_at,
    verified_minor, verified_minor_at, pending_email, pending_email_expires_at,
    pending_email_sent_at, pending_email_old_confirmed_at, pending_email_new_confirmed_at,
    email_marketing_consent, email_marketing_consent_at, email_marketing_consent_source,
    email_marketing_consent_app_version, email_marketing_global_optout,
    email_marketing_optout_observed_at)
    ON public.users TO support_reader;
