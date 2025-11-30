CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TABLE public.authorizations (
    id integer NOT NULL,
    stored_key_id integer,
    secret text NOT NULL,
    bunker_public_key character(64) NOT NULL,
    bunker_secret bytea NOT NULL,
    relays text NOT NULL,
    policy_id integer,
    max_uses integer,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id bigint DEFAULT 1 NOT NULL,
    connected_client_pubkey text,
    connected_at timestamp with time zone
);

CREATE SEQUENCE public.authorizations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.authorizations_id_seq OWNED BY public.authorizations.id;

CREATE TABLE public.email_verification_tokens (
    id text NOT NULL,
    user_pubkey character(64) NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.key_export_codes (
    id integer NOT NULL,
    user_pubkey character(64) NOT NULL,
    code text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    used_at timestamp with time zone
);

CREATE SEQUENCE public.key_export_codes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.key_export_codes_id_seq OWNED BY public.key_export_codes.id;

CREATE TABLE public.key_export_log (
    id integer NOT NULL,
    user_pubkey character(64) NOT NULL,
    format text NOT NULL,
    exported_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.key_export_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.key_export_log_id_seq OWNED BY public.key_export_log.id;

CREATE TABLE public.key_export_tokens (
    id integer NOT NULL,
    user_pubkey character(64) NOT NULL,
    token text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    used_at timestamp with time zone
);

CREATE SEQUENCE public.key_export_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.key_export_tokens_id_seq OWNED BY public.key_export_tokens.id;

CREATE TABLE public.oauth_applications (
    id integer NOT NULL,
    redirect_origin text NOT NULL,
    display_name text,
    name text NOT NULL,
    redirect_uris text NOT NULL,
    client_secret text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id bigint DEFAULT 1 NOT NULL,
    policy_id integer
);

CREATE SEQUENCE public.oauth_applications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.oauth_applications_id_seq OWNED BY public.oauth_applications.id;

CREATE TABLE public.oauth_authorizations (
    id integer NOT NULL,
    user_pubkey character(64) NOT NULL,
    redirect_origin text NOT NULL,
    application_id integer,
    bunker_public_key character(64) NOT NULL,
    secret text NOT NULL,
    relays text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    policy_id integer,
    expires_at timestamp with time zone,
    tenant_id bigint DEFAULT 1 NOT NULL,
    client_pubkey character(64),
    connected_client_pubkey text,
    connected_at timestamp with time zone
);

CREATE SEQUENCE public.oauth_authorizations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.oauth_authorizations_id_seq OWNED BY public.oauth_authorizations.id;

CREATE TABLE public.oauth_codes (
    code text NOT NULL,
    user_pubkey character(64) NOT NULL,
    application_id integer NOT NULL,
    redirect_uri text NOT NULL,
    scope text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id bigint DEFAULT 1 NOT NULL,
    code_challenge text,
    code_challenge_method text
);

CREATE TABLE public.password_reset_tokens (
    id text NOT NULL,
    user_pubkey character(64) NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.permissions (
    id integer NOT NULL,
    identifier text NOT NULL,
    config text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.permissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.permissions_id_seq OWNED BY public.permissions.id;

CREATE TABLE public.personal_keys (
    id integer NOT NULL,
    user_pubkey character(64) NOT NULL,
    encrypted_secret_key bytea NOT NULL,
    bunker_secret text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id bigint DEFAULT 1 NOT NULL
);

COMMENT ON COLUMN public.personal_keys.bunker_secret IS 'Deprecated: Was used for auto-bunker creation. Now bunker connections are created manually via oauth_authorizations.';

CREATE SEQUENCE public.personal_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.personal_keys_id_seq OWNED BY public.personal_keys.id;

CREATE TABLE public.policies (
    id integer NOT NULL,
    name text NOT NULL,
    team_id integer,
    slug VARCHAR(50),
    display_name VARCHAR(100),
    description TEXT,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.policies_id_seq OWNED BY public.policies.id;

CREATE TABLE public.policy_permissions (
    id integer NOT NULL,
    policy_id integer,
    permission_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.policy_permissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.policy_permissions_id_seq OWNED BY public.policy_permissions.id;

CREATE TABLE public.signing_activity (
    id integer NOT NULL,
    user_pubkey character(64) NOT NULL,
    application_id integer,
    bunker_secret text NOT NULL,
    event_kind integer NOT NULL,
    event_content text,
    event_id character(64),
    client_pubkey character(64),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id bigint DEFAULT 1 NOT NULL
);

CREATE SEQUENCE public.signing_activity_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.signing_activity_id_seq OWNED BY public.signing_activity.id;

CREATE TABLE public.stored_keys (
    id integer NOT NULL,
    name text NOT NULL,
    team_id integer,
    pubkey character(64) NOT NULL,
    secret_key bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id bigint DEFAULT 1 NOT NULL
);

CREATE SEQUENCE public.stored_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.stored_keys_id_seq OWNED BY public.stored_keys.id;

CREATE TABLE public.team_users (
    id integer NOT NULL,
    team_id integer,
    user_pubkey character(64),
    role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT team_users_role_check CHECK ((role = ANY (ARRAY['admin'::text, 'member'::text])))
);

CREATE SEQUENCE public.team_users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.team_users_id_seq OWNED BY public.team_users.id;

CREATE TABLE public.teams (
    id integer NOT NULL,
    name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id bigint DEFAULT 1 NOT NULL
);

CREATE SEQUENCE public.teams_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.teams_id_seq OWNED BY public.teams.id;

CREATE TABLE public.tenants (
    id bigint NOT NULL,
    domain text NOT NULL,
    name text NOT NULL,
    settings text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.tenants_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.tenants_id_seq OWNED BY public.tenants.id;

-- Signer instances registry for hashring-based NIP-46 event distribution
CREATE TABLE signer_instances (
    instance_id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signer_instances_heartbeat ON signer_instances(last_heartbeat);

CREATE TABLE public.user_authorizations (
    id integer NOT NULL,
    user_pubkey character(64),
    authorization_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.user_authorizations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.user_authorizations_id_seq OWNED BY public.user_authorizations.id;

CREATE TABLE public.user_profiles (
    pubkey character(64) NOT NULL,
    profile_json text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.users (
    pubkey character(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    email_verified boolean DEFAULT false,
    email text,
    password_hash text,
    email_verification_token text,
    email_verification_expires_at timestamp with time zone,
    email_verification_sent_at timestamp with time zone,
    password_reset_token text,
    password_reset_expires_at timestamp with time zone,
    username text,
    tenant_id bigint DEFAULT 1 NOT NULL
);

ALTER TABLE ONLY public.authorizations ALTER COLUMN id SET DEFAULT nextval('public.authorizations_id_seq'::regclass);

ALTER TABLE ONLY public.key_export_codes ALTER COLUMN id SET DEFAULT nextval('public.key_export_codes_id_seq'::regclass);

ALTER TABLE ONLY public.key_export_log ALTER COLUMN id SET DEFAULT nextval('public.key_export_log_id_seq'::regclass);

ALTER TABLE ONLY public.key_export_tokens ALTER COLUMN id SET DEFAULT nextval('public.key_export_tokens_id_seq'::regclass);

ALTER TABLE ONLY public.oauth_applications ALTER COLUMN id SET DEFAULT nextval('public.oauth_applications_id_seq'::regclass);

ALTER TABLE ONLY public.oauth_authorizations ALTER COLUMN id SET DEFAULT nextval('public.oauth_authorizations_id_seq'::regclass);

ALTER TABLE ONLY public.permissions ALTER COLUMN id SET DEFAULT nextval('public.permissions_id_seq'::regclass);

ALTER TABLE ONLY public.personal_keys ALTER COLUMN id SET DEFAULT nextval('public.personal_keys_id_seq'::regclass);

ALTER TABLE ONLY public.policies ALTER COLUMN id SET DEFAULT nextval('public.policies_id_seq'::regclass);

ALTER TABLE ONLY public.policy_permissions ALTER COLUMN id SET DEFAULT nextval('public.policy_permissions_id_seq'::regclass);

ALTER TABLE ONLY public.signing_activity ALTER COLUMN id SET DEFAULT nextval('public.signing_activity_id_seq'::regclass);

ALTER TABLE ONLY public.stored_keys ALTER COLUMN id SET DEFAULT nextval('public.stored_keys_id_seq'::regclass);

ALTER TABLE ONLY public.team_users ALTER COLUMN id SET DEFAULT nextval('public.team_users_id_seq'::regclass);

ALTER TABLE ONLY public.teams ALTER COLUMN id SET DEFAULT nextval('public.teams_id_seq'::regclass);

ALTER TABLE ONLY public.tenants ALTER COLUMN id SET DEFAULT nextval('public.tenants_id_seq'::regclass);

ALTER TABLE ONLY public.user_authorizations ALTER COLUMN id SET DEFAULT nextval('public.user_authorizations_id_seq'::regclass);

ALTER TABLE ONLY public.authorizations
    ADD CONSTRAINT authorizations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.email_verification_tokens
    ADD CONSTRAINT email_verification_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.email_verification_tokens
    ADD CONSTRAINT email_verification_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.key_export_codes
    ADD CONSTRAINT key_export_codes_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.key_export_log
    ADD CONSTRAINT key_export_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.key_export_tokens
    ADD CONSTRAINT key_export_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.key_export_tokens
    ADD CONSTRAINT key_export_tokens_token_key UNIQUE (token);

ALTER TABLE ONLY public.oauth_applications
    ADD CONSTRAINT oauth_applications_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth_authorizations
    ADD CONSTRAINT oauth_auth_user_origin_unique UNIQUE (tenant_id, user_pubkey, redirect_origin);

ALTER TABLE ONLY public.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.oauth_codes
    ADD CONSTRAINT oauth_codes_pkey PRIMARY KEY (code);

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.personal_keys
    ADD CONSTRAINT personal_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.policy_permissions
    ADD CONSTRAINT policy_permissions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.signing_activity
    ADD CONSTRAINT signing_activity_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.stored_keys
    ADD CONSTRAINT stored_keys_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.team_users
    ADD CONSTRAINT team_users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.teams
    ADD CONSTRAINT teams_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_domain_key UNIQUE (domain);

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_authorizations
    ADD CONSTRAINT user_authorizations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_profiles
    ADD CONSTRAINT user_profiles_pkey PRIMARY KEY (pubkey);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (pubkey);

CREATE INDEX authorizations_stored_key_id_idx ON public.authorizations USING btree (stored_key_id);

CREATE UNIQUE INDEX idx_authorizations_secret_tenant ON public.authorizations USING btree (tenant_id, secret);

CREATE INDEX idx_authorizations_tenant_id ON public.authorizations USING btree (tenant_id);

CREATE INDEX idx_auth_connected_client_pubkey ON public.authorizations USING btree (connected_client_pubkey) WHERE (connected_client_pubkey IS NOT NULL);

CREATE INDEX idx_email_verification_tokens_expires_at ON public.email_verification_tokens USING btree (expires_at);

CREATE INDEX idx_email_verification_tokens_token_hash ON public.email_verification_tokens USING btree (token_hash);

CREATE INDEX idx_email_verification_tokens_user_id ON public.email_verification_tokens USING btree (user_pubkey);

CREATE INDEX idx_key_export_codes_expires ON public.key_export_codes USING btree (expires_at);

CREATE INDEX idx_key_export_codes_user ON public.key_export_codes USING btree (user_pubkey);

CREATE INDEX idx_key_export_log_exported_at ON public.key_export_log USING btree (exported_at);

CREATE INDEX idx_key_export_log_user ON public.key_export_log USING btree (user_pubkey);

CREATE INDEX idx_key_export_tokens_expires ON public.key_export_tokens USING btree (expires_at);

CREATE INDEX idx_key_export_tokens_token ON public.key_export_tokens USING btree (token);

CREATE INDEX idx_key_export_tokens_user ON public.key_export_tokens USING btree (user_pubkey);

CREATE UNIQUE INDEX idx_oauth_applications_redirect_origin_tenant ON public.oauth_applications USING btree (tenant_id, redirect_origin);


CREATE INDEX idx_oauth_applications_tenant_id ON public.oauth_applications USING btree (tenant_id);

CREATE INDEX idx_oauth_applications_policy_id ON public.oauth_applications USING btree (policy_id);

CREATE INDEX idx_oauth_auth_app ON public.oauth_authorizations USING btree (application_id);

CREATE INDEX idx_oauth_auth_user ON public.oauth_authorizations USING btree (user_pubkey);

CREATE INDEX idx_oauth_authorizations_bunker_tenant ON public.oauth_authorizations USING btree (bunker_public_key, tenant_id);

CREATE INDEX idx_oauth_authorizations_policy_id ON public.oauth_authorizations USING btree (policy_id);

CREATE INDEX idx_oauth_authorizations_tenant_id ON public.oauth_authorizations USING btree (tenant_id);

CREATE INDEX idx_oauth_auth_connected_client_pubkey ON public.oauth_authorizations USING btree (connected_client_pubkey) WHERE (connected_client_pubkey IS NOT NULL);

CREATE INDEX idx_oauth_codes_challenge ON public.oauth_codes USING btree (code_challenge) WHERE (code_challenge IS NOT NULL);

CREATE INDEX idx_oauth_codes_expires ON public.oauth_codes USING btree (expires_at);

CREATE INDEX idx_oauth_codes_tenant_id ON public.oauth_codes USING btree (tenant_id);

CREATE INDEX idx_oauth_codes_user ON public.oauth_codes USING btree (user_pubkey);

CREATE INDEX idx_password_reset_tokens_expires_at ON public.password_reset_tokens USING btree (expires_at);

CREATE INDEX idx_password_reset_tokens_token_hash ON public.password_reset_tokens USING btree (token_hash);

CREATE INDEX idx_password_reset_tokens_user_id ON public.password_reset_tokens USING btree (user_pubkey);


CREATE INDEX idx_personal_keys_tenant_id ON public.personal_keys USING btree (tenant_id);

CREATE INDEX idx_personal_keys_user_pubkey ON public.personal_keys USING btree (user_pubkey);


CREATE INDEX idx_signing_activity_app ON public.signing_activity USING btree (application_id);

CREATE INDEX idx_signing_activity_bunker_secret ON public.signing_activity USING btree (bunker_secret);

CREATE INDEX idx_signing_activity_created_at ON public.signing_activity USING btree (created_at);

CREATE INDEX idx_signing_activity_tenant_id ON public.signing_activity USING btree (tenant_id);

CREATE INDEX idx_signing_activity_user ON public.signing_activity USING btree (user_pubkey);

CREATE INDEX idx_stored_keys_tenant_id ON public.stored_keys USING btree (tenant_id);

CREATE INDEX idx_teams_tenant_id ON public.teams USING btree (tenant_id);

CREATE UNIQUE INDEX idx_tenants_domain ON public.tenants USING btree (domain);

CREATE INDEX idx_tenants_name ON public.tenants USING btree (name);

CREATE INDEX idx_user_profiles_updated_at ON public.user_profiles USING btree (updated_at);

CREATE UNIQUE INDEX idx_users_email_tenant ON public.users USING btree (tenant_id, email) WHERE (email IS NOT NULL);

CREATE INDEX idx_users_email_verification_token ON public.users USING btree (email_verification_token) WHERE (email_verification_token IS NOT NULL);

CREATE INDEX idx_users_password_reset_token ON public.users USING btree (password_reset_token) WHERE (password_reset_token IS NOT NULL);

CREATE INDEX idx_users_tenant_id ON public.users USING btree (tenant_id);

CREATE UNIQUE INDEX idx_users_username_tenant ON public.users USING btree (tenant_id, username) WHERE (username IS NOT NULL);

CREATE INDEX permissions_identifier_idx ON public.permissions USING btree (identifier);

CREATE INDEX policies_name_idx ON public.policies USING btree (name);

CREATE INDEX policies_team_id_idx ON public.policies USING btree (team_id);

CREATE UNIQUE INDEX policies_slug_unique ON policies (slug) WHERE slug IS NOT NULL;

CREATE INDEX policy_permissions_permission_id_idx ON public.policy_permissions USING btree (permission_id);

CREATE INDEX policy_permissions_policy_id_idx ON public.policy_permissions USING btree (policy_id);

CREATE UNIQUE INDEX policy_permissions_policy_id_permission_id_idx ON public.policy_permissions USING btree (policy_id, permission_id);

CREATE INDEX stored_keys_pubkey_idx ON public.stored_keys USING btree (pubkey);

CREATE INDEX stored_keys_team_id_idx ON public.stored_keys USING btree (team_id);

CREATE INDEX team_users_team_id_idx ON public.team_users USING btree (team_id);

CREATE UNIQUE INDEX team_users_team_id_user_pubkey_idx ON public.team_users USING btree (team_id, user_pubkey);

CREATE INDEX team_users_user_pubkey_idx ON public.team_users USING btree (user_pubkey);

CREATE INDEX teams_name_idx ON public.teams USING btree (name);

CREATE INDEX user_authorizations_authorization_id_idx ON public.user_authorizations USING btree (authorization_id);

CREATE UNIQUE INDEX user_authorizations_user_pubkey_authorization_id_idx ON public.user_authorizations USING btree (user_pubkey, authorization_id);

CREATE INDEX user_authorizations_user_pubkey_idx ON public.user_authorizations USING btree (user_pubkey);

CREATE UNIQUE INDEX users_pubkey_idx ON public.users USING btree (pubkey);

CREATE TRIGGER authorizations_update_trigger BEFORE UPDATE ON public.authorizations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER oauth_applications_update_trigger BEFORE UPDATE ON public.oauth_applications FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER oauth_authorizations_update_trigger BEFORE UPDATE ON public.oauth_authorizations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER permissions_update_trigger BEFORE UPDATE ON public.permissions FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER personal_keys_update_trigger BEFORE UPDATE ON public.personal_keys FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER policies_update_trigger BEFORE UPDATE ON public.policies FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER policy_permissions_update_trigger BEFORE UPDATE ON public.policy_permissions FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER stored_keys_update_trigger BEFORE UPDATE ON public.stored_keys FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER team_users_update_trigger BEFORE UPDATE ON public.team_users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER teams_update_trigger BEFORE UPDATE ON public.teams FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER tenants_update_trigger BEFORE UPDATE ON public.tenants FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER user_authorizations_update_trigger BEFORE UPDATE ON public.user_authorizations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER users_update_trigger BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

ALTER TABLE ONLY public.authorizations
    ADD CONSTRAINT authorizations_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.policies(id);

ALTER TABLE ONLY public.authorizations
    ADD CONSTRAINT authorizations_stored_key_id_fkey FOREIGN KEY (stored_key_id) REFERENCES public.stored_keys(id);

ALTER TABLE ONLY public.authorizations
    ADD CONSTRAINT authorizations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.email_verification_tokens
    ADD CONSTRAINT email_verification_tokens_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey) ON DELETE CASCADE;

ALTER TABLE ONLY public.key_export_codes
    ADD CONSTRAINT key_export_codes_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey) ON DELETE CASCADE;

ALTER TABLE ONLY public.key_export_log
    ADD CONSTRAINT key_export_log_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey) ON DELETE CASCADE;

ALTER TABLE ONLY public.key_export_tokens
    ADD CONSTRAINT key_export_tokens_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey) ON DELETE CASCADE;

ALTER TABLE ONLY public.oauth_applications
    ADD CONSTRAINT oauth_applications_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.oauth_applications
    ADD CONSTRAINT oauth_applications_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.policies(id);

ALTER TABLE ONLY public.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.oauth_applications(id);

ALTER TABLE ONLY public.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey);

ALTER TABLE ONLY public.oauth_codes
    ADD CONSTRAINT oauth_codes_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.oauth_applications(id);

ALTER TABLE ONLY public.oauth_codes
    ADD CONSTRAINT oauth_codes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.oauth_codes
    ADD CONSTRAINT oauth_codes_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey);

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey) ON DELETE CASCADE;


ALTER TABLE ONLY public.personal_keys
    ADD CONSTRAINT personal_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.personal_keys
    ADD CONSTRAINT personal_keys_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey) ON DELETE CASCADE;

ALTER TABLE ONLY public.policies
    ADD CONSTRAINT policies_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id);


ALTER TABLE ONLY public.policy_permissions
    ADD CONSTRAINT policy_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(id);

ALTER TABLE ONLY public.policy_permissions
    ADD CONSTRAINT policy_permissions_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.policies(id);

ALTER TABLE ONLY public.signing_activity
    ADD CONSTRAINT signing_activity_application_id_fkey FOREIGN KEY (application_id) REFERENCES public.oauth_applications(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.signing_activity
    ADD CONSTRAINT signing_activity_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.signing_activity
    ADD CONSTRAINT signing_activity_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey) ON DELETE CASCADE;

ALTER TABLE ONLY public.stored_keys
    ADD CONSTRAINT stored_keys_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id);

ALTER TABLE ONLY public.stored_keys
    ADD CONSTRAINT stored_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.team_users
    ADD CONSTRAINT team_users_team_id_fkey FOREIGN KEY (team_id) REFERENCES public.teams(id);

ALTER TABLE ONLY public.team_users
    ADD CONSTRAINT team_users_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey);

ALTER TABLE ONLY public.teams
    ADD CONSTRAINT teams_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

ALTER TABLE ONLY public.user_authorizations
    ADD CONSTRAINT user_authorizations_authorization_id_fkey FOREIGN KEY (authorization_id) REFERENCES public.authorizations(id);

ALTER TABLE ONLY public.user_authorizations
    ADD CONSTRAINT user_authorizations_user_pubkey_fkey FOREIGN KEY (user_pubkey) REFERENCES public.users(pubkey);

ALTER TABLE ONLY public.user_profiles
    ADD CONSTRAINT user_profiles_pubkey_fkey FOREIGN KEY (pubkey) REFERENCES public.users(pubkey) ON DELETE CASCADE;

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);

INSERT INTO tenants (id, domain, name, created_at, updated_at)
VALUES (1, 'default', 'Default Tenant', NOW(), NOW())
ON CONFLICT DO NOTHING;

-- Fix sequence after explicit ID insert
SELECT setval('tenants_id_seq', (SELECT COALESCE(MAX(id), 0) + 1 FROM tenants), false);

INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_social',
    '{"allowed_kinds": [0, 1, 3, 7, 9735]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_messaging',
    '{"allowed_kinds": [4, 44, 1059]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_zaps',
    '{"allowed_kinds": [9734]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_lists',
    '{"allowed_kinds": [10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10015, 10030]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_longform',
    '{"allowed_kinds": [30023, 30024, 30030, 30040, 30041, 30078, 30311, 30315, 30402, 30403]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_wallet',
    '{"allowed_kinds": [23194, 23195]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_deletion',
    '{"allowed_kinds": [5]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_reports',
    '{"allowed_kinds": [1984]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_social_messaging',
    '{"allowed_kinds": [0, 1, 3, 4, 7, 44, 1059, 9735, 22242]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Decrypt only permission (true read-only: decrypt + NIP-42 auth only)
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'decrypt_only',
    '{}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Full access permission (no restrictions)
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'full_access',
    '{}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO policies (name, team_id, slug, display_name, description, created_at, updated_at)
VALUES (
    'Standard Social (Default)',
    NULL,
    'social',
    'Social App',
    'Post notes, reactions, and private messages',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
SELECT
    p.id,
    perm.id,
    NOW(),
    NOW()
FROM policies p
CROSS JOIN permissions perm
WHERE p.name = 'Standard Social (Default)'
  AND perm.identifier = 'allowed_kinds_social_messaging'
  AND NOT EXISTS (
    SELECT 1 FROM policy_permissions pp
    WHERE pp.policy_id = p.id AND pp.permission_id = perm.id
  );

INSERT INTO policies (name, team_id, slug, display_name, description, created_at, updated_at)
VALUES (
    'Read Only',
    NULL,
    'readonly',
    'Read Only',
    'Can only read encrypted messages and authenticate with relays. Cannot post, react, or send messages.',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
SELECT
    p.id,
    perm.id,
    NOW(),
    NOW()
FROM policies p
CROSS JOIN permissions perm
WHERE p.name = 'Read Only'
  AND perm.identifier = 'decrypt_only'
  AND NOT EXISTS (
    SELECT 1 FROM policy_permissions pp
    WHERE pp.policy_id = p.id AND pp.permission_id = perm.id
  );

INSERT INTO policies (name, team_id, slug, display_name, description, created_at, updated_at)
VALUES (
    'Wallet Only',
    NULL,
    'wallet',
    'Wallet Only',
    'Wallet and payment operations only',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
SELECT
    p.id,
    perm.id,
    NOW(),
    NOW()
FROM policies p
CROSS JOIN permissions perm
WHERE p.name = 'Wallet Only'
  AND perm.identifier = 'allowed_kinds_zaps'
  AND NOT EXISTS (
    SELECT 1 FROM policy_permissions pp
    WHERE pp.policy_id = p.id AND pp.permission_id = perm.id
  );

-- Full access policy (sign, encrypt, decrypt anything)
INSERT INTO policies (name, team_id, slug, display_name, description, created_at, updated_at)
VALUES (
    'Full Access',
    NULL,
    'full',
    'Full Access',
    'Sign, encrypt, and decrypt anything without restrictions',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
SELECT
    p.id,
    perm.id,
    NOW(),
    NOW()
FROM policies p
CROSS JOIN permissions perm
WHERE p.name = 'Full Access'
  AND perm.identifier = 'full_access'
  AND NOT EXISTS (
    SELECT 1 FROM policy_permissions pp
    WHERE pp.policy_id = p.id AND pp.permission_id = perm.id
  );

-- Note: policy is on oauth_authorizations, not oauth_applications
-- redirect_origin is the secure identifier (cannot be spoofed)
INSERT INTO oauth_applications (
    redirect_origin,
    display_name,
    client_secret,
    name,
    redirect_uris,
    tenant_id,
    created_at,
    updated_at
)
VALUES (
    'app://keycast-login',
    'keycast-login',
    'not-used-for-personal-auth',
    'Personal Keycast Bunker',
    'http://localhost:3000/api/connect,https://login.divine.video/api/connect',
    1,
    NOW(),
    NOW()
)
ON CONFLICT (tenant_id, redirect_origin)
DO UPDATE SET
    client_secret = EXCLUDED.client_secret,
    name = EXCLUDED.name,
    redirect_uris = EXCLUDED.redirect_uris,
    updated_at = NOW();

-- Divine OAuth application (third-party app)
INSERT INTO oauth_applications (
    redirect_origin,
    display_name,
    client_secret,
    name,
    redirect_uris,
    tenant_id,
    created_at,
    updated_at
)
VALUES (
    'https://divine.video',
    'divine',
    'public-client',
    'Divine Video',
    'https://divine.video/callback,http://localhost:5173/callback,http://localhost:3000/callback,divine://callback',
    1,
    NOW(),
    NOW()
)
ON CONFLICT (tenant_id, redirect_origin)
DO UPDATE SET
    client_secret = EXCLUDED.client_secret,
    name = EXCLUDED.name,
    redirect_uris = EXCLUDED.redirect_uris,
    updated_at = NOW();
