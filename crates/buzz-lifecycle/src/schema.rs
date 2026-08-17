use rusqlite::{Connection, TransactionBehavior};

use crate::Result;

pub(crate) const SCHEMA_VERSION: u32 = 8;

pub(crate) fn initialize(connection: &mut Connection) -> Result<()> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS lifecycle_schema (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            version INTEGER NOT NULL CHECK(version > 0)
        );
        INSERT INTO lifecycle_schema(singleton, version) VALUES (1, 1)
            ON CONFLICT(singleton) DO NOTHING;

        CREATE TABLE IF NOT EXISTS turns (
            turn_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            requester_id TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            client_nonce TEXT NOT NULL,
            input_digest TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN (
                'accepted','queued','running','waiting','completed','failed',
                'cancelled','expired','rejected'
            )),
            execution_id TEXT,
            result_digest TEXT,
            version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
            accepted_at_ms INTEGER NOT NULL CHECK(accepted_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            expires_at_ms INTEGER NOT NULL,
            UNIQUE(owner_id, agent_id, client_nonce)
        );
        CREATE INDEX IF NOT EXISTS turns_owner_active
            ON turns(owner_id, state, accepted_at_ms, turn_id);
        CREATE INDEX IF NOT EXISTS turns_execution
            ON turns(execution_id) WHERE execution_id IS NOT NULL;
        CREATE INDEX IF NOT EXISTS turns_owner_agent_expiry
            ON turns(owner_id,agent_id,state,expires_at_ms,turn_id);

        CREATE TABLE IF NOT EXISTS turn_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            turn_id TEXT NOT NULL REFERENCES turns(turn_id) ON DELETE RESTRICT,
            owner_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            from_state TEXT,
            to_state TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            occurred_at_ms INTEGER NOT NULL CHECK(occurred_at_ms >= 0)
        );
        CREATE INDEX IF NOT EXISTS turn_events_owner_sequence
            ON turn_events(owner_id, sequence);

        CREATE TABLE IF NOT EXISTS lifecycle_outbox (
            outbox_id TEXT PRIMARY KEY,
            turn_id TEXT NOT NULL REFERENCES turns(turn_id) ON DELETE RESTRICT,
            owner_id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('receipt','terminal')),
            dedupe_key TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('pending','delivered')),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
            not_before_ms INTEGER NOT NULL CHECK(not_before_ms >= 0),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            delivered_at_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS lifecycle_outbox_pending
            ON lifecycle_outbox(state, not_before_ms, created_at_ms, outbox_id);
        "#,
    )?;
    let mut version: u32 = transaction.query_row(
        "SELECT version FROM lifecycle_schema WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    match version {
        1 => {
            transaction.execute_batch(
                r#"
                ALTER TABLE lifecycle_outbox ADD COLUMN claim_token TEXT;
                ALTER TABLE lifecycle_outbox ADD COLUMN claim_expires_at_ms INTEGER;
                ALTER TABLE lifecycle_outbox ADD COLUMN delivered_event_id TEXT;
                CREATE INDEX lifecycle_outbox_claimable
                    ON lifecycle_outbox(state, not_before_ms, claim_expires_at_ms, created_at_ms, outbox_id);
                UPDATE lifecycle_schema SET version=2 WHERE singleton=1;
                "#,
            )?;
            version = 2;
        }
        2 | 3 | 4 | 5 | 6 | 7 | SCHEMA_VERSION => {}
        other => return Err(crate::LifecycleError::UnsupportedSchemaVersion(other)),
    }
    if version == 2 {
        transaction.execute_batch(
            r#"
            CREATE TABLE turn_dispatch (
                turn_id TEXT PRIMARY KEY REFERENCES turns(turn_id) ON DELETE RESTRICT,
                prompt_tag TEXT NOT NULL,
                delivery_mode TEXT NOT NULL CHECK(delivery_mode IN (
                    'normal','retry','merged_steer','merged_interrupt'
                )),
                retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count >= 0),
                not_before_ms INTEGER NOT NULL CHECK(not_before_ms >= 0),
                rule_fingerprint TEXT
            );
            CREATE INDEX turn_dispatch_due
                ON turn_dispatch(not_before_ms, turn_id);

            CREATE TABLE turn_recovery (
                turn_id TEXT PRIMARY KEY REFERENCES turns(turn_id) ON DELETE RESTRICT,
                instance_id TEXT NOT NULL,
                prior_state TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN (
                    'rehydrate','wait_until_due','hold_uncertain','missing_dispatch_intent'
                )),
                recovered_state TEXT NOT NULL,
                recovered_version INTEGER NOT NULL CHECK(recovered_version >= 0),
                recovered_at_ms INTEGER NOT NULL CHECK(recovered_at_ms >= 0)
            );

            CREATE TABLE runtime_leases (
                owner_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
                PRIMARY KEY(owner_id, agent_id)
            );
            UPDATE lifecycle_schema SET version=3 WHERE singleton=1;
            "#,
        )?;
        version = 3;
    }
    if version == 3 {
        transaction.execute_batch(
            r#"
            ALTER TABLE turn_recovery ADD COLUMN queue_acknowledged_at_ms INTEGER;
            UPDATE lifecycle_schema SET version=4 WHERE singleton=1;
            "#,
        )?;
        version = 4;
    }
    if version == 4 {
        transaction.execute_batch(
            r#"
            ALTER TABLE turn_dispatch ADD COLUMN lane TEXT NOT NULL DEFAULT 'user'
                CHECK(lane IN ('user','agent','background'));
            ALTER TABLE turn_dispatch ADD COLUMN source TEXT NOT NULL DEFAULT 'legacy'
                CHECK(length(source) BETWEEN 1 AND 64);

            CREATE TABLE run_scheduler_state (
                owner_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                next_epoch INTEGER NOT NULL DEFAULT 1 CHECK(next_epoch > 0),
                active_epoch INTEGER,
                active_execution_id TEXT,
                active_lane TEXT,
                active_source TEXT,
                active_started_at_ms INTEGER,
                claims_since_agent INTEGER NOT NULL DEFAULT 0 CHECK(claims_since_agent >= 0),
                claims_since_background INTEGER NOT NULL DEFAULT 0
                    CHECK(claims_since_background >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
                PRIMARY KEY(owner_id, agent_id),
                CHECK (
                    (active_epoch IS NULL AND active_execution_id IS NULL
                     AND active_lane IS NULL AND active_source IS NULL
                     AND active_started_at_ms IS NULL)
                    OR
                    (active_epoch IS NOT NULL AND active_execution_id IS NOT NULL
                     AND active_lane IN ('user','agent','background')
                     AND active_source IS NOT NULL AND active_started_at_ms IS NOT NULL)
                )
            );
            CREATE UNIQUE INDEX run_scheduler_active_execution
                ON run_scheduler_state(active_execution_id)
                WHERE active_execution_id IS NOT NULL;
            CREATE INDEX turns_owner_agent_active
                ON turns(owner_id,agent_id,state,accepted_at_ms,turn_id);
            CREATE INDEX turn_dispatch_lane_due
                ON turn_dispatch(lane,not_before_ms,turn_id);
            UPDATE lifecycle_schema SET version=5 WHERE singleton=1;
            "#,
        )?;
        version = 5;
    }
    if version == 5 {
        transaction.execute_batch(
            r#"
            ALTER TABLE turn_dispatch ADD COLUMN opaque_input_json TEXT;
            ALTER TABLE run_scheduler_state ADD COLUMN active_phase TEXT
                CHECK(active_phase IN ('reserved','launched'));
            UPDATE lifecycle_schema SET version=6 WHERE singleton=1;
            "#,
        )?;
        version = 6;
    }

    if version == 6 {
        transaction.execute_batch(
            r#"
            CREATE TABLE human_cards (
                card_id TEXT PRIMARY KEY,
                turn_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('action_request')),
                title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 256),
                body TEXT NOT NULL CHECK(length(body) <= 4096),
                choices_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                answered_choice_id TEXT,
                answered_at_ms INTEGER CHECK(answered_at_ms IS NULL OR answered_at_ms >= 0),
                resumed INTEGER NOT NULL DEFAULT 0 CHECK(resumed IN (0,1)),
                CHECK((answered_choice_id IS NULL AND answered_at_ms IS NULL AND resumed=0) OR (answered_choice_id IS NOT NULL AND answered_at_ms IS NOT NULL))
            );
            CREATE INDEX human_cards_owner ON human_cards(owner_id, created_at_ms, card_id);

            CREATE TABLE human_card_transcript (
                entry_id TEXT PRIMARY KEY,
                card_id TEXT NOT NULL REFERENCES human_cards(card_id) ON DELETE RESTRICT,
                turn_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('created','answered','resume')),
                payload_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
            );
            CREATE INDEX human_card_transcript_card ON human_card_transcript(card_id, created_at_ms, entry_id);

            CREATE TABLE automation_definitions (
                definition_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
                revision INTEGER NOT NULL CHECK(revision > 0),
                enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
                config_json TEXT NOT NULL
            );
            CREATE INDEX automation_definitions_owner ON automation_definitions(owner_id, definition_id);

            CREATE TABLE automation_wakes (
                wake_id TEXT PRIMARY KEY,
                definition_id TEXT NOT NULL REFERENCES automation_definitions(definition_id) ON DELETE RESTRICT,
                owner_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                payload_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
            );
            CREATE INDEX automation_wakes_definition ON automation_wakes(definition_id, created_at_ms, wake_id);

            CREATE TABLE automation_runs (
                run_id TEXT PRIMARY KEY,
                wake_id TEXT NOT NULL REFERENCES automation_wakes(wake_id) ON DELETE RESTRICT,
                definition_id TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                state TEXT NOT NULL CHECK(state IN ('pending','delivered','acked','failed')),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0)
            );
            CREATE INDEX automation_runs_state ON automation_runs(state, created_at_ms, run_id);

            CREATE TABLE spend_guard_state (
                owner_id TEXT PRIMARY KEY,
                config_json TEXT NOT NULL,
                window_start_ms INTEGER NOT NULL CHECK(window_start_ms >= 0),
                wakes_in_window INTEGER NOT NULL DEFAULT 0 CHECK(wakes_in_window >= 0),
                runs_in_window INTEGER NOT NULL DEFAULT 0 CHECK(runs_in_window >= 0),
                snoozed_until_ms INTEGER,
                grace_until_ms INTEGER,
                paused_scopes_json TEXT NOT NULL DEFAULT '[]',
                paused_definition_ids_json TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE skill_manifests (
                manifest_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                source TEXT NOT NULL,
                files_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
            );

            CREATE TABLE skills (
                skill_id TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version > 0),
                owner_id TEXT NOT NULL,
                manifest_id TEXT NOT NULL REFERENCES skill_manifests(manifest_id) ON DELETE RESTRICT,
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
                private INTEGER NOT NULL DEFAULT 1 CHECK(private IN (0,1)),
                PRIMARY KEY(skill_id, version)
            );
            CREATE INDEX skills_owner ON skills(owner_id, skill_id);

            UPDATE lifecycle_schema SET version=7 WHERE singleton=1;
            "#,
        )?;
        version = 7;
    }
    if version == 7 {
        transaction.execute_batch(
            r#"
            CREATE TABLE retention_policies (
                owner_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                retention_days INTEGER NOT NULL CHECK(retention_days BETWEEN 7 AND 90),
                soft_bytes INTEGER NOT NULL CHECK(soft_bytes BETWEEN 268435456 AND 2147483648),
                hard_bytes INTEGER NOT NULL CHECK(hard_bytes BETWEEN 268435456 AND 2147483648 AND hard_bytes >= soft_bytes),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
                PRIMARY KEY(owner_id, agent_id)
            );
            CREATE TABLE launch_fences (
                owner_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                launch_epoch INTEGER NOT NULL CHECK(launch_epoch >= 0),
                updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
                PRIMARY KEY(owner_id, agent_id)
            );
            CREATE TABLE activation_capabilities (
                capability_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                launch_epoch INTEGER NOT NULL CHECK(launch_epoch > 0),
                consumed INTEGER NOT NULL CHECK(consumed IN (0,1)),
                created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0)
            );
            CREATE INDEX activation_capabilities_scope
                ON activation_capabilities(owner_id, agent_id, launch_epoch);
            UPDATE lifecycle_schema SET version=8 WHERE singleton=1;
            "#,
        )?;
    }
    transaction.commit()?;
    Ok(())
}
