use buzz_lifecycle::{
    LaneHeads, RunLane, SchedulerCounters, SchedulerPolicy, SchedulerPolicyError,
};

fn heads(mask: u8) -> LaneHeads<&'static str> {
    LaneHeads {
        user: (mask & 0b100 != 0).then_some("user-head"),
        agent: (mask & 0b010 != 0).then_some("agent-head"),
        background: (mask & 0b001 != 0).then_some("background-head"),
    }
}

fn expected_normal_lane(mask: u8) -> Option<RunLane> {
    if mask & 0b100 != 0 {
        Some(RunLane::User)
    } else if mask & 0b010 != 0 {
        Some(RunLane::Agent)
    } else if mask & 0b001 != 0 {
        Some(RunLane::Background)
    } else {
        None
    }
}

fn selected_lane<T>(decision: &buzz_lifecycle::ClaimDecision<T>) -> Option<RunLane> {
    decision.selected.as_ref().map(|selected| selected.lane)
}

#[test]
fn defaults_and_configuration_require_positive_thresholds() {
    let policy = SchedulerPolicy::default();
    assert_eq!(policy.agent_promotion_threshold(), 8);
    assert_eq!(policy.background_promotion_threshold(), 32);

    assert_eq!(
        SchedulerPolicy::new(0, 1),
        Err(SchedulerPolicyError::ZeroPromotionThreshold {
            lane: RunLane::Agent
        })
    );
    assert_eq!(
        SchedulerPolicy::new(1, 0),
        Err(SchedulerPolicyError::ZeroPromotionThreshold {
            lane: RunLane::Background
        })
    );

    let configured = SchedulerPolicy::new(3, 7);
    assert!(configured.is_ok());
    if let Ok(configured) = configured {
        assert_eq!(configured.agent_promotion_threshold(), 3);
        assert_eq!(configured.background_promotion_threshold(), 7);
    }
}

#[test]
fn all_lane_presence_and_counter_boundaries_follow_precedence_and_accounting() {
    let policy = SchedulerPolicy::new(2, 3);
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let agent_boundaries = [0, 1, 2, 3, u64::MAX];
    let background_boundaries = [0, 2, 3, 4, u64::MAX];

    for mask in 0..=0b111 {
        for agent_bypasses in agent_boundaries {
            for background_bypasses in background_boundaries {
                let counters = SchedulerCounters {
                    agent_bypasses,
                    background_bypasses,
                };
                let decision = policy.claim(counters, heads(mask));
                let agent_present = mask & 0b010 != 0;
                let background_present = mask & 0b001 != 0;

                let expected_lane = if background_present && background_bypasses >= 3 {
                    Some(RunLane::Background)
                } else if agent_present && agent_bypasses >= 2 {
                    Some(RunLane::Agent)
                } else {
                    expected_normal_lane(mask)
                };
                assert_eq!(
                    selected_lane(&decision),
                    expected_lane,
                    "mask={mask:03b}, agent={agent_bypasses}, background={background_bypasses}"
                );

                let expected_agent = if !agent_present || expected_lane == Some(RunLane::Agent) {
                    0
                } else {
                    agent_bypasses.saturating_add(1)
                };
                let expected_background =
                    if !background_present || expected_lane == Some(RunLane::Background) {
                        0
                    } else {
                        background_bypasses.saturating_add(1)
                    };
                assert_eq!(
                    decision.counters,
                    SchedulerCounters {
                        agent_bypasses: expected_agent,
                        background_bypasses: expected_background,
                    },
                    "mask={mask:03b}, agent={agent_bypasses}, background={background_bypasses}"
                );

                let expected_head = match expected_lane {
                    Some(RunLane::User) => Some("user-head"),
                    Some(RunLane::Agent) => Some("agent-head"),
                    Some(RunLane::Background) => Some("background-head"),
                    None => None,
                };
                assert_eq!(
                    decision.selected.as_ref().map(|selected| selected.head),
                    expected_head
                );
            }
        }
    }
}

#[test]
fn background_and_agent_service_bounds_hold_under_continuous_contention() {
    for agent_threshold in 1..=8 {
        for background_threshold in 1..=8 {
            let policy = SchedulerPolicy::new(agent_threshold, background_threshold);
            assert!(policy.is_ok());
            let Some(policy) = policy.ok() else {
                continue;
            };
            let mut counters = SchedulerCounters::default();
            let mut claims_since_agent = 0_u64;
            let mut claims_since_background = 0_u64;

            for _ in 0..256 {
                let decision = policy.claim(counters, heads(0b111));
                counters = decision.counters;
                claims_since_agent += 1;
                claims_since_background += 1;

                match selected_lane(&decision) {
                    Some(RunLane::Agent) => claims_since_agent = 0,
                    Some(RunLane::Background) => claims_since_background = 0,
                    _ => {}
                }

                assert!(
                    claims_since_agent <= agent_threshold + 1,
                    "agent threshold={agent_threshold}, background threshold={background_threshold}"
                );
                assert!(
                    claims_since_background <= background_threshold,
                    "agent threshold={agent_threshold}, background threshold={background_threshold}"
                );
            }
        }
    }
}

#[test]
fn a_user_is_delayed_by_at_most_two_simultaneous_promotions() {
    let policy = SchedulerPolicy::new(2, 3);
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let mut counters = SchedulerCounters {
        agent_bypasses: 2,
        background_bypasses: 3,
    };
    let mut lanes = Vec::new();

    for _ in 0..3 {
        let decision = policy.claim(counters, heads(0b111));
        counters = decision.counters;
        lanes.push(selected_lane(&decision));
    }

    assert_eq!(
        lanes,
        vec![
            Some(RunLane::Background),
            Some(RunLane::Agent),
            Some(RunLane::User)
        ]
    );
}

#[test]
fn counters_saturate_and_absent_lanes_reset() {
    let policy = SchedulerPolicy::default();
    let decision = policy.claim(
        SchedulerCounters {
            agent_bypasses: u64::MAX,
            background_bypasses: u64::MAX,
        },
        LaneHeads {
            user: Some("user"),
            agent: Some("agent"),
            background: None,
        },
    );

    assert_eq!(selected_lane(&decision), Some(RunLane::Agent));
    assert_eq!(decision.counters.agent_bypasses, 0);
    assert_eq!(decision.counters.background_bypasses, 0);

    let saturated = policy.claim(
        SchedulerCounters {
            agent_bypasses: u64::MAX,
            background_bypasses: u64::MAX - 1,
        },
        LaneHeads {
            user: Some("user"),
            agent: Some("agent"),
            background: Some("background"),
        },
    );
    assert_eq!(selected_lane(&saturated), Some(RunLane::Background));
    assert_eq!(saturated.counters.agent_bypasses, u64::MAX);
    assert_eq!(saturated.counters.background_bypasses, 0);
}
