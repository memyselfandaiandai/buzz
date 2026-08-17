//! HumanCardBroker — bounded choices 2-6, exactly-once answer→resume, immutable transcript.
//!
//! Feature-gated by `cards-automations-skills` (off by default). No publish/share surface.

use serde::{Deserialize, Serialize};

use crate::LifecycleError;

/// Card kind — only supported kind for this slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardKind {
    ActionRequest,
}

impl CardKind {
    const fn as_str(self) -> &'static str {
        "action_request"
    }
}

impl std::str::FromStr for CardKind {
    type Err = LifecycleError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "action_request" | "actionRequest" => Ok(Self::ActionRequest),
            _other => Err(LifecycleError::InvalidRequest("unknown card kind")),
        }
    }
}
impl std::fmt::Display for CardKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One choice label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardChoice {
    pub choice_id: String,
    pub label: String,
}

fn validate_choices(choices: &[CardChoice]) -> Result<(), LifecycleError> {
    if !(2..=6).contains(&choices.len()) {
        return Err(LifecycleError::InvalidRequest(
            "card must have 2..=6 choices",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for c in choices {
        if c.choice_id.is_empty() || c.label.is_empty() {
            return Err(LifecycleError::InvalidRequest(
                "choice id/label must be non-empty",
            ));
        }
        if c.choice_id.len() > 64 || c.label.len() > 128 {
            return Err(LifecycleError::InvalidRequest(
                "choice id/label is too long",
            ));
        }
        if !seen.insert(&c.choice_id) {
            return Err(LifecycleError::InvalidRequest("duplicate choice id"));
        }
    }
    Ok(())
}

/// Immutable created card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanCard {
    pub card_id: String,
    pub turn_id: String,
    pub owner_id: String,
    pub agent_id: String,
    pub kind: CardKind,
    pub title: String,
    pub body: String,
    pub choices: Vec<CardChoice>,
    pub created_at_ms: i64,
    pub answered: Option<CardAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardAnswer {
    pub choice_id: String,
    pub answered_at_ms: i64,
    pub resumed: bool,
}

impl HumanCard {
    pub fn validate_new(&self) -> Result<(), LifecycleError> {
        if self.card_id.is_empty()
            || self.turn_id.is_empty()
            || self.owner_id.is_empty()
            || self.agent_id.is_empty()
        {
            return Err(LifecycleError::InvalidRequest(
                "card identifiers must be non-empty",
            ));
        }
        if self.title.is_empty() || self.title.len() > 256 {
            return Err(LifecycleError::InvalidRequest("card title must be 1..=256"));
        }
        if self.body.len() > 4096 {
            return Err(LifecycleError::InvalidRequest("card body is too long"));
        }
        if self.created_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "created_at must be non-negative",
            ));
        }
        validate_choices(&self.choices)?;
        if self.answered.is_some() {
            return Err(LifecycleError::InvalidRequest(
                "new card must not be pre-answered",
            ));
        }
        Ok(())
    }
}

/// One transcript entry (immutable, insert-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub entry_id: String,
    pub card_id: String,
    pub turn_id: String,
    pub owner_id: String,
    pub kind: String, // "created" | "answered" | "resume"
    pub payload_json: serde_json::Value,
    pub created_at_ms: i64,
}

/// In-memory broker used by tests and as the in-process authority; durable
/// persistence is via `LifecycleStore` helpers below so crash-reopen semantics
/// mirror the turn lifecycle.
#[derive(Debug, Default)]
pub struct HumanCardBroker {
    cards: std::collections::HashMap<String, HumanCard>,
    transcript: Vec<TranscriptEntry>,
}

impl HumanCardBroker {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn create(&mut self, card: HumanCard) -> Result<HumanCard, LifecycleError> {
        card.validate_new()?;
        if self.cards.contains_key(&card.card_id) {
            return Err(LifecycleError::InvalidRequest("card id already exists"));
        }
        let entry = TranscriptEntry {
            entry_id: format!("{}#created", card.card_id),
            card_id: card.card_id.clone(),
            turn_id: card.turn_id.clone(),
            owner_id: card.owner_id.clone(),
            kind: "created".into(),
            payload_json: serde_json::to_value(&card).unwrap_or(serde_json::Value::Null),
            created_at_ms: card.created_at_ms,
        };
        self.transcript.push(entry);
        self.cards.insert(card.card_id.clone(), card.clone());
        Ok(card)
    }
    pub fn get(&self, card_id: &str) -> Option<&HumanCard> {
        self.cards.get(card_id)
    }
    /// Exactly-once answer→resume. Second caller gets `AlreadyAnswered`. Resume flag is set atomically with the answer.
    pub fn answer(
        &mut self,
        card_id: &str,
        choice_id: &str,
        answered_at_ms: i64,
    ) -> Result<HumanCard, LifecycleError> {
        if answered_at_ms < 0 {
            return Err(LifecycleError::InvalidRequest(
                "answered_at must be non-negative",
            ));
        }
        let card = self
            .cards
            .get_mut(card_id)
            .ok_or(LifecycleError::InvalidRequest("card not found"))?;
        if card.answered.is_some() {
            return Err(LifecycleError::InvalidRequest("card already answered"));
        }
        if !card.choices.iter().any(|c| c.choice_id == choice_id) {
            return Err(LifecycleError::InvalidRequest("unknown choice id"));
        }
        card.answered = Some(CardAnswer {
            choice_id: choice_id.to_owned(),
            answered_at_ms,
            resumed: true,
        });
        let snapshot = card.clone();
        self.transcript.push(TranscriptEntry { entry_id: format!("{}#answered", card.card_id), card_id: card.card_id.clone(), turn_id: card.turn_id.clone(), owner_id: card.owner_id.clone(), kind: "answered".into(), payload_json: serde_json::json!({"choiceId": choice_id, "answeredAtMs": answered_at_ms}), created_at_ms: answered_at_ms });
        self.transcript.push(TranscriptEntry {
            entry_id: format!("{}#resume", card.card_id),
            card_id: card.card_id.clone(),
            turn_id: card.turn_id.clone(),
            owner_id: card.owner_id.clone(),
            kind: "resume".into(),
            payload_json: serde_json::json!({"resumed": true}),
            created_at_ms: answered_at_ms,
        });
        Ok(snapshot)
    }
    pub fn transcript_for_card(&self, card_id: &str) -> Vec<&TranscriptEntry> {
        self.transcript
            .iter()
            .filter(|e| e.card_id == card_id)
            .collect()
    }
    pub fn transcript(&self) -> &[TranscriptEntry] {
        &self.transcript
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn card(id: &str) -> HumanCard {
        HumanCard {
            card_id: id.to_owned(),
            turn_id: "t1".into(),
            owner_id: "o1".into(),
            agent_id: "a1".into(),
            kind: CardKind::ActionRequest,
            title: "Pick one".into(),
            body: "Choose wisely".into(),
            choices: vec![
                CardChoice {
                    choice_id: "yes".into(),
                    label: "Yes".into(),
                },
                CardChoice {
                    choice_id: "no".into(),
                    label: "No".into(),
                },
            ],
            created_at_ms: 100,
            answered: None,
        }
    }
    #[test]
    fn bounded_choices_enforced() {
        let mut b = HumanCardBroker::new();
        let mut c = card("c1");
        c.choices = vec![CardChoice {
            choice_id: "a".into(),
            label: "A".into(),
        }];
        assert!(b.create(c).is_err());
        let mut c2 = card("c2");
        c2.choices = (0..7)
            .map(|i| CardChoice {
                choice_id: format!("c{i}"),
                label: format!("L{i}"),
            })
            .collect();
        assert!(b.create(c2).is_err());
    }
    #[test]
    fn exactly_once_answer_resume() {
        let mut b = HumanCardBroker::new();
        b.create(card("c1")).unwrap();
        let a1 = b.answer("c1", "yes", 200).unwrap();
        assert!(a1.answered.as_ref().unwrap().resumed);
        assert!(b.answer("c1", "no", 201).is_err());
        assert_eq!(b.transcript_for_card("c1").len(), 3); // created, answered, resume
    }
    #[test]
    fn transcript_immutable_append_only() {
        let mut b = HumanCardBroker::new();
        b.create(card("c1")).unwrap();
        b.answer("c1", "yes", 200).unwrap();
        let kinds: Vec<_> = b
            .transcript_for_card("c1")
            .iter()
            .map(|e| e.kind.as_str())
            .collect();
        assert_eq!(kinds, ["created", "answered", "resume"]);
    }
}
