import { useState } from "react";
import type { HumanCard } from "@/shared/api/humanPolicy";
import { answerHumanCard } from "@/shared/api/humanPolicy";

type HumanCardProps = {
  card: HumanCard;
  onAnswered?: (updated: HumanCard) => void;
};

export function HumanCardComponent({ card, onAnswered }: HumanCardProps) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleChoice = async (choiceId: string) => {
    if (card.answered || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const updated = await answerHumanCard(card.card_id, choiceId);
      onAnswered?.(updated);
    } catch (err) {
      setError(String(err));
    } finally {
      setSubmitting(false);
    }
  };

  const isAnswered = Boolean(card.answered);
  const chosenId = card.answered?.choice_id;

  return (
    <div
      className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 space-y-3"
      data-testid="human-card"
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-amber-500">
          {card.kind}
        </span>
        <span className="text-xs text-muted-foreground">
          Agent: {card.agent_id.slice(0, 10)}...
        </span>
      </div>

      <div>
        <h4 className="text-sm font-semibold text-foreground">{card.title}</h4>
        <p className="mt-1 text-xs text-muted-foreground leading-relaxed whitespace-pre-wrap">
          {card.body}
        </p>
      </div>

      <div className="pt-2 flex flex-wrap gap-2">
        {card.choices.map((c) => {
          const isSelected = chosenId === c.choice_id;
          return (
            <button
              key={c.choice_id}
              type="button"
              disabled={isAnswered || submitting}
              onClick={() => handleChoice(c.choice_id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                isSelected
                  ? "bg-amber-600 text-white font-bold ring-2 ring-amber-400"
                  : isAnswered
                    ? "bg-muted text-muted-foreground opacity-50 cursor-not-allowed"
                    : "bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30"
              }`}
            >
              {c.label} {isSelected && "✓"}
            </button>
          );
        })}
      </div>

      {isAnswered && (
        <p className="text-2xs text-green-400/90 font-medium pt-1">
          ✓ Resolved (Choice: {chosenId}) — Turn execution resumed.
        </p>
      )}

      {error && (
        <p className="text-2xs text-red-400 font-medium pt-1">Error: {error}</p>
      )}
    </div>
  );
}
