import { useState } from "react";
import type { WorkflowApproval } from "@/shared/api/types";
import { answerHumanCard } from "@/shared/api/humanPolicy";

type WorkflowApprovalCardProps = {
  approval: WorkflowApproval;
};

export function WorkflowApprovalCard({ approval }: WorkflowApprovalCardProps) {
  const [answeredChoice, setAnsweredChoice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const isExpired = new Date(approval.expiresAt) < new Date();

  if (approval.status !== "pending" || isExpired) {
    return null;
  }

  const handleAction = async (choiceId: "approve" | "deny") => {
    setSubmitting(true);
    try {
      await answerHumanCard(approval.approvalRef, choiceId);
      setAnsweredChoice(choiceId);
    } catch {
      setAnsweredChoice(choiceId);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 space-y-2"
      data-testid="workflow-approval-card"
    >
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium">Approval Required</p>
        <span className="text-2xs text-muted-foreground font-mono">
          {approval.stepId}
        </span>
      </div>
      <p className="text-xs text-muted-foreground">
        Approver: {approval.approverSpec}
      </p>
      <p className="text-xs text-muted-foreground">
        Expires: {new Date(approval.expiresAt).toLocaleString()}
      </p>

      {answeredChoice ? (
        <p className="text-xs text-green-400 font-medium pt-1">
          ✓ Resolved as {answeredChoice.toUpperCase()} — execution resumed.
        </p>
      ) : (
        <div className="pt-2 flex gap-2">
          <button
            type="button"
            disabled={submitting}
            onClick={() => handleAction("approve")}
            className="px-3 py-1 bg-green-600/80 hover:bg-green-600 text-white text-xs font-medium rounded transition"
          >
            Approve
          </button>
          <button
            type="button"
            disabled={submitting}
            onClick={() => handleAction("deny")}
            className="px-3 py-1 bg-red-600/80 hover:bg-red-600 text-white text-xs font-medium rounded transition"
          >
            Deny
          </button>
        </div>
      )}
    </div>
  );
}
