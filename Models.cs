using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace SciChain
{
    /// <summary>
    /// Structured data carried in Transaction.Data for review transactions.
    /// Contains the reviewer's comments and their decision on the pending block.
    /// </summary>
    public class ReviewData
    {
        public enum Decision
        {
            Approve,
            RequestRevision,
            Reject
        }

        public string BlockGUID { get; set; }
        public string ReviewerAddress { get; set; }
        public Decision ReviewDecision { get; set; }
        public string Comments { get; set; }
        public DateTime Timestamp { get; set; }

        public ReviewData(string blockGUID, string reviewerAddress, Decision decision, string comments)
        {
            BlockGUID = blockGUID;
            ReviewerAddress = reviewerAddress;
            ReviewDecision = decision;
            Comments = comments;
            Timestamp = DateTime.UtcNow;
        }

        [JsonConstructor]
        public ReviewData() { }

        public string Serialize()
        {
            return JsonConvert.SerializeObject(this);
        }

        public static ReviewData Deserialize(string json)
        {
            if (string.IsNullOrEmpty(json))
                return null;
            try
            {
                return JsonConvert.DeserializeObject<ReviewData>(json);
            }
            catch
            {
                // Backwards compatibility: old reviews stored just the GUID string
                return null;
            }
        }
    }

    /// <summary>
    /// Structured data for revision transactions. Authors submit revisions in response 
    /// to reviewer feedback, referencing the original block and the review that prompted it.
    /// </summary>
    public class RevisionData
    {
        public string OriginalBlockGUID { get; set; }
        public string ReviewSignature { get; set; }
        public string RevisionNotes { get; set; }
        public string UpdatedContentHash { get; set; }
        public string UpdatedDOI { get; set; }
        public int RevisionNumber { get; set; }
        public DateTime Timestamp { get; set; }

        public RevisionData(string originalBlockGUID, string reviewSignature, string revisionNotes,
                           string updatedContentHash, string updatedDOI, int revisionNumber)
        {
            OriginalBlockGUID = originalBlockGUID;
            ReviewSignature = reviewSignature;
            RevisionNotes = revisionNotes;
            UpdatedContentHash = updatedContentHash;
            UpdatedDOI = updatedDOI;
            RevisionNumber = revisionNumber;
            Timestamp = DateTime.UtcNow;
        }

        [JsonConstructor]
        public RevisionData() { }

        public string Serialize()
        {
            return JsonConvert.SerializeObject(this);
        }

        public static RevisionData Deserialize(string json)
        {
            if (string.IsNullOrEmpty(json))
                return null;
            try
            {
                return JsonConvert.DeserializeObject<RevisionData>(json);
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Structured data for governance proposal transactions.
    /// A proposal describes a change and has a voting deadline.
    /// </summary>
    public class ProposalData
    {
        public enum ProposalStatus
        {
            Active,
            Passed,
            Rejected,
            Expired
        }

        public string ProposalId { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public string ProposerAddress { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime VotingDeadline { get; set; }
        public decimal ApprovalThreshold { get; set; }

        public ProposalData(string title, string description, string proposerAddress,
                           int votingPeriodDays, decimal approvalThreshold = 0.5M)
        {
            ProposalId = Guid.NewGuid().ToString();
            Title = title;
            Description = description;
            ProposerAddress = proposerAddress;
            CreatedAt = DateTime.UtcNow;
            VotingDeadline = CreatedAt.AddDays(votingPeriodDays);
            ApprovalThreshold = approvalThreshold;
        }

        [JsonConstructor]
        public ProposalData() { }

        public string Serialize()
        {
            return JsonConvert.SerializeObject(this);
        }

        public static ProposalData Deserialize(string json)
        {
            if (string.IsNullOrEmpty(json))
                return null;
            try
            {
                return JsonConvert.DeserializeObject<ProposalData>(json);
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Structured data for vote transactions. References a proposal by ID
    /// and records the voter's yes/no decision.
    /// </summary>
    public class VoteData
    {
        public string ProposalId { get; set; }
        public string VoterAddress { get; set; }
        public bool InFavor { get; set; }
        public DateTime Timestamp { get; set; }

        public VoteData(string proposalId, string voterAddress, bool inFavor)
        {
            ProposalId = proposalId;
            VoterAddress = voterAddress;
            InFavor = inFavor;
            Timestamp = DateTime.UtcNow;
        }

        [JsonConstructor]
        public VoteData() { }

        public string Serialize()
        {
            return JsonConvert.SerializeObject(this);
        }

        public static VoteData Deserialize(string json)
        {
            if (string.IsNullOrEmpty(json))
                return null;
            try
            {
                return JsonConvert.DeserializeObject<VoteData>(json);
            }
            catch
            {
                return null;
            }
        }
    }
}
