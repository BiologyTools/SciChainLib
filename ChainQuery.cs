using System;
using System.Collections.Generic;
using System.Linq;

namespace SciChain
{
    /// <summary>
    /// Read-only query methods for browsing published documents, review history,
    /// governance proposals, and chain statistics. All methods are thread-safe
    /// via the chain lock.
    /// </summary>
    public static class ChainQuery
    {
        private static readonly object chainLock = Blockchain.ChainLock;

        #region Document Queries

        /// <summary>
        /// Returns all mined blocks that have a BlockDocument attached,
        /// ordered by index (chronological publication order).
        /// </summary>
        public static List<Block> GetPublishedDocuments()
        {
            var results = new List<Block>();
            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.BlockDocument != null)
                        results.Add(block);
                }
            }
            return results;
        }

        /// <summary>
        /// Finds a published block by its DOI. Returns null if not found.
        /// </summary>
        public static Block GetBlockByDOI(string doi)
        {
            if (string.IsNullOrEmpty(doi))
                return null;

            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.BlockDocument != null && block.BlockDocument.DOI == doi)
                        return block;
                }
            }
            return null;
        }

        /// <summary>
        /// Finds a published block by its GUID. Searches both chain and pending.
        /// </summary>
        public static Block GetBlockByGUID(string guid, bool searchPending = false)
        {
            if (string.IsNullOrEmpty(guid))
                return null;

            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.GUID == guid)
                        return block;
                }
            }

            if (searchPending)
                return Blockchain.GetPendingBlock(guid);

            return null;
        }

        /// <summary>
        /// Returns all published blocks where the given address is listed as a publisher.
        /// </summary>
        public static List<Block> GetDocumentsByPublisher(string address)
        {
            var results = new List<Block>();
            if (string.IsNullOrEmpty(address))
                return results;

            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.BlockDocument?.Publishers != null &&
                        block.BlockDocument.Publishers.Contains(address))
                    {
                        results.Add(block);
                    }
                }
            }
            return results;
        }

        /// <summary>
        /// Searches published documents by keyword in Title, Abstract, or DOI.
        /// Case-insensitive partial match.
        /// </summary>
        public static List<Block> SearchDocuments(string keyword)
        {
            var results = new List<Block>();
            if (string.IsNullOrEmpty(keyword))
                return results;

            string lowerKeyword = keyword.ToLowerInvariant();
            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    var doc = block.BlockDocument;
                    if (doc == null) continue;

                    bool matchesDOI = doc.DOI?.ToLowerInvariant().Contains(lowerKeyword) == true;
                    bool matchesTitle = doc.Title?.ToLowerInvariant().Contains(lowerKeyword) == true;
                    bool matchesAbstract = doc.Abstract?.ToLowerInvariant().Contains(lowerKeyword) == true;

                    if (matchesDOI || matchesTitle || matchesAbstract)
                        results.Add(block);
                }
            }
            return results;
        }

        #endregion

        #region Review Queries

        /// <summary>
        /// Returns all review transactions for a given block GUID,
        /// with their structured ReviewData deserialized where possible.
        /// Searches both chain and pending transactions.
        /// </summary>
        public static List<ReviewRecord> GetReviewHistory(string blockGUID)
        {
            var reviews = new List<ReviewRecord>();
            if (string.IsNullOrEmpty(blockGUID))
                return reviews;

            // Search mined blocks
            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.Transactions == null) continue;
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType != Block.Transaction.Type.review)
                            continue;

                        ReviewRecord record = BuildReviewRecord(trans, blockGUID, true);
                        if (record != null)
                            reviews.Add(record);
                    }
                }
            }

            // Search pending transactions
            foreach (var kvp in Blockchain.PendingTransactions)
            {
                var trans = kvp.Value;
                if (trans.TransactionType != Block.Transaction.Type.review)
                    continue;

                ReviewRecord record = BuildReviewRecord(trans, blockGUID, false);
                if (record != null)
                    reviews.Add(record);
            }

            return reviews;
        }

        private static ReviewRecord BuildReviewRecord(Block.Transaction trans, string blockGUID, bool isMined)
        {
            // Try structured ReviewData first (new format)
            ReviewData reviewData = ReviewData.Deserialize(trans.Data);
            if (reviewData != null && reviewData.BlockGUID == blockGUID)
            {
                return new ReviewRecord
                {
                    ReviewerAddress = reviewData.ReviewerAddress ?? trans.ToAddress,
                    Decision = reviewData.ReviewDecision,
                    Comments = reviewData.Comments,
                    Timestamp = reviewData.Timestamp,
                    Signature = trans.Signature,
                    IsMined = isMined
                };
            }

            // Backwards compatibility: old format stored just the GUID in Data
            if (trans.Data == blockGUID)
            {
                return new ReviewRecord
                {
                    ReviewerAddress = trans.ToAddress,
                    Decision = ReviewData.Decision.Approve,
                    Comments = null,
                    Timestamp = DateTime.MinValue,
                    Signature = trans.Signature,
                    IsMined = isMined
                };
            }

            return null;
        }

        /// <summary>
        /// Returns all flag transactions for a given block GUID.
        /// </summary>
        public static List<FlagRecord> GetFlagHistory(string blockGUID)
        {
            var flagRecords = new List<FlagRecord>();
            if (string.IsNullOrEmpty(blockGUID))
                return flagRecords;

            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.Transactions == null) continue;
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType == Block.Transaction.Type.flag && trans.Data == blockGUID)
                        {
                            flagRecords.Add(new FlagRecord
                            {
                                FlaggerAddress = trans.ToAddress,
                                Signature = trans.Signature,
                                IsMined = true
                            });
                        }
                    }
                }
            }

            foreach (var kvp in Blockchain.PendingTransactions)
            {
                var trans = kvp.Value;
                if (trans.TransactionType == Block.Transaction.Type.flag && trans.Data == blockGUID)
                {
                    flagRecords.Add(new FlagRecord
                    {
                        FlaggerAddress = trans.ToAddress,
                        Signature = trans.Signature,
                        IsMined = false
                    });
                }
            }

            return flagRecords;
        }

        /// <summary>
        /// Returns all revision transactions for a given block GUID.
        /// </summary>
        public static List<RevisionRecord> GetRevisionHistory(string blockGUID)
        {
            var revisions = new List<RevisionRecord>();
            if (string.IsNullOrEmpty(blockGUID))
                return revisions;

            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.Transactions == null) continue;
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType != Block.Transaction.Type.revision)
                            continue;

                        RevisionData revData = RevisionData.Deserialize(trans.Data);
                        if (revData != null && revData.OriginalBlockGUID == blockGUID)
                        {
                            revisions.Add(new RevisionRecord
                            {
                                AuthorAddress = trans.FromAddress,
                                RevisionNotes = revData.RevisionNotes,
                                UpdatedContentHash = revData.UpdatedContentHash,
                                UpdatedDOI = revData.UpdatedDOI,
                                RevisionNumber = revData.RevisionNumber,
                                Timestamp = revData.Timestamp,
                                Signature = trans.Signature,
                                IsMined = true
                            });
                        }
                    }
                }
            }

            foreach (var kvp in Blockchain.PendingTransactions)
            {
                var trans = kvp.Value;
                if (trans.TransactionType != Block.Transaction.Type.revision)
                    continue;

                RevisionData revData = RevisionData.Deserialize(trans.Data);
                if (revData != null && revData.OriginalBlockGUID == blockGUID)
                {
                    revisions.Add(new RevisionRecord
                    {
                        AuthorAddress = trans.FromAddress,
                        RevisionNotes = revData.RevisionNotes,
                        UpdatedContentHash = revData.UpdatedContentHash,
                        UpdatedDOI = revData.UpdatedDOI,
                        RevisionNumber = revData.RevisionNumber,
                        Timestamp = revData.Timestamp,
                        Signature = trans.Signature,
                        IsMined = false
                    });
                }
            }

            return revisions.OrderBy(r => r.RevisionNumber).ToList();
        }

        #endregion

        #region Governance Queries

        /// <summary>
        /// Returns all governance proposals from the chain, with their current status
        /// computed from vote tallies and deadlines.
        /// </summary>
        public static List<ProposalRecord> GetProposals(bool activeOnly = false)
        {
            var proposals = new List<ProposalRecord>();

            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.Transactions == null) continue;
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType != Block.Transaction.Type.proposal)
                            continue;

                        ProposalData propData = ProposalData.Deserialize(trans.Data);
                        if (propData == null) continue;

                        var record = BuildProposalRecord(propData, trans.Signature);
                        if (activeOnly && record.Status != ProposalData.ProposalStatus.Active)
                            continue;

                        proposals.Add(record);
                    }
                }
            }

            // Also check pending proposals
            foreach (var kvp in Blockchain.PendingTransactions)
            {
                var trans = kvp.Value;
                if (trans.TransactionType != Block.Transaction.Type.proposal)
                    continue;

                ProposalData propData = ProposalData.Deserialize(trans.Data);
                if (propData == null) continue;

                var record = BuildProposalRecord(propData, trans.Signature);
                record.IsMined = false;
                if (activeOnly && record.Status != ProposalData.ProposalStatus.Active)
                    continue;

                proposals.Add(record);
            }

            return proposals;
        }

        private static ProposalRecord BuildProposalRecord(ProposalData propData, string transactionSignature)
        {
            var tally = TallyVotes(propData.ProposalId);
            ProposalData.ProposalStatus status = ComputeProposalStatus(propData, tally);

            return new ProposalRecord
            {
                Proposal = propData,
                VotesFor = tally.VotesFor,
                VotesAgainst = tally.VotesAgainst,
                TotalVoters = tally.TotalVoters,
                Status = status,
                TransactionSignature = transactionSignature,
                IsMined = true
            };
        }

        /// <summary>
        /// Tallies votes for a specific proposal. Each address gets one vote;
        /// if they voted multiple times, only the latest counts.
        /// </summary>
        public static VoteTally TallyVotes(string proposalId)
        {
            var latestVotes = new Dictionary<string, bool>();

            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.Transactions == null) continue;
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType != Block.Transaction.Type.vote)
                            continue;

                        VoteData voteData = VoteData.Deserialize(trans.Data);
                        if (voteData == null || voteData.ProposalId != proposalId)
                            continue;

                        // Latest vote per address wins
                        latestVotes[voteData.VoterAddress] = voteData.InFavor;
                    }
                }
            }

            // Also count pending votes
            foreach (var kvp in Blockchain.PendingTransactions)
            {
                var trans = kvp.Value;
                if (trans.TransactionType != Block.Transaction.Type.vote)
                    continue;

                VoteData voteData = VoteData.Deserialize(trans.Data);
                if (voteData == null || voteData.ProposalId != proposalId)
                    continue;

                latestVotes[voteData.VoterAddress] = voteData.InFavor;
            }

            int votesFor = latestVotes.Values.Count(v => v);
            int votesAgainst = latestVotes.Values.Count(v => !v);

            return new VoteTally
            {
                ProposalId = proposalId,
                VotesFor = votesFor,
                VotesAgainst = votesAgainst,
                TotalVoters = latestVotes.Count
            };
        }

        private static ProposalData.ProposalStatus ComputeProposalStatus(ProposalData proposal, VoteTally tally)
        {
            if (DateTime.UtcNow < proposal.VotingDeadline)
                return ProposalData.ProposalStatus.Active;

            if (tally.TotalVoters == 0)
                return ProposalData.ProposalStatus.Expired;

            decimal approvalRate = (decimal)tally.VotesFor / tally.TotalVoters;
            if (approvalRate >= proposal.ApprovalThreshold)
                return ProposalData.ProposalStatus.Passed;

            return ProposalData.ProposalStatus.Rejected;
        }

        /// <summary>
        /// Checks if an address has already voted on a specific proposal.
        /// </summary>
        public static bool HasVoted(string proposalId, string voterAddress)
        {
            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.Transactions == null) continue;
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType != Block.Transaction.Type.vote)
                            continue;

                        VoteData voteData = VoteData.Deserialize(trans.Data);
                        if (voteData != null && voteData.ProposalId == proposalId &&
                            voteData.VoterAddress == voterAddress)
                            return true;
                    }
                }
            }

            foreach (var kvp in Blockchain.PendingTransactions)
            {
                var trans = kvp.Value;
                if (trans.TransactionType != Block.Transaction.Type.vote)
                    continue;

                VoteData voteData = VoteData.Deserialize(trans.Data);
                if (voteData != null && voteData.ProposalId == proposalId &&
                    voteData.VoterAddress == voterAddress)
                    return true;
            }

            return false;
        }

        #endregion

        #region Chain Statistics

        /// <summary>
        /// Returns aggregate statistics about the current chain state.
        /// </summary>
        public static ChainStats GetChainStats()
        {
            int totalBlocks = 0;
            int totalTransactions = 0;
            int publishedDocuments = 0;
            int totalReviews = 0;
            int totalProposals = 0;
            int registeredUsers = 0;

            lock (chainLock)
            {
                totalBlocks = Blockchain.Chain.Count;
                foreach (var block in Blockchain.Chain)
                {
                    if (block.BlockDocument != null)
                        publishedDocuments++;

                    if (block.Transactions == null) continue;
                    foreach (var trans in block.Transactions)
                    {
                        totalTransactions++;
                        if (trans.TransactionType == Block.Transaction.Type.review)
                            totalReviews++;
                        if (trans.TransactionType == Block.Transaction.Type.proposal)
                            totalProposals++;
                        if (trans.TransactionType == Block.Transaction.Type.registration)
                            registeredUsers++;
                    }
                }
            }

            return new ChainStats
            {
                TotalBlocks = totalBlocks,
                TotalTransactions = totalTransactions,
                PublishedDocuments = publishedDocuments,
                TotalReviews = totalReviews,
                TotalProposals = totalProposals,
                RegisteredUsers = registeredUsers,
                PendingBlocks = Blockchain.PendingBlocks.Count,
                PendingTransactions = Blockchain.PendingTransactions.Count,
                CurrentSupply = Blockchain.currentSupply,
                TreasuryBalance = Blockchain.GetTreasury(),
                ConnectedPeers = Blockchain.Peers.Count
            };
        }

        /// <summary>
        /// Returns the full transaction history for an address.
        /// </summary>
        public static List<TransactionRecord> GetTransactionHistory(string address)
        {
            var history = new List<TransactionRecord>();
            if (string.IsNullOrEmpty(address))
                return history;

            lock (chainLock)
            {
                foreach (var block in Blockchain.Chain)
                {
                    if (block.Transactions == null) continue;
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.FromAddress == address || trans.ToAddress == address)
                        {
                            history.Add(new TransactionRecord
                            {
                                Transaction = trans,
                                BlockIndex = block.Index,
                                BlockTimestamp = block.TimeStamp,
                                IsMined = true
                            });
                        }
                    }
                }
            }

            return history;
        }

        #endregion

        #region Record Types

        public class ReviewRecord
        {
            public string ReviewerAddress { get; set; }
            public ReviewData.Decision Decision { get; set; }
            public string Comments { get; set; }
            public DateTime Timestamp { get; set; }
            public string Signature { get; set; }
            public bool IsMined { get; set; }
        }

        public class FlagRecord
        {
            public string FlaggerAddress { get; set; }
            public string Signature { get; set; }
            public bool IsMined { get; set; }
        }

        public class RevisionRecord
        {
            public string AuthorAddress { get; set; }
            public string RevisionNotes { get; set; }
            public string UpdatedContentHash { get; set; }
            public string UpdatedDOI { get; set; }
            public int RevisionNumber { get; set; }
            public DateTime Timestamp { get; set; }
            public string Signature { get; set; }
            public bool IsMined { get; set; }
        }

        public class ProposalRecord
        {
            public ProposalData Proposal { get; set; }
            public int VotesFor { get; set; }
            public int VotesAgainst { get; set; }
            public int TotalVoters { get; set; }
            public ProposalData.ProposalStatus Status { get; set; }
            public string TransactionSignature { get; set; }
            public bool IsMined { get; set; }
        }

        public class VoteTally
        {
            public string ProposalId { get; set; }
            public int VotesFor { get; set; }
            public int VotesAgainst { get; set; }
            public int TotalVoters { get; set; }
        }

        public class ChainStats
        {
            public int TotalBlocks { get; set; }
            public int TotalTransactions { get; set; }
            public int PublishedDocuments { get; set; }
            public int TotalReviews { get; set; }
            public int TotalProposals { get; set; }
            public int RegisteredUsers { get; set; }
            public int PendingBlocks { get; set; }
            public int PendingTransactions { get; set; }
            public decimal CurrentSupply { get; set; }
            public decimal TreasuryBalance { get; set; }
            public int ConnectedPeers { get; set; }
        }

        public class TransactionRecord
        {
            public Block.Transaction Transaction { get; set; }
            public int BlockIndex { get; set; }
            public DateTime BlockTimestamp { get; set; }
            public bool IsMined { get; set; }
        }

        #endregion
    }
}
