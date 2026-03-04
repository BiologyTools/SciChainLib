using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Net.Http;
using Newtonsoft.Json;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using NetCoreServer;
using System.IO;
using System.Net.Sockets;
using JsonIgnoreAttribute = Newtonsoft.Json.JsonIgnoreAttribute;
using HttpClient = System.Net.Http.HttpClient;
using Gdk;

namespace SciChain
{
    public class Block
    {
        public class Transaction
        {
            public enum Type
            {
                transaction,
                blockreward,
                registration,
                review,
                flag,
                addreputation,
                removereputation,
                revision,
                proposal,
                vote,
            }
            public string FromAddress { get; set; }
            public string ToAddress { get; set; }
            public string PublicKey { get; set; }
            public decimal Amount { get; set; }
            public string Data { get; set; }
            public string Signature { get; set; }
            public Type TransactionType { get; set; }

            public Transaction(Type t, string fromAddress, RSAParameters par, string toAddress, decimal amount)
            {
                TransactionType = t;
                FromAddress = fromAddress;
                ToAddress = toAddress;
                Amount = amount;
                PublicKey = RSA.RSAParametersToString(par);
            }

            [JsonConstructor]
            public Transaction() { }

            public static string DecimalToStringWithMaxDecimals(decimal value)
            {
                return value.ToString("0.############################");
            }

            public void SignTransaction(RSAParameters privateKey)
            {
                string dataToSign;
                if (string.IsNullOrEmpty(FromAddress))
                    dataToSign = ToAddress + DecimalToStringWithMaxDecimals(Amount);
                else
                    dataToSign = FromAddress + ToAddress + DecimalToStringWithMaxDecimals(Amount);
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(privateKey);
                    var dataToSignBytes = Encoding.UTF8.GetBytes(dataToSign);
                    using (var hasher = SHA256.Create())
                    {
                        var hashedData = hasher.ComputeHash(dataToSignBytes);
                        Signature = Convert.ToBase64String(rsa.SignData(hashedData, CryptoConfig.MapNameToOID("SHA256")));
                    }
                }
            }
        }

        public int Index { get; set; }
        public DateTime TimeStamp { get; set; }
        public string PreviousHash { get; set; }
        public IList<Transaction> Transactions { get; set; }
        public string Hash { get; set; }
        public string GUID { get; set; }
        public Document BlockDocument { get; set; }

        public class Document
        {
            public string DOI { get; set; }
            public string Title { get; set; }
            public string Abstract { get; set; }
            public string ContentHash { get; set; }
            public string PublicKey { get; set; }
            public string Signature { get; set; }
            public IList<string> Publishers { get; set; }

            public Document(string dOI, string title, string abstract_, string contentHash,
                           IList<string> publishers, RSAParameters publicKey)
            {
                DOI = dOI;
                Title = title;
                Abstract = abstract_;
                ContentHash = contentHash;
                Publishers = publishers;
                PublicKey = RSA.RSAParametersToString(publicKey);
            }

            /// <summary>
            /// Backwards-compatible constructor for documents without the new fields.
            /// </summary>
            public Document(string dOI, IList<string> publishers, RSAParameters publicKey)
                : this(dOI, null, null, null, publishers, publicKey) { }

            [Newtonsoft.Json.JsonConstructor]
            public Document(string dOI, string title, string abstract_, string contentHash,
                           IList<string> publishers, string publicKey)
            {
                DOI = dOI;
                Title = title;
                Abstract = abstract_;
                ContentHash = contentHash;
                Publishers = publishers;
                PublicKey = publicKey;
            }

            public void SignDocument(RSAParameters privateKey, string Address)
            {
                var dataToSign = Address + Blockchain.miningReward.ToString();
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(privateKey);
                    var dataToSignBytes = Encoding.UTF8.GetBytes(dataToSign);
                    using (var hasher = SHA256.Create())
                    {
                        var hashedData = hasher.ComputeHash(dataToSignBytes);
                        Signature = Convert.ToBase64String(rsa.SignData(hashedData, CryptoConfig.MapNameToOID("SHA256")));
                    }
                }
            }
        }

        public Block(DateTime timeStamp, string previousHash, IList<Transaction> transactions)
        {
            Index = 0;
            TimeStamp = timeStamp;
            PreviousHash = previousHash;
            Transactions = transactions;
            Hash = CalculateHash();
            GUID = Guid.NewGuid().ToString();
        }

        [JsonConstructor]
        public Block() { }

        public string CalculateHash()
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                string rawData = $"{TimeStamp}-{PreviousHash ?? ""}-{JsonConvert.SerializeObject(Transactions)}";
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
            }
        }
    }

    public static class Blockchain
    {
        public static Wallet wallet;
        public static string ID;
        private static string pass = "";
        public static string Password
        {
            get
            {
                if (wallet == null)
                {
                    wallet = new Wallet();
                    wallet.Load(pass);
                }
                return pass;
            }
            set
            {
                pass = value;
            }
        }

        public static int currentHeight = 0;
        public static ConcurrentDictionary<string, Block.Transaction> PendingTransactions = new ConcurrentDictionary<string, Block.Transaction>();
        public static ConcurrentDictionary<string, Block> PendingBlocks = new ConcurrentDictionary<string, Block>();
        private static IList<Block> chain;
        public static IList<Block> Chain
        {
            set
            {
                lock (chainLock)
                {
                    chain = value;
                }
            }
            get
            {
                if (chain == null)
                    chain = new List<Block>();
                return chain;
            }
        }
        private static readonly object chainLock = new object();
        public static object ChainLock { get { return chainLock; } }
        private static readonly object mineLock = new object();
        private static readonly object peersLock = new object();
        private static CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        public const decimal totalSupply = 9900000000 + treasury + founder;
        public const decimal treasury = 100000000;
        public const string treasuryAddress = "a634bc56308e2be97b6f305d8feac8666cc549c0ee127d58a16d8d6e49e86e68";
        public const decimal founder = (9900000000 + treasury) * 0.05M;
        public const long population = 10000000000;
        public const decimal gift = 0.005M;
        public static decimal currentSupply = treasury + founder;
        public const decimal miningReward = 10;
        public const int maxPeers = 8;
        public const int port = 8333;
        public const int reviewers = 1;
        public const int flags = 0;
        static string dir = Path.GetDirectoryName(Environment.ProcessPath);
        public static Dictionary<Guid, Peer> Peers { set; get; } = new Dictionary<Guid, Peer>();
        public static ChatServer Server;

        private static bool genesisCreated = false;

        public static void Initialize(Wallet wal, string id)
        {
            if (wallet == null)
            {
                if (wal == null)
                    wal = new Wallet();
                wallet = wal;
                wal.Load(id);
            }
            ID = id;
            Settings.Load();
            string h = Settings.GetSettings("Height");
            if (h != "")
                currentHeight = int.Parse(h);
            Chain = new List<Block>();
            Directory.CreateDirectory(Path.Combine(dir, "Blocks"));
            try
            {
                Server = new ChatServer(IPAddress.Any, 8333);
                bool start = Server.Start();
                Console.WriteLine("Started:" + start);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public static Block CreateGenesisBlock(Wallet wallet)
        {
            Block.Transaction tr = new Block.Transaction(Block.Transaction.Type.blockreward, null, wallet.PublicKey, "0009-0007-0687-6045", founder);
            Block.Transaction tre = new Block.Transaction(Block.Transaction.Type.blockreward, null, wallet.PublicKey, treasuryAddress, treasury);
            List<Block.Transaction> trs = new List<Block.Transaction>();
            trs.Add(tr);
            trs.Add(tre);
            return new Block(DateTime.Now, null, trs);
        }

        public static void EnsureGenesis()
        {
            lock (chainLock)
            {
                if (Chain.Count == 0 && !genesisCreated)
                {
                    Chain.Add(CreateGenesisBlock(wallet));
                    genesisCreated = true;
                }
            }
        }

        public static Block GetLatestBlock()
        {
            lock (chainLock)
            {
                EnsureGenesis();
                return Chain[Chain.Count - 1];
            }
        }

        public static decimal GetBalance(string address, bool pending = false)
        {
            if (address == null)
                return 0;
            if (wallet == null)
            {
                wallet = new Wallet();
                wallet.Load(Password);
                Initialize(wallet, pass);
            }

            EnsureGenesis();

            decimal balance = 0;
            lock (chainLock)
            {
                foreach (var block in Chain)
                {
                    if (block.Transactions != null)
                        foreach (var trans in block.Transactions)
                        {
                            if (trans.FromAddress == address)
                                balance -= trans.Amount;
                            if (trans.ToAddress == address)
                                balance += trans.Amount;
                        }
                }
            }
            if (pending)
            {
                foreach (var kvp in PendingTransactions)
                {
                    var trans = kvp.Value;
                    if (trans.FromAddress == address)
                        balance -= trans.Amount;
                    if (trans.ToAddress == address)
                        balance += trans.Amount;
                }
            }
            return balance;
        }

        public static decimal GetReputation(string address)
        {
            if (address == null)
                return 0;
            decimal balance = 0;
            lock (chainLock)
            {
                foreach (var block in Chain)
                {
                    if (block.Transactions != null)
                        foreach (var trans in block.Transactions)
                        {
                            if (trans.TransactionType != Block.Transaction.Type.addreputation &&
                                trans.TransactionType != Block.Transaction.Type.removereputation)
                                continue;

                            if (trans.FromAddress == address && trans.TransactionType == Block.Transaction.Type.removereputation)
                                balance -= trans.Amount;
                            if (trans.ToAddress == address && trans.TransactionType == Block.Transaction.Type.addreputation)
                                balance += trans.Amount;
                        }
                }
            }
            return balance;
        }

        public static decimal GetTreasury()
        {
            return GetBalance(treasuryAddress, true);
        }

        public static int GetReviews(string guid)
        {
            int revs = 0;
            lock (chainLock)
            {
                foreach (var block in Chain)
                {
                    if (block.Transactions != null)
                        foreach (var trans in block.Transactions)
                        {
                            if (trans.TransactionType != Block.Transaction.Type.review)
                                continue;
                            if (MatchesReviewBlockGUID(trans.Data, guid))
                                revs++;
                        }
                }
            }

            foreach (var kvp in PendingTransactions)
            {
                var trans = kvp.Value;
                if (trans.TransactionType != Block.Transaction.Type.review)
                    continue;
                if (MatchesReviewBlockGUID(trans.Data, guid))
                    revs++;
            }
            return revs;
        }

        /// <summary>
        /// Checks if a review transaction's Data field references the given block GUID.
        /// Handles both new structured ReviewData and old plain GUID format.
        /// </summary>
        private static bool MatchesReviewBlockGUID(string transactionData, string guid)
        {
            if (transactionData == guid)
                return true;

            ReviewData reviewData = ReviewData.Deserialize(transactionData);
            if (reviewData != null && reviewData.BlockGUID == guid)
                return true;

            return false;
        }

        public static Block.Transaction GetTransaction(Block.Transaction tr, bool searchPending = false)
        {
            lock (chainLock)
            {
                foreach (var block in Chain)
                {
                    if (block.Transactions != null)
                        foreach (var trans in block.Transactions)
                        {
                            if (tr.Signature == trans.Signature)
                                return trans;
                        }
                }
            }

            if (searchPending)
            {
                foreach (var kvp in PendingTransactions)
                {
                    if (tr.Signature == kvp.Value.Signature)
                        return kvp.Value;
                }
            }
            return null;
        }

        public static Block.Transaction GetTransaction(Block.Transaction.Type type, bool searchPending = false)
        {
            lock (chainLock)
            {
                foreach (var block in Chain)
                {
                    if (block.Transactions != null)
                        foreach (var trans in block.Transactions)
                        {
                            if (trans.TransactionType == type)
                                return trans;
                        }
                }
            }

            if (searchPending)
            {
                foreach (var kvp in PendingTransactions)
                {
                    if (kvp.Value.TransactionType == type)
                        return kvp.Value;
                }
            }
            return null;
        }

        public static bool IsGenesis(Block b)
        {
            if (b?.Transactions == null) return false;

            foreach (var trans in b.Transactions)
            {
                if (trans.TransactionType == Block.Transaction.Type.blockreward && trans.Amount > miningReward)
                    return true;
            }
            return false;
        }

        public static Block.Transaction GetTransactionByData(string data, bool searchPending = false)
        {
            lock (chainLock)
            {
                foreach (var block in Chain)
                {
                    if (block.Transactions != null)
                        foreach (var trans in block.Transactions)
                        {
                            if (trans.Data == data)
                                return trans;
                        }
                }
            }

            if (searchPending)
            {
                foreach (var kvp in PendingTransactions)
                {
                    if (kvp.Value.Data == data)
                        return kvp.Value;
                }
            }
            return null;
        }

        public static bool VerifyBlock(Block bl)
        {
            if (bl == null)
                return false;

            // Blocks with no transactions are valid pending blocks
            if (bl.Transactions == null || bl.Transactions.Count == 0)
                return true;

            foreach (var trans in bl.Transactions)
            {
                // Verify signatures for all transactions except genesis
                if (!IsGenesis(bl) && !VerifyTransaction(trans))
                    return false;

                // Check block rewards don't exceed limit (except genesis)
                if (!IsGenesis(bl) && trans.TransactionType == Block.Transaction.Type.blockreward &&
                    trans.Amount > miningReward)
                    return false;

                // Validate amounts
                if (trans.Amount < 0)
                    return false;
            }

            return true;
        }

        public static Block.Transaction GetTransaction(string signature, bool searchPending = false)
        {
            if (string.IsNullOrEmpty(signature))
                return null;

            lock (chainLock)
            {
                foreach (var block in Chain)
                {
                    if (block.Transactions != null)
                        foreach (var trans in block.Transactions)
                        {
                            if (trans.Signature == signature)
                                return trans;
                        }
                }
            }

            if (searchPending)
            {
                foreach (var kvp in PendingTransactions)
                {
                    if (kvp.Value.Signature == signature)
                        return kvp.Value;
                }
            }
            return null;
        }

        public static int GetFlags(string guid)
        {
            int revs = 0;
            lock (chainLock)
            {
                foreach (var block in Chain)
                {
                    if (block.Transactions != null)
                        foreach (var trans in block.Transactions)
                        {
                            if (trans.TransactionType != Block.Transaction.Type.flag)
                                continue;
                            if (trans.Data == guid)
                                revs++;
                        }
                }
            }

            foreach (var kvp in PendingTransactions)
            {
                var trans = kvp.Value;
                if (trans.TransactionType != Block.Transaction.Type.flag)
                    continue;
                if (trans.Data == guid)
                    revs++;
            }
            return revs;
        }

        public static Block GetPendingBlock(string guid)
        {
            Block block;
            if (PendingBlocks.TryGetValue(guid, out block))
                return block;
            return null;
        }

        public static List<Block> GetPendingBlocksList()
        {
            return PendingBlocks.Values.ToList();
        }

        public static string CalculateHash(string st)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(st));
                return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
            }
        }

        public static void AddBlock(Block block)
        {
            if (wallet == null)
                Initialize(wallet, ID);
            if (!VerifyBlock(block))
            {
                Console.WriteLine("Block verification failed");
                return;
            }

            lock (chainLock)
            {
                foreach (var item in Chain)
                {
                    if (item.Hash == block.Hash)
                        return;
                }

                // Remove matching pending transactions from dictionary and disk
                if (block.Transactions != null)
                {
                    foreach (var blockTrans in block.Transactions)
                    {
                        if (string.IsNullOrEmpty(blockTrans.Signature))
                            continue;

                        string key = CalculateHash(blockTrans.Signature);
                        Block.Transaction removed;
                        PendingTransactions.TryRemove(key, out removed);

                        string filePath = Path.Combine(dir, "PendingTransactions", key + ".json");
                        if (File.Exists(filePath))
                            File.Delete(filePath);
                    }
                }

                Block latestBlock = Chain.Count > 0 ? Chain[Chain.Count - 1] : null;
                if (latestBlock != null)
                {
                    block.Index = latestBlock.Index + 1;
                    block.PreviousHash = latestBlock.Hash;
                }
                else
                {
                    block.Index = 0;
                    block.PreviousHash = null;
                }
                block.Hash = block.CalculateHash();
                Chain.Add(block);
            }
            Save(block);
        }

        public static void AddTransaction(Block.Transaction transaction)
        {
            BroadcastNewTransaction(transaction);
        }

        public static void AddPendingBlock(Block b)
        {
            if (PendingBlocks.ContainsKey(b.GUID))
                return;

            string pendingDir = Path.Combine(dir, "Pending");
            Directory.CreateDirectory(pendingDir);
            File.WriteAllText(Path.Combine(pendingDir, b.GUID + ".json"), JsonConvert.SerializeObject(b));
            PendingBlocks.TryAdd(b.GUID, b);
            BroadcastNewPendingBlock(b);
        }

        private static void SavePendingTransaction(Block.Transaction transaction)
        {
            string pendingDir = Path.Combine(dir, "PendingTransactions");
            Directory.CreateDirectory(pendingDir);
            string key = CalculateHash(transaction.Signature);
            PendingTransactions.TryAdd(key, transaction);
            File.WriteAllText(Path.Combine(pendingDir, key + ".json"),
                JsonConvert.SerializeObject(transaction));
        }

        public static async Task<bool> ProcessTransaction(Block.Transaction transaction)
        {
            if (string.IsNullOrEmpty(transaction.Signature))
            {
                Console.WriteLine("Transaction rejected: Missing signature");
                return false;
            }

            // Check if already processed
            if (GetTransaction(transaction.Signature, true) != null)
            {
                Console.WriteLine("Processing Transaction: Skipping already processed transaction.");
                return false;
            }

            Console.WriteLine("Processing Transaction:" + transaction.TransactionType);

            if (!VerifyTransaction(transaction))
            {
                Console.WriteLine("Transaction failed: Not a valid transaction.");
                return false;
            }

            // Validate amount
            if (transaction.Amount < 0)
            {
                Console.WriteLine("Transaction failed: Negative amount.");
                return false;
            }

            if (transaction.TransactionType == Block.Transaction.Type.transaction)
            {
                if (transaction.FromAddress != null)
                {
                    var senderBalance = GetBalance(transaction.FromAddress, true);
                    if (senderBalance < transaction.Amount)
                    {
                        Console.WriteLine("Transaction failed: Not enough balance.");
                        return false;
                    }
                }
                SavePendingTransaction(transaction);
                return true;
            }

            // Check ORCID for non-anonymous users
            if (!await Orcid.CheckORCIDExistence(transaction.FromAddress))
            {
                Console.WriteLine("Transaction failed: Invalid ORCID.");
                return false;
            }

            if (transaction.TransactionType == Block.Transaction.Type.registration)
            {
                decimal treasuryBalance = GetBalance(treasuryAddress, true);
                if (treasuryBalance < gift)
                {
                    Console.WriteLine("Treasury depleted - cannot register new users");
                    return false;
                }

                bool alreadyRegistered = false;
                lock (chainLock)
                {
                    foreach (Block item in Chain)
                    {
                        if (item.Transactions != null && item.Transactions.Count > 0)
                        {
                            foreach (Block.Transaction t in item.Transactions)
                            {
                                if (t.TransactionType == Block.Transaction.Type.registration &&
                                   t.ToAddress == transaction.ToAddress)
                                {
                                    alreadyRegistered = true;
                                    break;
                                }
                            }
                        }
                        if (alreadyRegistered)
                            break;
                    }
                }

                if (!alreadyRegistered)
                {
                    SavePendingTransaction(transaction);
                    return true;
                }
            }
            else if (transaction.TransactionType == Block.Transaction.Type.review)
            {
                // Extract block GUID from either structured ReviewData or plain Data field
                string blockGUID = null;
                ReviewData reviewData = ReviewData.Deserialize(transaction.Data);
                if (reviewData != null)
                    blockGUID = reviewData.BlockGUID;
                else
                    blockGUID = transaction.Data;

                if (string.IsNullOrEmpty(blockGUID))
                {
                    Console.WriteLine("Review failed: No block GUID specified.");
                    return false;
                }

                int revs = GetReviews(blockGUID);
                int fls = GetFlags(blockGUID);
                Console.WriteLine("Block: " + blockGUID + " Reviews: " + revs + " Flags: " + fls);
                SavePendingTransaction(transaction);

                if (revs >= reviewers && fls <= flags)
                {
                    MineBlock(blockGUID);
                }
                return true;
            }
            else if (transaction.TransactionType == Block.Transaction.Type.flag)
            {
                SavePendingTransaction(transaction);
                return true;
            }
            else if (transaction.TransactionType == Block.Transaction.Type.blockreward)
            {
                SavePendingTransaction(transaction);
                return true;
            }
            else if (transaction.TransactionType == Block.Transaction.Type.addreputation)
            {
                SavePendingTransaction(transaction);
                return true;
            }
            else if (transaction.TransactionType == Block.Transaction.Type.removereputation)
            {
                SavePendingTransaction(transaction);
                return true;
            }
            else if (transaction.TransactionType == Block.Transaction.Type.revision)
            {
                // Validate revision data is present and references an existing block
                RevisionData revData = RevisionData.Deserialize(transaction.Data);
                if (revData == null || string.IsNullOrEmpty(revData.OriginalBlockGUID))
                {
                    Console.WriteLine("Revision failed: Invalid revision data.");
                    return false;
                }

                Block originalBlock = GetPendingBlock(revData.OriginalBlockGUID);
                if (originalBlock == null)
                {
                    originalBlock = ChainQuery.GetBlockByGUID(revData.OriginalBlockGUID);
                }
                if (originalBlock == null)
                {
                    Console.WriteLine("Revision failed: Original block not found.");
                    return false;
                }

                SavePendingTransaction(transaction);
                return true;
            }
            else if (transaction.TransactionType == Block.Transaction.Type.proposal)
            {
                // Validate proposal data structure
                ProposalData propData = ProposalData.Deserialize(transaction.Data);
                if (propData == null || string.IsNullOrEmpty(propData.Title))
                {
                    Console.WriteLine("Proposal failed: Invalid proposal data.");
                    return false;
                }

                // Proposer must have non-negative reputation
                if (GetReputation(transaction.FromAddress) < 0)
                {
                    Console.WriteLine("Proposal failed: Proposer has negative reputation.");
                    return false;
                }

                SavePendingTransaction(transaction);
                return true;
            }
            else if (transaction.TransactionType == Block.Transaction.Type.vote)
            {
                // Validate vote data references a real proposal
                VoteData voteData = VoteData.Deserialize(transaction.Data);
                if (voteData == null || string.IsNullOrEmpty(voteData.ProposalId))
                {
                    Console.WriteLine("Vote failed: Invalid vote data.");
                    return false;
                }

                // Voter must be a registered user with non-negative reputation
                if (GetReputation(transaction.FromAddress) < 0)
                {
                    Console.WriteLine("Vote failed: Voter has negative reputation.");
                    return false;
                }

                // Check if already voted (one vote per address per proposal)
                if (ChainQuery.HasVoted(voteData.ProposalId, voteData.VoterAddress))
                {
                    Console.WriteLine("Vote failed: Already voted on this proposal.");
                    return false;
                }

                SavePendingTransaction(transaction);
                return true;
            }

            return false;
        }

        public static bool VerifyTransaction(Block.Transaction transaction)
        {
            if (transaction == null || string.IsNullOrEmpty(transaction.PublicKey))
                return false;

            using (var rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    rsa.ImportParameters(RSA.StringToRSAParameters(transaction.PublicKey));
                    string dataToVerify;
                    if (string.IsNullOrEmpty(transaction.FromAddress))
                        dataToVerify = transaction.ToAddress + Block.Transaction.DecimalToStringWithMaxDecimals(transaction.Amount);
                    else
                        dataToVerify = transaction.FromAddress + transaction.ToAddress + Block.Transaction.DecimalToStringWithMaxDecimals(transaction.Amount);
                    var dataToVerifyBytes = Encoding.UTF8.GetBytes(dataToVerify);
                    using (var hasher = SHA256.Create())
                    {
                        var hashedData = hasher.ComputeHash(dataToVerifyBytes);
                        return rsa.VerifyData(hashedData, CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(transaction.Signature));
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Transaction verification error: {e.Message}");
                    return false;
                }
            }
        }

        #region Server

        public static Peer GetPeer(Guid guid)
        {
            lock (peersLock)
            {
                foreach (var item in Peers)
                {
                    if (item.Value.ID == guid || item.Value.Client.Id == guid)
                        return item.Value;
                }
            }
            return null;
        }

        public static Peer GetPeer(string address)
        {
            lock (peersLock)
            {
                foreach (var item in Peers)
                {
                    if (item.Value.Address == address)
                        return item.Value;
                }
            }
            return null;
        }

        public class Peer
        {
            [JsonIgnore]
            public ChatClient Client { get; set; }
            public string Address { get; set; }
            public Guid ID { get; set; }
            public int Port { get; set; }

            public Peer(Guid guid, ChatClient cli, string address, int port)
            {
                Client = cli;
                Address = address;
                Port = port;
                ID = guid;
            }
        }

        public class Node
        {
            public string Address { get; set; }
            public int Port { get; set; }
        }

        public class Message
        {
            public string Type { get; set; }
            public string Content { get; set; }

            public Message(string type, string content)
            {
                Type = type;
                Content = content;
            }
        }

        public class GetCommand
        {
            public Peer Peer { get; set; }
            public string Type { get; set; }
            public string Data { get; set; }
            public string Content { get; set; }

            public GetCommand(Peer peer, string type, string data)
            {
                Peer = peer;
                Type = type;
                Data = data;
                Content = "";
            }
        }

        public static void ProcessMessage(Message message, Peer peer)
        {
            Console.WriteLine("Processing message: " + message.Type);

            if (peer == null)
            {
                Console.WriteLine("ProcessMessage: Peer is null");
                return;
            }

            try
            {
                string con = message.Content;

                if (message.Type == "NewBlock")
                {
                    var block = JsonConvert.DeserializeObject<Block>(con);
                    if (block != null && block.Index > GetLatestBlock()?.Index)
                    {
                        AddBlock(block);
                        Console.WriteLine(message.Type + " " + block.Hash);
                    }
                }
                else if (message.Type == "NewTransaction")
                {
                    var tr = JsonConvert.DeserializeObject<Block.Transaction>(con);
                    if (tr != null)
                        ProcessTransaction(tr);
                }
                else if (message.Type == "NewPeer")
                {
                    var pr = JsonConvert.DeserializeObject<Peer>(con);
                    if (pr != null)
                    {
                        int peerCount;
                        lock (peersLock) { peerCount = Peers.Count; }
                        bool exists;
                        lock (peersLock) { exists = Peers.Values.Any(p => p.Address == pr.Address); }

                        if (peerCount < maxPeers && !exists)
                            ConnectToPeer(pr.Address, new ChatClient(pr.Address, port), port);

                        BroadcastNewPeer(pr);
                    }
                }
                else if (message.Type == "Peers")
                {
                    var prs = JsonConvert.DeserializeObject<Peer[]>(con);
                    if (prs != null)
                    {
                        foreach (var pr in prs)
                        {
                            int peerCount;
                            lock (peersLock) { peerCount = Peers.Count; }
                            if (peerCount >= maxPeers) break;

                            bool exists;
                            lock (peersLock) { exists = Peers.Values.Any(p => p.Address == pr.Address); }
                            if (!exists)
                                ConnectToPeer(pr.Address, new ChatClient(pr.Address, port), port);
                        }
                    }
                }
                else if (message.Type == "GetBlock")
                {
                    var com = JsonConvert.DeserializeObject<GetCommand>(con);
                    if (com != null)
                    {
                        int h = int.Parse(com.Data);
                        int chainCount;
                        lock (chainLock) { chainCount = Chain.Count; }
                        if (h < chainCount)
                        {
                            Block b;
                            lock (chainLock) { b = Chain[h]; }
                            SendBlockMessage(peer, b);
                        }
                    }
                }
                else if (message.Type == "PendingBlock")
                {
                    Block b = JsonConvert.DeserializeObject<Block>(con);
                    if (b != null)
                        AddPendingBlock(b);
                }
                else if (message.Type == "GetPending")
                {
                    var com = JsonConvert.DeserializeObject<GetCommand>(con);
                    if (com != null)
                        SendPendingBlocksMessage(peer, int.Parse(com.Data));
                }
                else if (message.Type == "Pending")
                {
                    Block b = JsonConvert.DeserializeObject<Block>(con);
                    if (b != null)
                        AddPendingBlock(b);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error processing message: {e.Message}");
            }
        }

        public static void ConnectToPeer(string address, ChatClient client, int port)
        {
            try
            {
                // Don't connect to ourselves
                if (address == "127.0.0.1" || address == "localhost" ||
                    address == Server?.Address.ToString())
                {
                    Console.WriteLine("Skipping self-connection");
                    return;
                }

                lock (peersLock)
                {
                    // Check if already connected
                    if (Peers.Values.Any(p => p.Address == address && p.Port == port))
                    {
                        Console.WriteLine($"Already connected to {address}:{port}");
                        return;
                    }

                    // Check max peers
                    if (Peers.Count >= maxPeers)
                    {
                        Console.WriteLine("Max peers reached");
                        return;
                    }

                    Console.WriteLine($"Connecting to peer: {address}:{port}");
                    Peer p = new Peer(client.Id, client, address, port);
                    Peers.Add(client.Id, p);
                }

                // Connect with timeout (outside lock to avoid blocking)
                var connectTask = Task.Run(() => client.Connect());
                if (!connectTask.Wait(TimeSpan.FromSeconds(10)))
                {
                    Console.WriteLine("Connection timeout");
                    lock (peersLock) { Peers.Remove(client.Id); }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error connecting to peer: {e.Message}");
                lock (peersLock)
                {
                    if (Peers.ContainsKey(client.Id))
                        Peers.Remove(client.Id);
                }
            }
        }

        public static void BroadcastNewBlock(Block block)
        {
            List<Peer> peersCopy;
            lock (peersLock) { peersCopy = Peers.Values.ToList(); }

            foreach (var peer in peersCopy)
            {
                var message = new Message("NewBlock", JsonConvert.SerializeObject(block));
                var messageString = JsonConvert.SerializeObject(message);
                try
                {
                    peer.Client.Send(messageString);
                    peer.Client.ReceiveAsync();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error sending message to peer {peer.Address}:{peer.Port} - {e.Message}");
                }
            }
        }

        public static void BroadcastNewPendingBlock(Block block)
        {
            List<Peer> peersCopy;
            lock (peersLock) { peersCopy = Peers.Values.ToList(); }

            foreach (var peer in peersCopy)
            {
                var message = new Message("PendingBlock", JsonConvert.SerializeObject(block));
                var messageString = JsonConvert.SerializeObject(message);
                try
                {
                    peer.Client.Send(messageString);
                    peer.Client.ReceiveAsync();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error sending message to peer {peer.Address}:{peer.Port} - {e.Message}");
                }
            }
        }

        public static void SendGetBlockMessage(GetCommand com)
        {
            Console.WriteLine("Sending GetBlock Message: " + com.Data);
            var message = new Message("GetBlock", JsonConvert.SerializeObject(com));
            try
            {
                var messageString = JsonConvert.SerializeObject(message);
                com.Peer.Client.Send(messageString);
                com.Peer.Client.ReceiveAsync();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error sending message to peer {com.Peer.Address}:{com.Peer.Port} - {e.Message}");
            }
        }

        public static void SendBlockMessage(Peer p, Block b)
        {
            if (p == null)
            {
                Console.WriteLine("SendBlockMessage: Peer is null.");
                return;
            }

            var message = new Message("NewBlock", JsonConvert.SerializeObject(b));
            try
            {
                var messageString = JsonConvert.SerializeObject(message);
                Console.WriteLine("SendBlockMessage to: " + p.ID);
                p.Client.Send(messageString);
                p.Client.ReceiveAsync();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error sending message to peer {p.ID} - {e.Message}");
            }
        }

        public static void SendGetPendingBlocksMessage(GetCommand com)
        {
            var message = new Message("GetPending", JsonConvert.SerializeObject(com));
            try
            {
                var messageString = JsonConvert.SerializeObject(message);
                Peer p = com.Peer;
                if (p != null)
                {
                    Console.WriteLine("SendGetPendingBlocksMessage to: " + com.Peer.ID);
                    p.Client.Send(messageString);
                    p.Client.ReceiveAsync();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error sending message to peer {com.Peer.ID} - {e.Message}");
            }
        }

        public static void SendPendingBlocksMessage(Peer p, int index)
        {
            var blocks = PendingBlocks.Values.ToList();
            if (index > blocks.Count || index < 1)
                return;

            var message = new Message("Pending", JsonConvert.SerializeObject(blocks[index - 1]));
            try
            {
                var messageString = JsonConvert.SerializeObject(message);
                if (p != null)
                {
                    Console.WriteLine("SendPendingBlocksMessage to: " + p.ID);
                    p.Client.Send(messageString);
                    p.Client.ReceiveAsync();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error sending message to peer {p.ID} - {e.Message}");
            }
        }

        public static void BroadcastNewTransaction(Block.Transaction tr)
        {
            List<Peer> peersCopy;
            lock (peersLock) { peersCopy = Peers.Values.ToList(); }

            foreach (var peer in peersCopy)
            {
                var message = new Message("NewTransaction", JsonConvert.SerializeObject(tr));
                var messageString = JsonConvert.SerializeObject(message);
                try
                {
                    peer.Client.Send(messageString);
                    peer.Client.ReceiveAsync();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error sending message to peer {peer.Address}:{peer.Port} - {e.Message}");
                }
            }
        }

        public static void BroadcastNewPeer(Peer pr)
        {
            List<Peer> peersCopy;
            lock (peersLock) { peersCopy = Peers.Values.ToList(); }

            foreach (var peer in peersCopy)
            {
                if (peer == pr)
                    continue;

                var message = new Message("NewPeer", JsonConvert.SerializeObject(pr));
                var messageString = JsonConvert.SerializeObject(message);
                try
                {
                    peer.Client.Send(messageString);
                    peer.Client.ReceiveAsync();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error sending message to peer {peer.Address}:{peer.Port} - {e.Message}");
                }
            }
        }

        public static void BroadcastPeerList(Peer[] pr, Peer peer)
        {
            var message = new Message("Peers", JsonConvert.SerializeObject(pr));
            var messageString = JsonConvert.SerializeObject(message);
            try
            {
                peer.Client.Send(messageString);
                peer.Client.ReceiveAsync();
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error sending message to peer {peer.Address}:{peer.Port} - {e.Message}");
            }
        }

        public static void GetBlock(Peer peer, int index)
        {
            GetCommand com = new GetCommand(peer, "GetBlock", index.ToString());
            SendGetBlockMessage(com);
        }

        public static void GetPending(Peer peer, int index)
        {
            GetCommand com = new GetCommand(peer, "GetPending", index.ToString());
            SendGetPendingBlocksMessage(com);
        }

        #endregion

        public static void MineBlock(string GUID)
        {
            lock (mineLock)
            {
                Console.WriteLine("Mining Block:" + GUID);
                Block block = GetPendingBlock(GUID);

                if (block == null)
                {
                    Console.WriteLine("Block not found: " + GUID);
                    return;
                }

                if (block.BlockDocument?.Publishers == null || block.BlockDocument.Publishers.Count == 0)
                {
                    Console.WriteLine("Invalid block document");
                    return;
                }

                if (GetReputation(block.BlockDocument.Publishers[0]) < 0)
                {
                    Console.WriteLine("Not enough reputation for publishing: " + block.BlockDocument.Publishers[0]);
                    return;
                }

                int revs = GetReviews(GUID);
                int fls = GetFlags(GUID);

                if (revs < reviewers || fls > flags)
                {
                    Console.WriteLine($"Block requirements not met. Reviews: {revs}/{reviewers}, Flags: {fls}/{flags}");
                    return;
                }

                List<Block.Transaction> transactions = new List<Block.Transaction>();
                foreach (var kvp in PendingTransactions)
                {
                    if (VerifyTransaction(kvp.Value))
                        transactions.Add(kvp.Value);
                }

                List<Block> blocksToMine = new List<Block>();
                foreach (var kvp in PendingBlocks)
                {
                    var bl = kvp.Value;
                    int r = GetReviews(bl.GUID);
                    int f = GetFlags(bl.GUID);
                    if (r >= reviewers && f <= flags)
                    {
                        blocksToMine.Add(bl);
                    }
                }

                if (blocksToMine.Count > 0)
                {
                    for (int i = 0; i < blocksToMine.Count; i++)
                    {
                        Block bl = blocksToMine[i];
                        if (i == 0)
                            bl.Transactions = transactions;

                        AddBlock(bl);

                        RSAParameters par = RSA.StringToRSAParameters(block.BlockDocument.PublicKey);
                        Block.Transaction br = new Block.Transaction(Block.Transaction.Type.blockreward, null, par, block.BlockDocument.Publishers[0], miningReward);
                        br.SignTransaction(wallet.PrivateKey);
                        ProcessTransaction(br);

                        Block.Transaction rep = new Block.Transaction(Block.Transaction.Type.addreputation, null, par, block.BlockDocument.Publishers[0], 1);
                        rep.SignTransaction(wallet.PrivateKey);
                        ProcessTransaction(rep);

                        string pendingFile = Path.Combine(dir, "Pending", bl.GUID + ".json");
                        if (File.Exists(pendingFile))
                            File.Delete(pendingFile);

                        Block removed;
                        PendingBlocks.TryRemove(bl.GUID, out removed);

                        BroadcastNewBlock(bl);
                    }

                    // Clear remaining pending
                    PendingBlocks.Clear();
                    PendingTransactions.Clear();

                    string pendingDir = Path.Combine(dir, "PendingTransactions");
                    if (Directory.Exists(pendingDir))
                        Directory.Delete(pendingDir, true);

                    currentSupply += miningReward * blocksToMine.Count;
                }
            }
        }

        public class Wallet
        {
            public RSAParameters PublicKey { get; private set; }
            public RSAParameters PrivateKey { get; private set; }

            public Wallet()
            {
                using (var rsa = new RSACryptoServiceProvider(2048))
                {
                    PublicKey = rsa.ExportParameters(false);
                    PrivateKey = rsa.ExportParameters(true);
                }
            }

            private static void EncryptAndSaveKeys(string publicKey, string privateKey, string password, string filePath)
            {
                byte[] salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                var key = new Rfc2898DeriveBytes(password, salt, 10000);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        fileStream.Write(salt, 0, salt.Length);

                        using (var cryptoStream = new CryptoStream(fileStream, encryptor, CryptoStreamMode.Write))
                        {
                            using (var streamWriter = new StreamWriter(cryptoStream))
                            {
                                streamWriter.WriteLine(publicKey);
                                streamWriter.WriteLine(privateKey);
                            }
                        }
                    }
                }
            }

            public void Save(string password)
            {
                string path = Path.GetDirectoryName(Environment.ProcessPath);
                EncryptAndSaveKeys(RSA.RSAParametersToString(PublicKey),
                    RSA.RSAParametersToStringAll(PrivateKey),
                    password,
                    Path.Combine(path, "wallet.dat"));
            }

            public static void ReadAndDecryptKeys(string password, string filePath, out string publicKey, out string privateKey)
            {
                byte[] salt = new byte[16];

                using (var fileStream = new FileStream(filePath, FileMode.Open))
                {
                    fileStream.Read(salt, 0, salt.Length);

                    var key = new Rfc2898DeriveBytes(password, salt, 10000);

                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = key.GetBytes(aes.KeySize / 8);
                        aes.IV = key.GetBytes(aes.BlockSize / 8);

                        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                        using (var cryptoStream = new CryptoStream(fileStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (var streamReader = new StreamReader(cryptoStream))
                            {
                                publicKey = streamReader.ReadLine();
                                privateKey = streamReader.ReadLine();
                            }
                        }
                    }
                }
            }

            public void Load(string password)
            {
                string path = Path.GetDirectoryName(Environment.ProcessPath);
                string walletPath = Path.Combine(path, "wallet.dat");

                if (!File.Exists(walletPath))
                    return;

                string pub, priv;
                ReadAndDecryptKeys(password, walletPath, out pub, out priv);
                PublicKey = RSA.StringToRSAParametersAll(pub);
                PrivateKey = RSA.StringToRSAParametersAll(priv);
            }
        }

        public static bool IsValid()
        {
            lock (chainLock)
            {
                for (int i = 1; i < Chain.Count; i++)
                {
                    Block currentBlock = Chain[i];
                    Block previousBlock = Chain[i - 1];

                    if (currentBlock.Hash != currentBlock.CalculateHash())
                        return false;

                    if (currentBlock.PreviousHash != previousBlock.Hash)
                        return false;
                }
            }
            return true;
        }

        public static void Save()
        {
            Settings.AddSettings("Height", currentHeight.ToString());
            Settings.Save();

            lock (chainLock)
            {
                if (Chain != null)
                {
                    foreach (var block in Chain)
                    {
                        string f = Path.Combine(dir, "Blocks", block.Index + ".json");
                        if (!File.Exists(f))
                        {
                            File.WriteAllText(f, JsonConvert.SerializeObject(block));
                        }
                    }
                }
            }
        }

        public static void Save(Block block)
        {
            Settings.AddSettings("Height", currentHeight.ToString());
            Settings.Save();
            string f = Path.Combine(dir, "Blocks", block.Index + ".json");
            if (!File.Exists(f))
            {
                File.WriteAllText(f, JsonConvert.SerializeObject(block));
            }
        }

        static bool loaded = false;

        private static void GetBlockThread()
        {
            try
            {
                // Initial block sync
                while (!loaded && !cancellationTokenSource.Token.IsCancellationRequested)
                {
                    int peerCount;
                    lock (peersLock) { peerCount = Peers.Count; }
                    if (peerCount > 0)
                    {
                        Peer firstPeer;
                        lock (peersLock) { firstPeer = Peers.First().Value; }
                        int chainCount;
                        lock (chainLock) { chainCount = Chain.Count; }
                        GetBlock(firstPeer, chainCount);
                    }
                    Thread.Sleep(100);
                }

                // Periodic pending block check
                while (!cancellationTokenSource.Token.IsCancellationRequested)
                {
                    Thread.Sleep(10000);
                    int peerCount;
                    lock (peersLock) { peerCount = Peers.Count; }
                    if (peerCount > 0)
                    {
                        try
                        {
                            Peer firstPeer;
                            lock (peersLock) { firstPeer = Peers.First().Value; }
                            GetPending(firstPeer, PendingBlocks.Count + 1);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"Error getting pending blocks: {e.Message}");
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"GetBlockThread crashed: {e.Message}");
            }
        }

        public static void Load()
        {
            string blocksDir = Path.Combine(dir, "Blocks");
            if (Directory.Exists(blocksDir))
            {
                foreach (var f in Directory.GetFiles(blocksDir))
                {
                    try
                    {
                        var json = File.ReadAllText(f);
                        Block b = JsonConvert.DeserializeObject<Block>(json);
                        if (b != null)
                            AddBlock(b);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error loading block from {f}: {e.Message}");
                    }
                }
            }

            string pendingTransDir = Path.Combine(dir, "PendingTransactions");
            if (Directory.Exists(pendingTransDir))
            {
                foreach (var f in Directory.GetFiles(pendingTransDir))
                {
                    try
                    {
                        var json = File.ReadAllText(f);
                        Block.Transaction t = JsonConvert.DeserializeObject<Block.Transaction>(json);
                        if (t != null && !string.IsNullOrEmpty(t.Signature))
                        {
                            string key = CalculateHash(t.Signature);
                            PendingTransactions.TryAdd(key, t);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error loading transaction from {f}: {e.Message}");
                    }
                }
            }

            string pendingDir = Path.Combine(dir, "Pending");
            Directory.CreateDirectory(pendingDir);
            foreach (var f in Directory.GetFiles(pendingDir))
            {
                try
                {
                    var json = File.ReadAllText(f);
                    Block b = JsonConvert.DeserializeObject<Block>(json);
                    if (b != null)
                        PendingBlocks.TryAdd(b.GUID, b);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error loading pending block from {f}: {e.Message}");
                }
            }

            Thread th = new Thread(GetBlockThread);
            th.IsBackground = true;
            th.Start();
        }

        public static void Shutdown()
        {
            Console.WriteLine("Shutting down blockchain...");
            cancellationTokenSource.Cancel();
            Server?.Stop();
            Save();
        }
    }

    public class ChatSession : TcpSession
    {
        public ChatSession(TcpServer server) : base(server) { }

        protected override void OnConnected()
        {
            Console.WriteLine("Connected: " + this.Socket.RemoteEndPoint);
            string address = ((IPEndPoint)this.Socket.RemoteEndPoint).Address.ToString();
            Blockchain.ConnectToPeer(address, new ChatClient(address, Blockchain.port), Blockchain.port);
        }

        protected override void OnDisconnected()
        {
            Console.WriteLine("Disconnected: " + this.Id);
            lock (typeof(Blockchain))
            {
                if (Blockchain.Peers.ContainsKey(this.Id))
                    Blockchain.Peers.Remove(this.Id);
            }
        }

        protected override void OnReceived(byte[] buffer, long offset, long size)
        {
            string message = Encoding.UTF8.GetString(buffer, (int)offset, (int)size);
            Server.Multicast(message);
        }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Chat TCP session caught an error with code {error}");
        }
    }

    public class ChatServer : TcpServer
    {
        public ChatServer(IPAddress address, int port) : base(address, port) { }

        protected override TcpSession CreateSession()
        {
            return new ChatSession(this);
        }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Chat TCP server caught an error with code {error}");
        }
    }

    public class ChatClient : NetCoreServer.TcpClient
    {
        private bool _stop;

        public ChatClient(string address, int port) : base(address, port) { }

        public void DisconnectAndStop()
        {
            _stop = true;
            DisconnectAsync();
            while (IsConnected)
                Thread.Yield();
        }

        protected override void OnConnected()
        {
            Console.WriteLine($"Chat TCP client connected a new session with Id {Id}");
        }

        protected override void OnDisconnected()
        {
            Console.WriteLine($"Chat TCP client disconnected a session with Id {Id}");

            Thread.Sleep(1000);

            if (!_stop)
                ConnectAsync();
        }

        protected override void OnReceived(byte[] buffer, long offset, long size)
        {
            string s = Encoding.UTF8.GetString(buffer, (int)offset, (int)size);
            List<string> msg = new List<string>();
            msg.AddRange(GetMessage(s));

            foreach (string st in msg)
            {
                try
                {
                    var mes = JsonConvert.DeserializeObject<Blockchain.Message>(st);
                    if (mes != null)
                    {
                        Blockchain.Peer peer = Blockchain.GetPeer(Id);
                        if (peer == null)
                        {
                            Console.WriteLine("Adding Peer:" + Address + " " + Id);
                            Blockchain.ConnectToPeer(Address, this, Port);
                            peer = Blockchain.GetPeer(Id);
                        }
                        if (peer != null)
                            Blockchain.ProcessMessage(mes, peer);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error OnReceived:" + e.Message);
                }
            }
        }

        private string[] GetMessage(string s)
        {
            List<string> messages = new List<string>();
            int start = -1;
            int braceCount = 0;

            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == '{')
                {
                    if (braceCount == 0)
                        start = i;
                    braceCount++;
                }
                else if (s[i] == '}')
                {
                    braceCount--;
                    if (braceCount == 0 && start != -1)
                    {
                        string candidate = s.Substring(start, i - start + 1);
                        try
                        {
                            JsonConvert.DeserializeObject(candidate);
                            messages.Add(candidate);
                        }
                        catch
                        {
                            Console.WriteLine("Invalid JSON message received");
                        }
                        start = -1;
                    }
                }
            }

            return messages.ToArray();
        }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Chat TCP client caught an error with code {error}");
        }
    }

    public static class RSA
    {
        public static string RSAParametersToString(RSAParameters parameters)
        {
            var paramsToSerialize = new
            {
                Modulus = parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                Exponent = parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
            };

            return JsonConvert.SerializeObject(paramsToSerialize);
        }

        public static RSAParameters StringToRSAParameters(string jsonString)
        {
            var paramsFromJson = JsonConvert.DeserializeObject<dynamic>(jsonString);

            return new RSAParameters
            {
                Modulus = paramsFromJson.Modulus != null ? Convert.FromBase64String(paramsFromJson.Modulus.ToString()) : null,
                Exponent = paramsFromJson.Exponent != null ? Convert.FromBase64String(paramsFromJson.Exponent.ToString()) : null,
            };
        }

        public static string RSAParametersToStringAll(RSAParameters parameters)
        {
            var paramsToSerialize = new
            {
                Modulus = parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                Exponent = parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                P = parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                Q = parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                DP = parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                DQ = parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                InverseQ = parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                D = parameters.D != null ? Convert.ToBase64String(parameters.D) : null
            };

            return JsonConvert.SerializeObject(paramsToSerialize);
        }

        public static RSAParameters StringToRSAParametersAll(string jsonString)
        {
            var paramsFromJson = JsonConvert.DeserializeObject<dynamic>(jsonString);

            return new RSAParameters
            {
                Modulus = paramsFromJson.Modulus != null ? Convert.FromBase64String(paramsFromJson.Modulus.ToString()) : null,
                Exponent = paramsFromJson.Exponent != null ? Convert.FromBase64String(paramsFromJson.Exponent.ToString()) : null,
                P = paramsFromJson.P != null ? Convert.FromBase64String(paramsFromJson.P.ToString()) : null,
                Q = paramsFromJson.Q != null ? Convert.FromBase64String(paramsFromJson.Q.ToString()) : null,
                DP = paramsFromJson.DP != null ? Convert.FromBase64String(paramsFromJson.DP.ToString()) : null,
                DQ = paramsFromJson.DQ != null ? Convert.FromBase64String(paramsFromJson.DQ.ToString()) : null,
                InverseQ = paramsFromJson.InverseQ != null ? Convert.FromBase64String(paramsFromJson.InverseQ.ToString()) : null,
                D = paramsFromJson.D != null ? Convert.FromBase64String(paramsFromJson.D.ToString()) : null
            };
        }
    }

    public static class Orcid
    {
        private static readonly string clientId = "APP-PCZPI3V579SL36TV";
        private static readonly string clientSecret = "6d00747a-ae0f-4567-bade-5bfa359bc75a";
        private static readonly HttpClient httpClient = new HttpClient();

        public static async Task<OAuthTokenResponse> GetAccessToken(string authorizationCode)
        {
            var tokenEndpoint = "https://orcid.org/oauth/token";
            var postData = new Dictionary<string, string>
            {
                { "client_id", clientId },
                { "client_secret", clientSecret },
                { "grant_type", "authorization_code" },
                { "redirect_uri", "http://127.0.0.1:8000" },
                { "code", authorizationCode }
            };

            var content = new FormUrlEncodedContent(postData);
            var response = await httpClient.PostAsync(tokenEndpoint, content);
            var responseString = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var tokenResponse = JsonConvert.DeserializeObject<OAuthTokenResponse>(responseString);
                return tokenResponse;
            }

            throw new Exception("Failed to obtain access token.");
        }

        public class OAuthTokenResponse
        {
            [JsonProperty("access_token")]
            public string AccessToken { get; set; }
            [JsonProperty("bearer")]
            public string Bearer { get; set; }
            [JsonProperty("refresh_token")]
            public string RefreshToken { get; set; }
            [JsonProperty("expires_in")]
            public string Expiry { get; set; }
            [JsonProperty("scope")]
            public string Scope { get; set; }
            [JsonProperty("name")]
            public string Name { get; set; }
            [JsonProperty("orcid")]
            public string ORCID { get; set; }
        }

        public static async Task<string> SearchForORCID(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return null;

            var searchEndpoint = "https://pub.orcid.org/v3.0/search/";
            var query = $"q={Uri.EscapeDataString(name)}";
            var requestUri = $"{searchEndpoint}?{query}";

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                var response = await client.GetAsync(requestUri);
                response.EnsureSuccessStatusCode();

                var responseString = await response.Content.ReadAsStringAsync();
                var responseObject = JsonConvert.DeserializeObject<dynamic>(responseString);

                if (responseObject?["result"] == null || responseObject["result"].Count == 0)
                    return null;

                var orcidId = responseObject["result"][0]["orcid-identifier"]["path"];
                return orcidId;
            }
        }

        public static async Task<bool> CheckORCIDExistence(string orcid)
        {
            if (string.IsNullOrEmpty(orcid))
                return false;

            var orcidEndpoint = $"https://pub.orcid.org/v3.0/{orcid}/record";

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                try
                {
                    var response = await client.GetAsync(orcidEndpoint);

                    if (response.IsSuccessStatusCode)
                    {
                        var responseData = await response.Content.ReadAsStringAsync();
                        dynamic responseObject = JsonConvert.DeserializeObject(responseData);
                        return responseObject != null && responseObject["error"] == null;
                    }
                    else
                    {
                        return false;
                    }
                }
                catch
                {
                    return false;
                }
            }
        }
    }

    public static class OAuthHelper
    {
        private static HttpListener httpListener;
        private static string authorizationCode;

        public static async Task<string> StartListenerAsync()
        {
            string redirectUri = "http://127.0.0.1:8000/";
            httpListener = new HttpListener();
            httpListener.Prefixes.Add(redirectUri);
            httpListener.Start();

            string authorizationUrl = $"https://orcid.org/oauth/authorize?client_id=APP-PCZPI3V579SL36TV&response_type=code&scope=/authenticate&redirect_uri=http://127.0.0.1:8000";
            OpenUrl(authorizationUrl);

            var context = await httpListener.GetContextAsync();
            var request = context.Request;

            string responseString = request.QueryString["code"];
            authorizationCode = responseString;

            var response = context.Response;
            string responseHtml = "<html><head><meta http-equiv='Content-Type' content='text/html; charset=utf-8'></head><body>Please return to the application.</body></html>";
            byte[] buffer = Encoding.UTF8.GetBytes(responseHtml);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            await responseOutput.WriteAsync(buffer, 0, buffer.Length);
            responseOutput.Close();
            httpListener.Stop();

            return authorizationCode;
        }

        private static void OpenUrl(string url)
        {
            try
            {
                Process.Start(url);
            }
            catch
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("xdg-open", url);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("open", url);
                }
                else
                {
                    throw;
                }
            }
        }
    }
}
