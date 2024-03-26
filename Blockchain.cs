using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json.Serialization;
using static SciChain.Block;
using System.Net.Sockets;
using JsonIgnoreAttribute = Newtonsoft.Json.JsonIgnoreAttribute;
using NetCoreServer;
using System.Reflection;
using System.Drawing;
using System.Runtime.CompilerServices;
using static SciChain.Blockchain;
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
            public void SignTransaction(RSAParameters privateKey)
            {
                string dataToSign;
                if(FromAddress == null || FromAddress == "")
                    dataToSign = ToAddress + Amount.ToString();
                else
                    dataToSign = FromAddress + ToAddress + Amount.ToString();
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(privateKey);
                    var dataToSignBytes = Encoding.UTF8.GetBytes(dataToSign);
                    var hasher = new SHA256Managed();
                    var hashedData = hasher.ComputeHash(dataToSignBytes);
                    Signature = Convert.ToBase64String(rsa.SignData(hashedData, CryptoConfig.MapNameToOID("SHA256")));
                }
            }
        }
        public int Index { get; set; } // Position of the block on the chain
        public DateTime TimeStamp { get; set; } // When the block was created
        public string PreviousHash { get; set; } // The hash of the previous block
        public IList<Transaction> Transactions { get; set; }
        public string Hash { get; set; } // The block's hash
        public string GUID { get; set; }
        public Document BlockDocument { get; set; }
        public class Document
        {
            public string DOI { get; set; }
            public string PublicKey { get; set; }
            public string Signature { get; set; }
            public IList<string> Publishers { get; set; }
            public Document(string dOI, IList<string> publishers, RSAParameters publicKey)
            {
                DOI = dOI;
                Publishers = publishers;
                PublicKey = RSA.RSAParametersToString(publicKey);
            }
            [Newtonsoft.Json.JsonConstructor]
            public Document(string dOI, IList<string> publishers, string publicKey)
            {
                DOI = dOI;
                Publishers = publishers;
                PublicKey = publicKey;
            }
            public void SignDocument(RSAParameters privateKey, string Address)
            {
                var dataToSign = Address + miningReward.ToString();
                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(privateKey);
                    var dataToSignBytes = Encoding.UTF8.GetBytes(dataToSign);
                    var hasher = new SHA256Managed();
                    var hashedData = hasher.ComputeHash(dataToSignBytes);
                    Signature = Convert.ToBase64String(rsa.SignData(hashedData, CryptoConfig.MapNameToOID("SHA256")));
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
        public static int currentHeight = 0;
        public static List<Transaction> PendingTransactions = new List<Transaction>();
        public static List<Block> PendingBlocks = new List<Block>();
        public static IList<Block> Chain { set; get; }
        //Total supply is calculated to be one coin per person.
        public const decimal totalSupply = 9900000000 + treasury + founder;
        public const decimal treasury = 100000000;
        public const decimal founder = (9900000000 + treasury) * 0.05M;
        public static decimal treasuryBalance = treasury;
        //We will use 10 billion people as our population
        public const long population = 10000000000;
        //With the treasury we can give each user 0.01 coins. But we give only 0.005 so that half of the treasury is left for developement.
        public const decimal gift = 0.005M;
        public static decimal currentSupply = treasury;
        public const decimal miningReward = 10;
        public const int maxPeers = 8;
        public const int port = 8333;
        //For now for testing reviewers will be 1 once released this will be 8 reviewers per block.
        public const int reviewers = 1;
        //For now for testing minimum flags will be 0.
        public const int flags = 0;
        static string dir = System.IO.Path.GetDirectoryName(Environment.ProcessPath);
        public static Dictionary<Guid,Peer> Peers { set; get; } = new Dictionary<Guid, Peer>();
        public static string IP;
        public static ChatServer Server;
        public static void Initialize(Wallet wal)
        {
            wallet = wal;
            Settings.Load();
            string h = Settings.GetSettings("Height");
            if(h!="")
            currentHeight = int.Parse(h);
            Chain = new List<Block>();
            Directory.CreateDirectory(dir + "/Blocks");
            IP = new System.Net.WebClient().DownloadString("https://api.ipify.org");
            Server = new ChatServer(IPAddress.Any, 8333);
            Server.OptionKeepAlive = true;
            bool start = Server.Start();
            Console.WriteLine("Started:" + start);
        }

        public static void AddGenesisBlock(Wallet wallet, string ID)
        {
            if(Chain.Count == 0)
            Chain.Add(CreateGenesisBlock(wallet,ID));
        }

        private static Block CreateGenesisBlock(Wallet wallet, string ID)
        {
            Transaction tr = new Transaction(Transaction.Type.blockreward, null, wallet.PublicKey, ID, founder);
            List<Transaction> trs = new List<Transaction>();
            trs.Add(tr);
            return new Block(DateTime.Now, null, trs);
        }

        public static Block GetLatestBlock()
        {
            if (Chain.Count > 0)
                return Chain[Chain.Count - 1];
            else
                return null;
        }

        public static decimal GetBalance(string address)
        {
            decimal balance = 0;

            foreach (var block in Chain)
            {
                if(block.Transactions!=null)
                foreach (var trans in block.Transactions)
                {
                    if (trans.FromAddress == address)
                    {
                        balance -= trans.Amount;
                    }
                    if (trans.ToAddress == address)
                    {
                        balance += trans.Amount;
                    }
                }
            }

            return balance;
        }

        public static decimal GetReputation(string address)
        {
            decimal balance = 0;

            foreach (var block in Chain)
            {
                if (block.Transactions != null)
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType != Transaction.Type.addreputation || trans.TransactionType != Transaction.Type.removereputation)
                            continue;
                        if (trans.FromAddress == address && trans.TransactionType == Transaction.Type.removereputation)
                        {
                            balance -= trans.Amount;
                        }
                        if (trans.ToAddress == address && trans.TransactionType == Transaction.Type.addreputation)
                        {
                            balance += trans.Amount;
                        }
                    }
            }

            return balance;
        }

        public static decimal GetTreasury()
        {
            decimal balance = treasury;
            foreach (var block in Chain)
            {
                if (block.Transactions != null)
                foreach (var trans in block.Transactions)
                {
                    if (trans.TransactionType != Transaction.Type.registration)
                        continue;
                    balance -= 0.005M;
                }
            }
            return balance;
        }

        public static int GetReviews(string guid)
        {
            int revs = 0;
            foreach (var block in Chain)
            {
                if (block.Transactions != null)
                foreach (var trans in block.Transactions)
                {
                    if (trans.TransactionType != Transaction.Type.review)
                        continue;
                    if (trans.Data == guid.ToString())
                        revs++;
                }
            }
            foreach (var trans in PendingTransactions)
            {
                if (trans.TransactionType != Transaction.Type.review)
                    continue;
                if (trans.Data == guid.ToString())
                    revs++;
            }
            return revs;
        }

        public static Transaction GetTransaction(string address,string type)
        {
            foreach (var block in Chain)
            {
                if (block.Transactions != null)
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType.ToString() != type)
                            continue;
                        if (trans.ToAddress == address && trans.TransactionType.ToString() == type)
                            return trans;
                    }
            }
            return null;
        }
        public static Transaction GetTransaction(string signature)
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
            foreach (var trans in PendingTransactions)
            {
                if (trans.Signature == signature)
                    return trans;
            }
            return null;
        }

        public static int GetFlags(string guid)
        {
            int revs = 0;
            foreach (var block in Chain)
            {
                if (block.Transactions != null)
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType != Transaction.Type.flag)
                            continue;
                        if (trans.Data == guid.ToString())
                            revs++;
                    }
            }
            foreach (var trans in PendingTransactions)
            {
                if (trans.TransactionType != Transaction.Type.flag)
                    continue;
                if (trans.Data == guid.ToString())
                    revs++;
            }
            return revs;
        }
        public static Block GetPendingBlock(string guid)
        {
            foreach (var item in PendingBlocks)
            {
                if (item.GUID == guid)
                    return item;
            }
            return null;
        }

        public static void AddBlock(Block block)
        {
            foreach (var item in Chain)
            {
                if (item.Hash == block.Hash)
                    return;
            }
            Block latestBlock = GetLatestBlock();
            if (latestBlock != null)
            {
                block.Index = latestBlock.Index + 1;
                block.PreviousHash = latestBlock.Hash;
                block.Hash = block.CalculateHash();
                Chain.Add(block);
                Save(block);
            }
        }

        public static void AddTransaction(Transaction transaction)
        {
            PendingTransactions.Add(transaction);
            BroadcastNewTransaction(transaction);
        }

        public static void AddPendingBlock(Block b)
        {
            foreach (var item in PendingBlocks)
            {
                if (item.GUID == b.GUID)
                    return;
            }
            Directory.CreateDirectory(dir + "/Pending");
            File.WriteAllText(dir + "/Pending/" + b.GUID + ".json",JsonConvert.SerializeObject(b));
            PendingBlocks.Add(b);
            BroadcastNewPendingBlock(b);
        }

        public static bool ProcessTransaction(Transaction transaction)
        {
            //If this transaction has already been processed we skip and return false.)
            if (GetTransaction(transaction.Signature) != null)
                return false;
            Console.WriteLine("Processing Transaction:" + transaction.TransactionType);
            if (!VerifyTransaction(transaction))
            {
                Console.WriteLine("Transaction failed: Not a valid transaction.");
                return false;
            }
            if (transaction.TransactionType == Transaction.Type.transaction)
            {
                // Proceed with adding the transaction
                if (transaction.FromAddress != null)
                {
                    var senderBalance = GetBalance(transaction.FromAddress);

                    if (senderBalance < transaction.Amount)
                    {
                        Console.WriteLine("Transaction failed: Not enough balance.");
                        return false;
                    }
                }
                PendingTransactions.Add(transaction);
            }
            else if (transaction.TransactionType == Transaction.Type.registration)
            {
                transaction.Amount = gift;
                //We will register this user and associate their ORCID ID with their public key (RSAParameters) 
                //If this is a new user we will send them the gift transaction from the treasury.
                bool found = false;
                foreach (Block item in Chain)
                {
                    foreach (Transaction t in item.Transactions)
                    {
                        if(t.TransactionType == Transaction.Type.registration && t.ToAddress != transaction.ToAddress)
                        {
                            found = true;
                            break;
                        }
                    }
                    if (found)
                        break;
                }
                if(!found)
                {
                    treasuryBalance -= gift;
                    PendingTransactions.Add(transaction);
                }
            }
            else if (transaction.TransactionType == Transaction.Type.review)
            {
                transaction.Amount = gift;
                PendingTransactions.Add(transaction);
                int revs = GetReviews(transaction.Data);
                int fls = GetFlags(transaction.Data);
                Console.WriteLine("Block: " + transaction.Data + " Reviews: " + revs + " Flags: " + fls);
                if(revs >= reviewers && fls <= flags)
                {
                    MineBlock(transaction.Data);
                }
            }
            else if (transaction.TransactionType == Transaction.Type.flag)
            {
                transaction.Amount = gift;
                PendingTransactions.Add(transaction);
            }
            else if (transaction.TransactionType == Transaction.Type.blockreward)
            {
                transaction.Amount = miningReward; 
                PendingTransactions.Add(transaction);
            }
            else if (transaction.TransactionType == Transaction.Type.addreputation)
            {
                transaction.Amount = 1;
                PendingTransactions.Add(transaction);
            }
            else if (transaction.TransactionType == Transaction.Type.removereputation)
            {
                transaction.Amount = 10;
                PendingTransactions.Add(transaction);
            }
            BroadcastNewTransaction(transaction);
            return true;
        }
        public static bool VerifyTransaction(Transaction transaction)
        {
            if (transaction.TransactionType != Transaction.Type.transaction)
                return true;
            using (var rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    rsa.ImportParameters(RSA.StringToRSAParameters(transaction.PublicKey));
                    var dataToVerify = transaction.FromAddress + transaction.ToAddress + transaction.Amount.ToString();
                    var dataToVerifyBytes = Encoding.UTF8.GetBytes(dataToVerify);
                    var hasher = new SHA256Managed();
                    var hashedData = hasher.ComputeHash(dataToVerifyBytes);
                    return rsa.VerifyData(hashedData, CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(transaction.Signature));
                }
                catch
                {
                    return false;
                }
            }
        }

        #region Server
        
        public static Peer? GetPeer(Guid guid)
        {
            foreach (var item in Peers)
            {
                if (item.Value.Client.Id == guid)
                    return item.Value;
            }
            return null;
        }
        public static Peer? GetPeer(string address)
        {
            foreach (var item in Peers)
            {
                if (item.Value.Address == address)
                    return item.Value;
            }
            return null;
        }

        public class Peer
        {
            [JsonIgnore]
            public ChatClient Client
            {
                get;
                set;
            }
            public string Address { get; set; }
            public Guid ID { get; set; }
            public int Port { get; set; }

            public Peer(Guid guid, ChatClient cli, string address, int port)
            {
                Client = new ChatClient(address, port);
                Address = address;
                Port = port;
                ID = guid;
            }
        }
        public class Node
        {
            public string Address { get; set; } // Could be IP address, domain name, etc.
            public int Port { get; set; }

            // Additional node-specific information (e.g., public key)
        }

        public class Message
        {
            public string Type { get; set; } // E.g., "NewBlock", "NewTransaction", etc.
            public string Content { get; set; } // The actual message content, likely serialized data
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

        public static void ProcessMessage(Message message,Peer peer)
        {
            Console.WriteLine("Processsing message. " + message.Type);
            if(peer == null)
            {
                Console.WriteLine("ProcessMessage:Peer is null");
                return;
            }
            string con = message.Content;
            if (message.Type == "NewBlock")
            {
                var block = JsonConvert.DeserializeObject<Block>(con);
                AddBlock(block);
                Console.WriteLine(message.Type + " " + block.Hash);
            }
            else
            if (message.Type == "NewTransaction")
            {
                var tr = JsonConvert.DeserializeObject<Transaction>(con);
                ProcessTransaction(tr);
                Console.WriteLine(message.Type + " " + tr.FromAddress + " to " + tr.ToAddress + " " + tr.Amount + " " + tr.Signature);
            }
            else
            if(message.Type == "NewPeer")
            {
                var pr = JsonConvert.DeserializeObject<Peer>(con);
                if (Peers.Count < maxPeers)
                {
                    bool ex = false;
                    foreach (var p in Peers)
                    {
                        if (pr.Address == p.Value.Address)
                        {
                            ex = true;
                            break;
                        }
                    }
                    if(!ex)
                        ConnectToPeer(pr.Address, new ChatClient(pr.Address, port), port);
                }
                BroadcastNewPeer(pr);
                Console.WriteLine(message.Type + " " + pr.Address);
            }
            else
            if(message.Type == "Peers")
            {
                var prs = JsonConvert.DeserializeObject<Peer[]>(con);
                foreach (var pr in prs)
                {
                    if (Peers.Count < maxPeers)
                    {
                        bool ex = false;
                        foreach (var p in Peers)
                        {
                            if (pr.Address == p.Value.Address)
                            {
                                ex = true;
                                break;
                            }
                        }
                        if (!ex)
                            ConnectToPeer(pr.Address, new ChatClient(pr.Address, port), port);
                    }
                }
                
                Console.WriteLine(message.Type);
            }
            else
            if(message.Type == "GetBlock")
            {
                var com = JsonConvert.DeserializeObject<GetCommand>(con);
                int h = int.Parse(com.Data);
                if (Chain.Count == 0)
                {
                    AddGenesisBlock(wallet,ID);
                }
                if (h < Chain.Count)
                {
                    Block b = Chain[h];
                    SendBlockMessage(peer,b);
                    Console.WriteLine(message.Type + " " + com.Data);
                }
                else
                {
                    Console.WriteLine("Requested Block is higher than chain height.");
                }
            }
            if(message.Type == "PendingBlock")
            {
                Block b = JsonConvert.DeserializeObject<Block>(message.Content);
                if (b != null)
                    AddPendingBlock(b);
                else
                    Console.WriteLine("Received empty block.");
            }
            else
            if (message.Type == "GetPending")
            {
                var com = JsonConvert.DeserializeObject<GetCommand>(con);
                SendPendingBlocksMessage(peer,int.Parse(com.Data));
            }
            else
            if(message.Type == "Pending")
            {
                Block b = JsonConvert.DeserializeObject<Block>(message.Content);
                AddPendingBlock(b);
            }
            // Handle other message types as necessary
        }

        public static void ConnectToPeer(string address, ChatClient client, int port)
        {
            try
            {
                foreach (var pr in Peers)
                {
                    if (pr.Value.Address == address && pr.Value.Port == port)
                        return;
                }
                Console.WriteLine("Adding peer:" + address + ":" + port);
                Peer p = new Peer(client.Id, client,address, port);
                Peers.Add(client.Id,p);
                p.Client.Connect();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error connecting to peer: " + e.Message);
            }
        }
        public static void BroadcastNewBlock(Block block)
        {
            foreach (var peer in Peers)
            {
                var message = new Message("NewBlock", JsonConvert.SerializeObject(block));
                var messageString = JsonConvert.SerializeObject(message);
                try
                {
                    peer.Value.Client.Send(messageString);
                    peer.Value.Client.ReceiveAsync();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error sending message to peer {peer.Value.Address}:{peer.Value.Port} - {e.Message}");
                    // Handle error (e.g., remove peer from list)
                }
            }
        }
        public static void BroadcastNewPendingBlock(Block block)
        {
            
            foreach (var peer in Peers)
            {
                var message = new Message("PendingBlock", JsonConvert.SerializeObject(block));
            var messageString = JsonConvert.SerializeObject(message);
                try
                {
                    peer.Value.Client.Send(messageString);
                    peer.Value.Client.ReceiveAsync();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error sending message to peer {peer.Value.Address}:{peer.Value.Port} - {e.Message}");
                    // Handle error (e.g., remove peer from list)
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
                // Handle error (e.g., remove peer from list)
            }
        }
        public static void SendBlockMessage(Peer p, Block b)
        {
            if(p == null)
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
                // Handle error (e.g., remove peer from list)
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
                // Handle error (e.g., remove peer from list)
            }
        }
        public static void SendPendingBlocksMessage(Peer p,int index)
        {
            var message = new Message("Pending", JsonConvert.SerializeObject(PendingBlocks[index-1]));
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
                // Handle error (e.g., remove peer from list)
            }
        }
        public static void BroadcastNewTransaction(Transaction tr)
        {
            foreach (var peer in Peers)
            {
                var message = new Message("NewTransaction", JsonConvert.SerializeObject(tr));
                var messageString = JsonConvert.SerializeObject(message);
                try
                {
                    peer.Value.Client.Send(messageString);
                    peer.Value.Client.ReceiveAsync();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error sending message to peer {peer.Value.Address}:{peer.Value.Port} - {e.Message}");
                    // Handle error (e.g., remove peer from list)
                }
            }
        }
        public static void BroadcastNewPeer(Peer pr)
        {
            foreach (var peer in Peers)
            {
                var message = new Message("NewPeer", JsonConvert.SerializeObject(pr));
                var messageString = JsonConvert.SerializeObject(message);
                if (peer.Value == pr)
                    continue;
                try
                {
                    peer.Value.Client.Send(messageString);
                    peer.Value.Client.ReceiveAsync();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error sending message to peer {peer.Value.Address}:{peer.Value.Port} - {e.Message}");
                    // Handle error (e.g., remove peer from list)
                }
            }
        }
        public static void BroadcastPeerList(Peer[] pr,Peer peer)
        {
            var message = new Message("Peers", JsonConvert.SerializeObject(pr));
            var messageString = JsonConvert.SerializeObject(message);
            try
            {
                peer.Client.Send(messageString);
                peer.Client.Receive(Encoding.UTF8.GetBytes(messageString));
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error sending message to peer {peer.Address}:{peer.Port} - {e.Message}");
                // Handle error (e.g., remove peer from list)
            }
        }

        public static void GetBlock(Peer peer, int index)
        {
            GetCommand com = new GetCommand(peer,"GetBlock",index.ToString());
            SendGetBlockMessage(com);
        }
        public static void GetPending(Peer peer, int index)
        {
            GetCommand com = new GetCommand(peer, "GetPending",index.ToString());
            SendGetPendingBlocksMessage(com);
        }
        #endregion

        public static void MineBlock(string GUID)
        {
            Console.WriteLine("Mining Block:" + GUID);
            Block block = GetPendingBlock(GUID);
            if (GetReputation(block.BlockDocument.Publishers[0]) < 0)
            {
                Console.WriteLine("Not enough reputation for publishing: " + block.BlockDocument.Publishers[0]);
            }
            List<Transaction> transactions = new List<Transaction>();
            foreach (var transaction in PendingTransactions)
            {
                if(VerifyTransaction(transaction))
                    transactions.Add(transaction);
            }
            List<Block> blocks = new List<Block>();
            foreach (var bl in PendingBlocks)
            {
                int revs = GetReviews(bl.GUID);
                int fls = GetFlags(bl.GUID);
                if(revs >= reviewers && fls <= flags)
                {
                    blocks.Add(bl);
                }
            }
            if (blocks.Count > 0)
            {
                for (int i = 0; i < blocks.Count; i++)
                {
                    Block bl = blocks[i];
                    if (i == 0)
                        bl.Transactions = transactions;
                    AddBlock(bl);
                    RSAParameters par = RSA.StringToRSAParameters(block.BlockDocument.PublicKey);
                    ProcessTransaction(new Transaction(Transaction.Type.blockreward, null, par, block.BlockDocument.Publishers[0], miningReward));
                    ProcessTransaction(new Transaction(Transaction.Type.addreputation, null, par, block.BlockDocument.Publishers[0], 1));
                    File.Delete(dir + "/Pending/" + bl.GUID + ".json");
                    BroadcastNewBlock(bl);
                }
                PendingBlocks = new List<Block>();
                // Reset the pending transactions
                PendingTransactions = new List<Transaction>();
                currentSupply += miningReward * blocks.Count;
            }
            
        }

        public class Wallet
        {
            public RSAParameters PublicKey { get; private set; }
            public RSAParameters PrivateKey { get; private set; }

            public Wallet()
            {
                using (var rsa = new RSACryptoServiceProvider(2048)) // 2048-bit key size
                {
                    PublicKey = rsa.ExportParameters(false); // Export the public key
                    PrivateKey = rsa.ExportParameters(true); // Export the private key
                }
            }
            private static void EncryptAndSaveKeys(string publicKey, string privateKey, string password, string filePath)
            {
                // Generate a random salt
                byte[] salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                // Derive a key and IV from the password and salt
                var key = new Rfc2898DeriveBytes(password, salt, 10000);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key.GetBytes(aes.KeySize / 8);
                    aes.IV = key.GetBytes(aes.BlockSize / 8);

                    // Create an encryptor to perform the stream transform
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    // Create the streams used for encryption
                    using (var fileStream = new FileStream(filePath, FileMode.Create))
                    {
                        // First write the salt
                        fileStream.Write(salt, 0, salt.Length);

                        using (var cryptoStream = new CryptoStream(fileStream, encryptor, CryptoStreamMode.Write))
                        {
                            using (var streamWriter = new StreamWriter(cryptoStream))
                            {
                                // Write the public and private keys to the stream
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
                EncryptAndSaveKeys(RSA.RSAParametersToString(PublicKey), RSA.RSAParametersToStringAll(PrivateKey), password,path + "/wallet.dat");
            }
            public static void ReadAndDecryptKeys(string password, string filePath, out string publicKey, out string privateKey)
            {
                byte[] salt = new byte[16];

                using (var fileStream = new FileStream(filePath, FileMode.Open))
                {
                    // First read the salt
                    fileStream.Read(salt, 0, salt.Length);

                    // Derive a key and IV from the password and salt
                    var key = new Rfc2898DeriveBytes(password, salt, 10000);

                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = key.GetBytes(aes.KeySize / 8);
                        aes.IV = key.GetBytes(aes.BlockSize / 8);

                        // Create a decryptor to perform the stream transform
                        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                        using (var cryptoStream = new CryptoStream(fileStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (var streamReader = new StreamReader(cryptoStream))
                            {
                                // Read the decrypted public and private keys from the stream
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
                string pub, priv;
                if (!File.Exists(path + "/wallet.dat"))
                    return;
                ReadAndDecryptKeys(password,path + "/wallet.dat",out pub,out priv);
                PublicKey = RSA.StringToRSAParametersAll(pub);
                PrivateKey = RSA.StringToRSAParametersAll(priv);
            }
        }

        public static bool IsValid()
        {
            for (int i = 1; i < Chain.Count; i++)
            {
                Block currentBlock = Chain[i];
                Block previousBlock = Chain[i - 1];

                if (currentBlock.Hash != currentBlock.CalculateHash())
                {
                    return false;
                }

                if (currentBlock.PreviousHash != previousBlock.Hash)
                {
                    return false;
                }
            }
            return true;
        }

        public static void Save()
        {
            Settings.AddSettings("Height",currentHeight.ToString());
            Settings.Save();
            foreach (var block in Chain)
            {
                string f = dir + "/Blocks/" + block.Index + ".json";
                if(!File.Exists(f))
                {
                    File.WriteAllText(f, JsonConvert.SerializeObject(block));
                }
            }
        }
        public static void Save(Block block)
        {
            Settings.AddSettings("Height", currentHeight.ToString());
            Settings.Save();
            string f = dir + "/Blocks/" + block.Index + ".json";
            if (!File.Exists(f))
            {
                File.WriteAllText(f, JsonConvert.SerializeObject(block));
            }
        }
        static bool loaded = false;
        private static void GetBlockThread()
        {
            do
            {
                if (Peers.Count > 0)
                {
                    GetBlock(Peers.First().Value, Chain.Count);
                }
                Thread.Sleep(10000);
                if (Peers.Count > 0)
                {
                    GetPending(Peers.First().Value, Chain.Count);
                }
            } while (true);
        }
        public static void Load()
        {
            foreach (var f in Directory.GetFiles(dir + "/Blocks/"))
            {
                var json = File.ReadAllText(f);
                Block b = JsonConvert.DeserializeObject<Block>(json);
                Chain.Add(b);
            }
            Directory.CreateDirectory(dir + "/Pending");
            foreach (var f in Directory.GetFiles(dir + "/Pending"))
            {
                var json = File.ReadAllText(f);
                Block b = JsonConvert.DeserializeObject<Block>(json);
                PendingBlocks.Add(b);
            }
            Thread th = new Thread(GetBlockThread);
            th.Start();
        }

    }
    public class ChatSession : TcpSession
    {
        public ChatSession(TcpServer server) : base(server) { }

        protected override void OnConnected()
        {
            Console.WriteLine("Connected: " + this.Server.Address);
            Blockchain.ConnectToPeer(this.Server.Address,new ChatClient(this.Server.Address, this.Server.Port),this.Server.Port);
        }

        protected override void OnDisconnected()
        {
            Console.WriteLine("Disconnected: " + this.Server.Address);
            Blockchain.Peers.Remove(this.Id);
        }

        protected override void OnReceived(byte[] buffer, long offset, long size)
        {
            string message = Encoding.UTF8.GetString(buffer, (int)offset, (int)size);
            // Multicast message to all connected sessions
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

        protected override TcpSession CreateSession() { return new ChatSession(this); }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Chat TCP server caught an error with code {error}");
        }
    }

    public class ChatClient : NetCoreServer.TcpClient
    {
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

            // Wait for a while...
            Thread.Sleep(1000);

            // Try to connect again
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
                    Peer peer = GetPeer(Id);
                    if(peer == null)
                    {
                        Console.WriteLine("Adding Peer:" + Address + " " + Id);
                        ConnectToPeer(Address, this, Port);
                        peer = GetPeer(Id);
                    }
                    Blockchain.ProcessMessage(mes,peer);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error OnReceived:" + e.Message);
                }
            }
        }
        private string[] GetMessage(string s)
        {
            List<string> sts = new List<string>();
            string st = "";
            int scope = 0;
            for (int i = 0; i < s.Length; i++)
            {
                st += s[i];
                if (s[i] == '{')
                {
                    scope++;
                }
                else
                if (s[i] == '}')
                {
                    scope--;
                    if (scope == 0)
                    {
                        sts.Add(st);
                        st = "";
                    }
                }
            }
            return sts.ToArray();
        }
        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Chat TCP client caught an error with code {error}");
        }

        private bool _stop;
    }


    public static class RSA
    {
        //Note we only store the public key parts of the RSA Parameters on purpose.
        public static string RSAParametersToString(RSAParameters parameters)
        {
            // RSAParameters contains fields that are byte arrays and cannot be directly serialized by JsonConvert,
            // so we create a serializable object to hold the data.
            var paramsToSerialize = new
            {
                Modulus = parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                Exponent = parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                //P = parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                //Q = parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                //DP = parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                //DQ = parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                //InverseQ = parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                //D = parameters.D != null ? Convert.ToBase64String(parameters.D) : null
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
                //P = paramsFromJson.P != null ? Convert.FromBase64String(paramsFromJson.P.ToString()) : null,
                //Q = paramsFromJson.Q != null ? Convert.FromBase64String(paramsFromJson.Q.ToString()) : null,
                //DP = paramsFromJson.DP != null ? Convert.FromBase64String(paramsFromJson.DP.ToString()) : null,
                //DQ = paramsFromJson.DQ != null ? Convert.FromBase64String(paramsFromJson.DQ.ToString()) : null,
                //InverseQ = paramsFromJson.InverseQ != null ? Convert.FromBase64String(paramsFromJson.InverseQ.ToString()) : null,
                //D = paramsFromJson.D != null ? Convert.FromBase64String(paramsFromJson.D.ToString()) : null
            };
        }
        public static string RSAParametersToStringAll(RSAParameters parameters)
        {
            // RSAParameters contains fields that are byte arrays and cannot be directly serialized by JsonConvert,
            // so we create a serializable object to hold the data.
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
        private static readonly System.Net.Http.HttpClient httpClient = new System.Net.Http.HttpClient();
        public static async Task<OAuthTokenResponse> GetAccessToken(string authorizationCode)
        {
            var httpClient = new System.Net.Http.HttpClient();
            httpClient.BaseAddress = new Uri("https://orcid.org/");
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
                return tokenResponse; // This is the access token you'll use in subsequent requests
            }

            throw new Exception("Failed to obtain access token.");
        }

        // Assume OAuthTokenResponse is a class that matches the JSON structure of ORCID's response
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
            // Include other fields as necessary
        }

        public static async Task<string> SearchForORCID(string name)
        {
            var searchEndpoint = "https://pub.orcid.org/v3.0/search/";
            var query = $"q={Uri.EscapeDataString(name)}";
            var requestUri = $"{searchEndpoint}?{query}";

            using (var httpClient = new System.Net.Http.HttpClient())
            {
                httpClient.DefaultRequestHeaders.Add("Accept", "application/json");

                var response = await httpClient.GetAsync(requestUri);
                response.EnsureSuccessStatusCode();

                var responseString = await response.Content.ReadAsStringAsync();
                var responseObject = JsonConvert.DeserializeObject<dynamic>(responseString);

                // Extract ORCID iD from the response
                var orcidId = responseObject["result"][0]["orcid-identifier"]["path"];

                return orcidId;
            }
        }
        public static async Task<bool> CheckORCIDExistence(string orcid)
        {
            var orcidEndpoint = $"https://pub.orcid.org/v3.0/{orcid}/record";

            using (var httpClient = new System.Net.Http.HttpClient())
            {
                httpClient.DefaultRequestHeaders.Add("Accept", "application/json");

                var response = await httpClient.GetAsync(orcidEndpoint);

                if (response.IsSuccessStatusCode)
                {
                    var responseData = await response.Content.ReadAsStringAsync();
                    dynamic responseObject = JsonConvert.DeserializeObject(responseData);

                    // Check if the response contains a valid ORCID record
                    return responseObject != null && responseObject["error"] == null;
                }
                else
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

            // Open the user's browser and direct them to the authorization URL
            string authorizationUrl = $"https://orcid.org/oauth/authorize?client_id=APP-PCZPI3V579SL36TV&response_type=code&scope=/authenticate&redirect_uri=http://127.0.0.1:8000";
            OpenUrl(authorizationUrl);
            // Wait for the authorization response
            var context = httpListener.GetContext();
            var request = context.Request;

            // Extract the authorization code from the request
            string responseString = request.QueryString["code"];
            authorizationCode = responseString; // This is the authorization code

            // You can now send an HTTP response to the browser to close the window or display a message
            var response = context.Response;
            string responseHtml = "<html><head><meta http-equiv='Content-Type' content='text/html; charset=utf-8'></head><body>Please return to the application.</body></html>";
            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseHtml);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;
            Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
            {
                responseOutput.Close();
                httpListener.Stop();
            });

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
                // hack because of this: https://github.com/dotnet/corefx/issues/10361
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
