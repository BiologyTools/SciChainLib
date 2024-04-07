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
using System.Globalization;
using static System.Runtime.InteropServices.JavaScript.JSType;
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
            /* The above code is defining a constructor for a `Transaction` class in C#. The
            constructor takes in parameters for the transaction type (`Type t`), the sender's
            address (`string fromAddress`), RSA parameters (`RSAParameters par`), the recipient's
            address (`string toAddress`), and the transaction amount (`decimal amount`). Inside the
            constructor, it assigns these values to the corresponding properties of the
            `Transaction` class - `TransactionType`, `FromAddress`, `ToAddress`, `Amount`, and
            `PublicKey`. The `PublicKey` property is set by converting the RSA parameters to a
            string using */
            public Transaction(Type t, string fromAddress, RSAParameters par, string toAddress, decimal amount)
            {
                TransactionType = t;
                FromAddress = fromAddress;
                ToAddress = toAddress;
                Amount = amount;
                PublicKey = RSA.RSAParametersToString(par);
            }
            /// <summary>
            /// The function DecimalToStringWithMaxDecimals converts a decimal value to a string with up
            /// to 28 decimal places.
            /// </summary>
            /// <param name="value">The `DecimalToStringWithMaxDecimals` method takes a `decimal` value
            /// as input and converts it to a string with up to 28 decimal places. The method uses a
            /// specific format string "0.</param>
            /// <returns>
            /// The method `DecimalToStringWithMaxDecimals` returns a string representation of the
            /// decimal value with up to 28 decimal places. It uses the format string "0.
            /// </returns>
            public static string DecimalToStringWithMaxDecimals(decimal value)
            {
                // Using "0.############################" to ensure up to 28 decimal places
                // This format string includes a digit placeholder to the left of the decimal point
                // and up to 28 # characters after the decimal point, which represent optional digits.
                return value.ToString("0.############################");
            }
            /// <summary>
            /// The SignTransaction function signs transaction data using RSA encryption with a private
            /// key.
            /// </summary>
            /// <param name="RSAParameters">RSAParameters is a struct that represents the RSA key
            /// parameters. It contains the components of an RSA key pair, including the modulus,
            /// exponent, and other key-specific values needed for encryption and decryption
            /// operations.</param>
            public void SignTransaction(RSAParameters privateKey)
            {
                string dataToSign;
                if(FromAddress == null || FromAddress == "")
                    dataToSign = ToAddress + DecimalToStringWithMaxDecimals(Amount);
                else
                    dataToSign = FromAddress + ToAddress + DecimalToStringWithMaxDecimals(Amount);
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
        /* The `Document` class in C# represents a document with properties such as DOI, PublicKey,
        Signature, and Publishers, and includes methods for signing the document using RSA
        encryption. */
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


        /* The above code is defining a constructor for a class named `Block` in C#. The constructor
        takes in parameters for a `DateTime` object `timeStamp`, a `string` `previousHash`, and a
        list of `Transaction` objects `transactions`. Inside the constructor, the `Index` is set to
        0, the `TimeStamp`, `PreviousHash`, and `Transactions` properties are assigned the values
        passed in as parameters. The `Hash` property is then calculated using a method
        `CalculateHash()`, and the `GUID` property is set to a new unique identifier generated using
        `Guid */
        public Block(DateTime timeStamp, string previousHash, IList<Transaction> transactions)
        {
            Index = 0;
            TimeStamp = timeStamp;
            PreviousHash = previousHash;
            Transactions = transactions;
            Hash = CalculateHash();
            GUID = Guid.NewGuid().ToString();
        }

       /// <summary>
       /// The CalculateHash function generates a SHA256 hash based on a combination of timestamp,
       /// previous hash, and serialized transactions.
       /// </summary>
       /// <returns>
       /// The method CalculateHash is returning a lowercase hexadecimal string representation of the
       /// SHA-256 hash value calculated from the concatenation of the TimeStamp, PreviousHash (if not
       /// null), and the serialized Transactions in JSON format.
       /// </returns>
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
        public const string treasuryAddress = "a634bc56308e2be97b6f305d8feac8666cc549c0ee127d58a16d8d6e49e86e68";
        public const decimal founder = (9900000000 + treasury) * 0.05M;
        //We will use 10 billion people as our population
        public const long population = 10000000000;
        //With the treasury we can give each user 0.01 coins. But we give only 0.005 so that half of the treasury is left for developement.
        public const decimal gift = 0.005M;
        public static decimal currentSupply = treasury + founder;
        public const decimal miningReward = 10;
        public const int maxPeers = 8;
        public const int port = 8333;
        //For now for testing reviewers will be 1 once released this will be 8 reviewers per block.
        public const int reviewers = 1;
        //For now for testing minimum flags will be 0.
        public const int flags = 0;
        static string dir = System.IO.Path.GetDirectoryName(Environment.ProcessPath);
        public static Dictionary<Guid,Peer> Peers { set; get; } = new Dictionary<Guid, Peer>();
        public static ChatServer Server;
       /// <summary>
       /// The Initialize function initializes a wallet, loads settings, sets current height, creates a
       /// chain list, creates a directory, starts a chat server, and prints a message indicating if the
       /// server started successfully.
       /// </summary>
       /// <param name="Wallet">A wallet object that contains information about a user's cryptocurrency
       /// wallet.</param>
        public static void Initialize(Wallet wal,string id)
        {
            wallet = wal;
            ID = id;
            Settings.Load();
            string h = Settings.GetSettings("Height");
            if(h!="")
            currentHeight = int.Parse(h);
            Chain = new List<Block>();
            Directory.CreateDirectory(dir + "/Blocks");
            try
            {
                Server = new ChatServer(IPAddress.Any, 8333);
                Server.OptionKeepAlive = true;
                bool start = Server.Start();
                Console.WriteLine("Started:" + start);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            
        }

        /// <summary>
        /// The function `AddGenesisBlock` adds a genesis block to the blockchain if the chain is empty.
        /// </summary>
        /// <param name="Wallet">The `Wallet` parameter is an object representing a digital wallet that
        /// stores a user's cryptocurrency holdings and allows them to send and receive transactions on
        /// the blockchain network.</param>
        public static void AddGenesisBlock(Wallet wallet)
        {
            if(Chain.Count == 0)
            AddBlock(CreateGenesisBlock(wallet));
        }

        private static Block CreateGenesisBlock(Wallet wallet)
        {
            Transaction tr = new Transaction(Transaction.Type.blockreward, null, wallet.PublicKey, "0009-0007-0687-6045", founder);
            Transaction tre = new Transaction(Transaction.Type.blockreward, null, wallet.PublicKey, treasuryAddress, treasury);
            List<Transaction> trs = new List<Transaction>();
            trs.Add(tr);
            trs.Add(tre);
            return new Block(DateTime.Now, null, trs);
        }

        /// <summary>
        /// The function GetLatestBlock returns the latest block in a chain if it exists, otherwise it
        /// returns null.
        /// </summary>
        /// <returns>
        /// The GetLatestBlock method returns the latest block in the Chain list. If the Chain list is
        /// not empty, it returns the block at the last index (Chain.Count - 1). If the Chain list is
        /// empty, it returns null.
        /// </returns>
        public static Block GetLatestBlock()
        {
            if (Chain.Count > 0)
                return Chain[Chain.Count - 1];
            else
                return null;
        }

        /// <summary>
        /// The function `GetBalance` calculates the balance of a given address by iterating through
        /// blockchain transactions.
        /// </summary>
        /// <param name="address">The `GetBalance` method takes a `string` parameter `address`, which
        /// represents the address for which you want to retrieve the balance. The method iterates
        /// through the blocks in the `Chain` and calculates the balance for the specified address by
        /// subtracting the amounts sent from that address and adding the</param>
        /// <returns>
        /// The GetBalance method returns the balance of a specific address by iterating through all
        /// transactions in the blockchain and calculating the total amount of funds sent and received
        /// by that address.
        /// </returns>
        public static decimal GetBalance(string address, bool pending = false)
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
            if (pending)
            {
                foreach (var trans in PendingTransactions)
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

        /// <summary>
        /// This C# function calculates the reputation balance for a given address based on transactions
        /// in a blockchain.
        /// </summary>
        /// <param name="address">It looks like you are trying to calculate the reputation balance for a
        /// specific address by iterating through a chain of blocks and transactions. However, there
        /// seems to be a logical issue in your code.</param>
        /// <returns>
        /// The `GetReputation` method is returning the reputation balance for a given address.
        /// </returns>
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

        /// <summary>
        /// This C# function calculates the remaining balance in the treasury after deducting a fee for
        /// each registration transaction in a blockchain.
        /// </summary>
        /// <returns>
        /// The `GetTreasury` method is returning the balance of the treasury after deducting 0.005M for
        /// each registration transaction in the blockchain.
        /// </returns>
        public static decimal GetTreasury()
        {
            return GetBalance(treasuryAddress,true);
        }

        /// <summary>
        /// This C# function iterates through blocks and pending transactions to count the number of
        /// reviews associated with a given GUID.
        /// </summary>
        /// <param name="guid">The `guid` parameter in the `GetReviews` method is a string that
        /// represents a unique identifier for a review. The method iterates through the `Chain` and
        /// `PendingTransactions` to count the number of reviews that match the provided `guid`.</param>
        /// <returns>
        /// The GetReviews method returns the total number of reviews associated with a specific GUID.
        /// </returns>
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

        /// <summary>
        /// The function `GetTransaction` searches for a specific transaction within a chain of blocks
        /// in C#.
        /// </summary>
        /// <param name="Transaction">It looks like you are trying to implement a method that retrieves
        /// a specific transaction from a blockchain. The `GetTransaction` method takes a `Transaction`
        /// object as a parameter and iterates through the blocks in the blockchain to find and return
        /// the matching transaction.</param>
        /// <returns>
        /// The GetTransaction method is returning a Transaction object. If the input Transaction object
        /// `tr` is found within the list of Transactions in the blocks of the Chain, then that specific
        /// Transaction object is returned. If the input Transaction object is not found, then null is
        /// returned.
        /// </returns>
        public static Transaction GetTransaction(Transaction tr, bool searchPending = false)
        {
            foreach (var block in Chain)
            {
                if (block.Transactions != null)
                    foreach (var trans in block.Transactions)
                    {
                        if(tr == trans)
                            return trans;
                    }
            }
            if (searchPending)
            foreach (var t in PendingTransactions)
            {
                if (tr == t)
                    return tr;
            }
            return null;
        }

        public static Transaction GetTransaction(Transaction.Type type, bool searchPending = false)
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
            if (searchPending)
                foreach (var t in PendingTransactions)
                {
                    if (t.TransactionType == type)
                        return t;
                }
            return null;
        }

        public static bool IsGenesis(Block b)
        {
            foreach (var block in Chain)
            {
                if (block.Transactions != null)
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType == Transaction.Type.blockreward && trans.Amount > miningReward)
                            return true;
                    }
            }
            return false;
        }

        public static Transaction GetTransactionByData(string data,bool searchPending = false)
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
            if (searchPending)
            foreach (var tr in PendingTransactions)
            {
                if (tr.Data == data)
                    return tr;
            }
            return null;
        }

        public static bool VerifyBlock(Block bl)
        {
            foreach (var block in Chain)
            {
                if (block.Transactions != null)
                    foreach (var trans in block.Transactions)
                    {
                        if (trans.TransactionType == Transaction.Type.blockreward && trans.Amount > miningReward)
                            return false;
                    }
            }

            return true;
        }

        /// <summary>
        /// The GetTransaction function searches for a transaction with a specific signature in the
        /// blockchain and pending transactions.
        /// </summary>
        /// <param name="signature">The `signature` parameter is a string that represents the unique
        /// identifier of a transaction. The `GetTransaction` method searches for a transaction with a
        /// matching signature within the blockchain and, optionally, within the pending transactions if
        /// the `searchPending` parameter is set to true.</param>
        /// <param name="searchPending">The `searchPending` parameter in the `GetTransaction` method is
        /// a boolean parameter that specifies whether to search for the transaction in the pending
        /// transactions list if it is not found in the blockchain. If `searchPending` is set to `true`,
        /// the method will also search through the `PendingTransactions</param>
        /// <returns>
        /// The GetTransaction method returns a Transaction object with the specified signature if it is
        /// found in the blockchain or pending transactions. If the transaction with the specified
        /// signature is not found and the searchPending parameter is set to true, it will return the
        /// transaction from the pending transactions. If no matching transaction is found, it will
        /// return null.
        /// </returns>
        public static Transaction GetTransaction(string signature,bool searchPending = false)
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
            if(searchPending)
            foreach (var trans in PendingTransactions)
            {
                if (trans.Signature == signature)
                    return trans;
            }
            return null;
        }

        /// <summary>
        /// This C# function iterates through blocks and pending transactions to count the occurrences
        /// of a specific GUID in flag transactions.
        /// </summary>
        /// <param name="guid">The `guid` parameter in the `GetFlags` method is a string that represents
        /// a unique identifier. The method iterates through blocks in a chain and pending transactions
        /// to count the number of transactions with a type of `flag` and data matching the provided
        /// `guid`.</param>
        /// <returns>
        /// The GetFlags method returns the total number of flag transactions that match the provided
        /// GUID in both the Chain and PendingTransactions lists.
        /// </returns>
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
        /// <summary>
       /// The function `GetPendingBlock` retrieves a pending block based on a given GUID.
       /// </summary>
       /// <param name="guid">The `guid` parameter in the `GetPendingBlock` method is a unique
       /// identifier used to search for a specific block in the `PendingBlocks` collection. The method
       /// iterates through the `PendingBlocks` collection and returns the block that matches the
       /// provided `guid`. If no matching block is found</param>
       /// <returns>
       /// The GetPendingBlock method is returning a Block object with the specified GUID if it exists
       /// in the PendingBlocks collection. If no matching Block is found, it will return null.
       /// </returns>
        public static Block GetPendingBlock(string guid)
        {
            foreach (var item in PendingBlocks)
            {
                if (item.GUID == guid)
                    return item;
            }
            return null;
        }
        /// <summary>
        /// The function CalculateHash takes a string input, computes its SHA-256 hash value, and
        /// returns the hash as a lowercase hexadecimal string.
        /// </summary>
        /// <param name="st">The `CalculateHash` method takes a string `st` as input and calculates the
        /// SHA-256 hash of that string. The hash is then returned as a lowercase hexadecimal string
        /// representation without any dashes.</param>
        /// <returns>
        /// The CalculateHash method returns a lowercase hexadecimal string representation of the
        /// SHA-256 hash of the input string.
        /// </returns>
        public static string CalculateHash(string st)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(st));
                return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
            }
        }
        /// <summary>
        /// The function `AddBlock` adds a new block to a blockchain, ensuring that it is not a
        /// duplicate, updating the block index and hash, and saving it to the chain.
        /// </summary>
        /// <param name="Block">A block is a data structure that contains information about
        /// transactions, such as sender, receiver, amount, timestamp, and a hash of the previous block.
        /// It is used in blockchain technology to store data securely and immutably.</param>
        /// <returns>
        /// If the condition `item.Hash == block.Hash` is met in the `foreach` loop, the method will
        /// return early and exit the loop. Otherwise, if the loop completes without finding a matching
        /// hash, nothing will be returned explicitly.
        /// </returns>
        public static void AddBlock(Block block)
        {
            if (!VerifyBlock(block))
                return;
            foreach (var item in Chain)
            {
                if (item.Hash == block.Hash)
                    return;
            }
            for (var i = 0; i < PendingTransactions.Count; i++)
            {
                if (block.Transactions.Contains(PendingTransactions[i]))
                {
                    string g = CalculateHash(PendingTransactions[i].Signature) + ".json";
                    if(File.Exists(g))
                    File.Delete(g);
                    PendingTransactions.RemoveAt(i);
                }
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
            else
            {
                block.Index = 0;
                block.Hash = block.CalculateHash();
                Chain.Add(block);
                Save(block);
            }
        }

        /// <summary>
        /// The AddTransaction function broadcasts a new transaction.
        /// </summary>
        /// <param name="Transaction">The `AddTransaction` method is a static method that takes a
        /// `Transaction` object as a parameter. Inside the method, it calls the
        /// `BroadcastNewTransaction` method with the `Transaction` object passed as an
        /// argument.</param>
        public static void AddTransaction(Transaction transaction)
        {
            BroadcastNewTransaction(transaction);
        }

        /// <summary>
        /// The function `AddPendingBlock` checks if a block is already in the pending blocks list,
        /// creates a directory if it doesn't exist, writes the block to a JSON file, adds the block to
        /// the pending blocks list, and broadcasts the new pending block.
        /// </summary>
        /// <param name="Block">A data structure representing a block in a blockchain, typically
        /// containing information such as a unique identifier (GUID) and other relevant data.</param>
        /// <returns>
        /// If a block with the same GUID as the input block `b` is found in the `PendingBlocks`
        /// collection, the method will return without performing any further actions.
        /// </returns>
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
        /// <summary>
        /// The function `SavePendingTransaction` saves a transaction to a directory as a JSON file.
        /// </summary>
        /// <param name="Transaction">The `Transaction` parameter in the `SavePendingTransaction` method
        /// represents a transaction object that contains information about a financial transaction,
        /// such as the sender, receiver, amount, timestamp, and signature. This method is responsible
        /// for saving pending transactions to a specific directory in JSON format.</param>
        private static void SavePendingTransaction(Transaction transaction)
        {
            Directory.CreateDirectory(dir + "/PendingTransactions");
            PendingTransactions.Add(transaction);
            File.WriteAllText(dir + "/PendingTransactions/" + CalculateHash(transaction.Signature) + ".json",JsonConvert.SerializeObject(transaction));
        }
        /// <summary>
        /// The function `ProcessTransaction` processes different types of transactions based on their
        /// transaction type and performs various checks and actions accordingly.
        /// </summary>
        /// <param name="Transaction">It looks like the code you provided is a method called
        /// `ProcessTransaction` that processes different types of transactions based on their
        /// `TransactionType`. The method checks if a transaction has already been processed, verifies
        /// the transaction, and then performs specific actions based on the type of
        /// transaction.</param>
        /// <returns>
        /// The method `ProcessTransaction` returns a boolean value, either `true` or `false`, depending
        /// on the outcome of processing the transaction.
        /// </returns>
        public static async Task<bool> ProcessTransaction(Transaction transaction)
        {
            //If this transaction has already been processed we skip and return false.)
            if(transaction.Signature != null)
            if (GetTransaction(transaction) != null)
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
                SavePendingTransaction(transaction);
                return true;
            }
            //If the sender is an anonymous user we return here since anonymous users should not be able to perform any other actions.
            if(!await Orcid.CheckORCIDExistence(transaction.FromAddress))
            {
                return false;
            }
            if (transaction.TransactionType == Transaction.Type.registration)
            {
                transaction.Amount = gift;
                transaction.FromAddress = treasuryAddress;
                //We will register this user and associate their ORCID ID with their public key (RSAParameters) 
                //If this is a new user we will send them the gift transaction from the treasury.
                bool found = false;
                foreach (Block item in Chain)
                {
                    if(item.Transactions!=null && item.Transactions.Count > 0)
                    foreach (Transaction t in item.Transactions)
                    {
                        if(t.TransactionType == Transaction.Type.registration && t.ToAddress == transaction.ToAddress)
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
                    SavePendingTransaction(transaction);
                }
            }
            else if (transaction.TransactionType == Transaction.Type.review)
            {
                transaction.Amount = gift;
                int revs = GetReviews(transaction.Data);
                int fls = GetFlags(transaction.Data);
                Console.WriteLine("Block: " + transaction.Data + " Reviews: " + revs + " Flags: " + fls);
                SavePendingTransaction(transaction);
                if(revs >= reviewers && fls <= flags)
                {
                    MineBlock(transaction.Data);
                }
            }
            else if (transaction.TransactionType == Transaction.Type.flag)
            {
                transaction.Amount = gift;
                SavePendingTransaction(transaction);
            }
            else if (transaction.TransactionType == Transaction.Type.blockreward)
            {
                transaction.Amount = miningReward;
                SavePendingTransaction(transaction);
            }
            else if (transaction.TransactionType == Transaction.Type.addreputation)
            {
                transaction.Amount = 1;
                SavePendingTransaction(transaction);
            }
            else if (transaction.TransactionType == Transaction.Type.removereputation)
            {
                transaction.Amount = 10;
                SavePendingTransaction(transaction);
            }
            return true;
        }
        /// <summary>
        /// The function `VerifyTransaction` uses RSA encryption to verify the integrity of a
        /// transaction by comparing the hashed data with the provided signature.
        /// </summary>
        /// <param name="Transaction">The `VerifyTransaction` method is used to verify the authenticity
        /// of a transaction by checking its signature against the provided public key.</param>
        /// <returns>
        /// The method `VerifyTransaction` returns a boolean value. It returns `true` if the
        /// verification of the transaction signature using RSA is successful, and `false` if there is
        /// an exception during the verification process or if the verification fails.
        /// </returns>
        public static bool VerifyTransaction(Transaction transaction)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    rsa.ImportParameters(RSA.StringToRSAParameters(transaction.PublicKey));
                    string dataToVerify;
                    if(transaction.FromAddress == null || transaction.FromAddress == "")
                        dataToVerify = transaction.ToAddress + Transaction.DecimalToStringWithMaxDecimals(transaction.Amount);
                    else
                        dataToVerify = transaction.FromAddress + transaction.ToAddress + Transaction.DecimalToStringWithMaxDecimals(transaction.Amount);
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
                if (item.Value.ID == guid || item.Value.Client.Id == guid)
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
        /// <summary>
        /// The ProcessMessage function in C# processes different types of messages received from peers
        /// in a blockchain network.
        /// </summary>
        /// <param name="Message">The `ProcessMessage` method you provided is responsible for handling
        /// different types of messages received from a peer in a peer-to-peer network. The `Message`
        /// parameter represents the message being processed, and the `Peer` parameter represents the
        /// peer from which the message was received.</param>
        /// <param name="Peer">A `Peer` represents another node in a peer-to-peer network. In this
        /// context, it seems to be an entity that can communicate with the current node and exchange
        /// messages. The `Peer` object likely contains information such as the address of the peer node
        /// and possibly other relevant details for establishing connections and</param>
        /// <returns>
        /// The method `ProcessMessage` returns void, as indicated by the `void` keyword in its
        /// signature.
        /// </returns>
        public static void ProcessMessage(Message message,Peer peer)
        {
            Console.WriteLine("Processsing message. " + message.Type + " Balance:" + GetBalance(ID,true));
            if(peer == null)
            {
                Console.WriteLine("ProcessMessage: Peer is null");
                return;
            }
            string con = message.Content;
            if (message.Type == "NewBlock")
            {
                var block = JsonConvert.DeserializeObject<Block>(con);
                if (block == null)
                    loaded = true;
                if (block.Index != Chain.Last().Index)
                {
                    AddBlock(block);
                    Console.WriteLine(message.Type + " " + block.Hash);
                }
                else
                    loaded = true;
            }
            else
            if (message.Type == "NewTransaction")
            {
                var tr = JsonConvert.DeserializeObject<Transaction>(con);
                ProcessTransaction(tr);
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
                    AddGenesisBlock(wallet);
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
                    loaded = true;
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

        /// <summary>
        /// The ConnectToPeer function connects a chat client to a peer at a specified address and port,
        /// handling exceptions and adding the peer to a list of connected peers.
        /// </summary>
        /// <param name="address">The `address` parameter in the `ConnectToPeer` method is a string that
        /// represents the network address of the peer you want to connect to. This could be an IP
        /// address or a domain name.</param>
        /// <param name="ChatClient">A ChatClient object represents a client in a chat application. It
        /// likely contains information about the client, such as an ID, and methods for connecting to
        /// other clients or sending messages.</param>
        /// <param name="port">The `port` parameter in the `ConnectToPeer` method is an integer value
        /// that represents the port number to which the connection will be established with the peer
        /// identified by the `address`. It is used to specify the specific communication endpoint on
        /// the network where the connection will be made.</param>
        /// <returns>
        /// If a peer with the specified address and port already exists in the list of peers, the
        /// method will return without adding a new peer.
        /// </returns>
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
        /// <summary>
        /// The function `BroadcastNewBlock` sends a new block message to all connected peers in a C#
        /// application.
        /// </summary>
        /// <param name="Block">A data structure representing a block in a blockchain, typically
        /// containing information such as the block's index, timestamp, data, previous hash, and
        /// hash.</param>
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
        /// <summary>
        /// The function `BroadcastNewPendingBlock` sends a message containing a new pending block to
        /// all connected peers.
        /// </summary>
        /// <param name="Block">A data structure representing a block in a blockchain, typically
        /// containing information such as block number, timestamp, previous block hash, transactions,
        /// and a nonce.</param>
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
        /// <summary>
       /// The function `SendGetBlockMessage` sends a GetBlock message to a peer using JSON
       /// serialization.
       /// </summary>
       /// <param name="GetCommand">GetCommand is a class that represents a command to get a block. It
       /// likely contains information such as the data of the block being requested and the peer to
       /// which the request should be sent.</param>
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
        /// <summary>
        /// The function `SendBlockMessage` sends a new block message to a peer using JSON
        /// serialization.
        /// </summary>
        /// <param name="Peer">A `Peer` represents a network peer that the current node is connected to.
        /// It typically contains information such as the peer's ID, IP address, and a client for
        /// sending and receiving messages over the network.</param>
        /// <param name="Block">A block is a data structure used in blockchain technology to store a
        /// collection of transactions. It contains information such as the block number, timestamp, a
        /// reference to the previous block, a list of transactions, and a nonce value used in the
        /// mining process.</param>
        /// <returns>
        /// If the `Peer p` parameter is null, the method will return early after printing
        /// "SendBlockMessage: Peer is null." to the console.
        /// </returns>
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
        /// <summary>
        /// The function `SendGetPendingBlocksMessage` sends a message to a peer to request pending
        /// blocks using JSON serialization.
        /// </summary>
        /// <param name="GetCommand">The `GetCommand` class seems to be a custom class used in your
        /// code. It likely contains information related to a command to get pending blocks. It seems to
        /// have a property `Peer` of type `Peer` which probably represents a network peer to which the
        /// message will be sent.</param>
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
        /// <summary>
        /// The function `SendPendingBlocksMessage` sends a message containing a pending block to a
        /// specified peer.
        /// </summary>
        /// <param name="Peer">Peer is a class representing a network peer in a peer-to-peer system. It
        /// likely contains information about the peer such as its ID, client connection, and other
        /// relevant data for communication.</param>
        /// <param name="index">The `index` parameter in the `SendPendingBlocksMessage` method
        /// represents the position of the pending block in the `PendingBlocks` list that you want to
        /// send a message about. It is used to access the specific pending block in the list for
        /// processing and sending the message.</param>
        /// <returns>
        /// If the `index` parameter is greater than the count of `PendingBlocks`, the method will
        /// return early without sending any message.
        /// </returns>
        public static void SendPendingBlocksMessage(Peer p,int index)
        {
            if (index > PendingBlocks.Count)
                return;
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
        /// <summary>
        /// The function `BroadcastNewTransaction` sends a new transaction to all connected peers in a
        /// C# application.
        /// </summary>
        /// <param name="Transaction">A transaction object that contains information about a financial
        /// transaction, such as sender, receiver, amount, timestamp, etc.</param>
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
        /// <summary>
        /// The function `BroadcastNewPeer` sends a message to all peers in a list, excluding the new
        /// peer being added, in a C# program.
        /// </summary>
        /// <param name="Peer">Peer is a class representing a network peer, containing properties such
        /// as Address, Port, and Client.</param>
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
        /// <summary>
        /// The function BroadcastPeerList sends a list of peers to a specific peer using JSON
        /// serialization.
        /// </summary>
        /// <param name="pr">an array of Peer objects representing a list of peers to broadcast
        /// to.</param>
        /// <param name="Peer">A Peer object representing a single peer in a network. It typically
        /// contains information such as the peer's address, port, and client connection.</param>
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

        /// <summary>
        /// The GetBlock function sends a GetBlock message to a peer with a specified index.
        /// </summary>
        /// <param name="Peer">Peer represents a network node or participant in a peer-to-peer network.
        /// It typically contains information about the network address, such as IP and port, of the
        /// peer with which communication is being established.</param>
        /// <param name="index">The `index` parameter is an integer value that represents the index of
        /// the block that you want to retrieve from a peer in a blockchain network.</param>
        public static void GetBlock(Peer peer, int index)
        {
            GetCommand com = new GetCommand(peer,"GetBlock",index.ToString());
            SendGetBlockMessage(com);
        }
        /// <summary>
        /// The GetPending function creates a GetCommand object with a specified index and sends a
        /// message to request pending blocks from a peer.
        /// </summary>
        /// <param name="Peer">A class representing a network peer that the code is interacting
        /// with.</param>
        /// <param name="index">The `index` parameter is an integer value that represents the index of
        /// the pending block to retrieve.</param>
        public static void GetPending(Peer peer, int index)
        {
            GetCommand com = new GetCommand(peer, "GetPending",index.ToString());
            SendGetPendingBlocksMessage(com);
        }
        #endregion

        /// <summary>
        /// The function `MineBlock` mines a block by processing pending transactions, verifying blocks,
        /// adding rewards, and updating the blockchain.
        /// </summary>
        /// <param name="GUID">The `GUID` parameter in the `MineBlock` method is a unique identifier for
        /// the block that is being mined. It is used to retrieve the pending block to be mined and
        /// perform various operations related to mining, such as verifying transactions, adding
        /// transactions to the block, processing transactions, rewarding miners,</param>
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
                    Transaction br = new Transaction(Transaction.Type.blockreward, null, par, block.BlockDocument.Publishers[0], miningReward);
                    br.SignTransaction(wallet.PrivateKey);
                    ProcessTransaction(br);
                    Transaction rep = new Transaction(Transaction.Type.addreputation, null, par, block.BlockDocument.Publishers[0], 1);
                    rep.SignTransaction(wallet.PrivateKey);
                    ProcessTransaction(rep);
                    File.Delete(dir + "/Pending/" + bl.GUID + ".json");
                    BroadcastNewBlock(bl);
                }
                PendingBlocks = new List<Block>();
                // Reset the pending transactions
                PendingTransactions = new List<Transaction>();
                Directory.Delete(dir + "/PendingTransactions");
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
            /// <summary>
            /// The function `EncryptAndSaveKeys` generates a random salt, derives a key and IV from a
            /// password and salt, encrypts and saves public and private keys to a file using AES
            /// encryption.
            /// </summary>
            /// <param name="publicKey">The `publicKey` parameter in the `EncryptAndSaveKeys` method is
            /// a string that represents the public key that you want to encrypt and save to a file.
            /// This key is typically used for encryption or verifying signatures in asymmetric
            /// cryptography.</param>
            /// <param name="privateKey">The `privateKey` parameter in the `EncryptAndSaveKeys` method
            /// is a string that represents the private key that you want to encrypt and save to a file.
            /// This private key is typically used in asymmetric cryptography for signing or decrypting
            /// data. It is important to keep the private key secure and</param>
            /// <param name="password">The `password` parameter in the `EncryptAndSaveKeys` method is
            /// used to derive a key and IV (Initialization Vector) for encrypting the public and
            /// private keys before saving them to a file. The password is used in conjunction with a
            /// randomly generated salt to create a secure encryption key using the</param>
            /// <param name="filePath">The `filePath` parameter in the `EncryptAndSaveKeys` method is
            /// the path to the file where the encrypted keys will be saved. This parameter should
            /// specify the location and name of the file where the keys will be stored after
            /// encryption. Make sure to provide the full path including the file name and</param>
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
            /// <summary>
            /// The Save function encrypts and saves RSA key parameters to a file using a provided
            /// password.
            /// </summary>
            /// <param name="password">The `password` parameter is a string that is passed to the `Save`
            /// method. It is used as a parameter for encrypting and saving keys in the
            /// `EncryptAndSaveKeys` method.</param>
            public void Save(string password)
            {
                string path = Path.GetDirectoryName(Environment.ProcessPath);
                EncryptAndSaveKeys(RSA.RSAParametersToString(PublicKey), RSA.RSAParametersToStringAll(PrivateKey), password,path + "/wallet.dat");
            }
            /// <summary>
            /// The function `ReadAndDecryptKeys` reads and decrypts public and private keys from a file
            /// using a password and salt.
            /// </summary>
            /// <param name="password">The `password` parameter is the password used to derive the key
            /// and IV for decrypting the keys stored in the file.</param>
            /// <param name="filePath">The `filePath` parameter in the `ReadAndDecryptKeys` method is
            /// the path to the file from which the public and private keys will be read and decrypted.
            /// It should be a string representing the location of the file on the file system.</param>
            /// <param name="publicKey">The `publicKey` parameter in the `ReadAndDecryptKeys` method is
            /// used to store the decrypted public key read from the specified file after decrypting it
            /// using the provided password and salt.</param>
            /// <param name="privateKey">The `privateKey` parameter in the `ReadAndDecryptKeys` method
            /// is an output parameter that will store the decrypted private key read from the specified
            /// file after decrypting it using the provided password.</param>
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
            /// <summary>
            /// The Load function reads and decrypts keys from a wallet file using a provided password
            /// in C#.
            /// </summary>
            /// <param name="password">The `password` parameter is a string that represents the password
            /// needed to decrypt the keys stored in the wallet file.</param>
            /// <returns>
            /// If the file "wallet.dat" does not exist at the specified path, the method will return
            /// without performing any further actions.
            /// </returns>
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

        /// <summary>
        /// The function `IsValid` checks the validity of a blockchain by verifying the hashes and
        /// previous hash links between blocks.
        /// </summary>
        /// <returns>
        /// The `IsValid` method is checking the validity of a blockchain by iterating through the
        /// blocks in the chain. It returns a boolean value - `true` if the blockchain is valid, and
        /// `false` if any block's hash does not match the calculated hash or if the previous hash of a
        /// block does not match the hash of the previous block.
        /// </returns>
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

        /// <summary>
        /// The Save function saves settings and blockchain blocks to files in JSON format.
        /// </summary>
        public static void Save()
        {
            Settings.AddSettings("Height",currentHeight.ToString());
            Settings.Save();
            if(Chain != null)
            foreach (var block in Chain)
            {
                string f = dir + "/Blocks/" + block.Index + ".json";
                if(!File.Exists(f))
                {
                    File.WriteAllText(f, JsonConvert.SerializeObject(block));
                }
            }
        }
        /// <summary>
        /// The function `Save` saves a `Block` object to a JSON file and updates the current height
        /// setting.
        /// </summary>
        /// <param name="Block">A block object that contains data to be saved.</param>
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
        /// <summary>
        /// The function `GetBlockThread` continuously retrieves blocks and pending transactions from
        /// peers until a certain condition is met.
        /// </summary>
        private static void GetBlockThread()
        {
            do
            {
                if (Peers.Count > 0)
                {
                    GetBlock(Peers.First().Value, Chain.Count);
                }
                Thread.Sleep(100);
            } while (!loaded);
            do
            {
                Thread.Sleep(10000);
                if (Peers.Count > 0)
                {
                    GetPending(Peers.First().Value, Chain.Count);
                }
            } while (true);
        }
        /// <summary>
        /// The Load function reads and deserializes JSON files for blocks and transactions, adds them
        /// to corresponding lists, creates a directory for pending blocks, and starts a new thread for
        /// block retrieval.
        /// </summary>
        public static void Load()
        {
            foreach (var f in Directory.GetFiles(dir + "/Blocks/"))
            {
                var json = File.ReadAllText(f);
                Block b = JsonConvert.DeserializeObject<Block>(json);
                AddBlock(b);
            }
            if(Directory.Exists(dir + "/PendingTransactions/"))
            foreach (var f in Directory.GetFiles(dir + "/PendingTransactions/"))
            {
                var json = File.ReadAllText(f);
                Transaction t = JsonConvert.DeserializeObject<Transaction>(json);
                PendingTransactions.Add(t);
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
   /* The ChatSession class extends TcpSession and handles connection, disconnection, message
   receiving, and error handling for a chat server. */
    public class ChatSession : TcpSession
    {
        public ChatSession(TcpServer server) : base(server) { }

        /// <summary>
        /// The OnConnected method in C# prints a message indicating a successful connection and then
        /// connects to a peer using the Blockchain class and a ChatClient object.
        /// </summary>
        protected override void OnConnected()
        {
            Console.WriteLine("Connected: " + this.Server.Address);
            Blockchain.ConnectToPeer(this.Server.Address,new ChatClient(this.Server.Address, this.Server.Port),this.Server.Port);
        }

        /// <summary>
        /// The OnDisconnected function in C# prints a message indicating disconnection and removes the
        /// peer from the Blockchain.
        /// </summary>
        protected override void OnDisconnected()
        {
            Console.WriteLine("Disconnected: " + this.Server.Address);
            Blockchain.Peers.Remove(this.Id);
        }

       /// <summary>
       /// This function receives a byte array, converts it to a UTF-8 string, and then multicasts the
       /// message to all connected sessions in a server.
       /// </summary>
       /// <param name="buffer">The `buffer` parameter is an array of bytes that contains the data
       /// received by the server.</param>
       /// <param name="offset">The `offset` parameter in the `OnReceived` method represents the
       /// starting position in the `buffer` array from which the data should be read. It is of type
       /// `long` and indicates the index in the buffer where the data starts.</param>
       /// <param name="size">The `size` parameter in the `OnReceived` method represents the size of the
       /// data received in bytes. It indicates the length of the data stored in the `buffer` starting
       /// from the `offset` position.</param>
        protected override void OnReceived(byte[] buffer, long offset, long size)
        {
            string message = Encoding.UTF8.GetString(buffer, (int)offset, (int)size);
            // Multicast message to all connected sessions
            Server.Multicast(message);
        }

        /// <summary>
        /// The `OnError` function in C# is used to handle and display errors that occur in a chat TCP
        /// session.
        /// </summary>
        /// <param name="SocketError">The `SocketError` parameter in the `OnError` method represents an
        /// enumeration of socket error codes that can occur during socket operations. It provides
        /// information about the specific error that occurred, such as connection failures, timeouts,
        /// or other socket-related issues.</param>
        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Chat TCP session caught an error with code {error}");
        }
    }

    /* The ChatServer class extends TcpServer and handles errors in a chat TCP server. */
    public class ChatServer : TcpServer
    {
        public ChatServer(IPAddress address, int port) : base(address, port) { }

        protected override TcpSession CreateSession() { return new ChatSession(this); }

        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Chat TCP server caught an error with code {error}");
        }
    }

    /* The `ChatClient` class is a C# TCP client that handles connecting, disconnecting, receiving
    messages, and processing JSON messages related to a blockchain. */
    public class ChatClient : NetCoreServer.TcpClient
    {
        public ChatClient(string address, int port) : base(address, port) { }

        /// <summary>
        /// The DisconnectAndStop function sets a flag to stop a process, disconnects asynchronously,
        /// and waits until the connection is no longer active.
        /// </summary>
        public void DisconnectAndStop()
        {
            _stop = true;
            DisconnectAsync();
            while (IsConnected)
                Thread.Yield();
        }

       /// <summary>
       /// The OnConnected function in C# prints a message indicating that a new session has been
       /// connected with a specific Id.
       /// </summary>
        protected override void OnConnected()
        {
            Console.WriteLine($"Chat TCP client connected a new session with Id {Id}");

        }

       /// <summary>
       /// The OnDisconnected method in C# handles the disconnection of a chat TCP client session by
       /// printing a message, waiting for a specified time, and attempting to reconnect if not stopped.
       /// </summary>
        protected override void OnDisconnected()
        {
            Console.WriteLine($"Chat TCP client disconnected a session with Id {Id}");

            // Wait for a while...
            Thread.Sleep(1000);

            // Try to connect again
            if (!_stop)
                ConnectAsync();
        }

        /// <summary>
        /// The function processes received byte data by converting it to a string, extracting messages,
        /// deserializing JSON objects, and handling errors.
        /// </summary>
        /// <param name="buffer">The `buffer` parameter is a byte array that contains the data received
        /// by the method.</param>
        /// <param name="offset">The `offset` parameter in the `OnReceived` method represents the
        /// starting position in the `buffer` array from which to begin reading data. It is of type
        /// `long` and indicates the index in the array where the data to be processed starts.</param>
        /// <param name="size">The `size` parameter in the `OnReceived` method represents the size of
        /// the data in bytes that has been received. It is used to determine how much data from the
        /// buffer should be processed.</param>
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
        /// <summary>
        /// The function `GetMessage` extracts messages enclosed within curly braces from a given string
        /// and returns them as an array of strings.
        /// </summary>
        /// <param name="s">The `GetMessage` method you provided seems to be splitting a string `s` into
        /// an array of substrings based on curly braces `{}`. The method accumulates characters until
        /// it encounters a closing curly brace `}` that matches the opening curly brace `{` at the same
        /// scope level. It then</param>
        /// <returns>
        /// The `GetMessage` method returns an array of strings that are extracted from the input string
        /// `s` based on the curly braces `{}`. Each string within the array represents a substring
        /// enclosed within a pair of curly braces in the input string.
        /// </returns>
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
       /// <summary>
       /// The `OnError` function in C# is used to handle and display errors that occur in a chat TCP
       /// client.
       /// </summary>
       /// <param name="SocketError">The `SocketError` parameter in the `OnError` method represents an
       /// enumeration of socket error codes that can occur during socket operations. It provides
       /// information about the specific error that occurred, allowing you to handle and respond to
       /// errors appropriately in your code.</param>
        protected override void OnError(SocketError error)
        {
            Console.WriteLine($"Chat TCP client caught an error with code {error}");
        }

        private bool _stop;
    }


    public static class RSA
    {
        //Note we only store the public key parts of the RSA Parameters on purpose.
        /// <summary>
        /// The function RSAParametersToString converts RSAParameters to a JSON string by serializing
        /// the data into a custom object.
        /// </summary>
        /// <param name="RSAParameters">The `RSAParameters` structure in .NET represents the standard
        /// parameters for the RSA algorithm, including the modulus, exponent, prime factors, and
        /// private key components.</param>
        /// <returns>
        /// The `RSAParametersToString` method returns a JSON string representing the RSA parameters in
        /// a serialized format. The method converts the RSA parameters into a serializable object by
        /// converting the byte arrays (Modulus and Exponent) into Base64 strings. The other fields (P,
        /// Q, DP, DQ, InverseQ, D) are currently commented out in the code snippet provided.
        /// </returns>
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
       /// <summary>
       /// The function `StringToRSAParameters` converts a JSON string representation of RSA parameters
       /// into an `RSAParameters` object in C#.
       /// </summary>
       /// <param name="jsonString">The `StringToRSAParameters` method you provided is used to convert a
       /// JSON string representation of RSA parameters into an `RSAParameters` object.</param>
       /// <returns>
       /// The `StringToRSAParameters` method returns an `RSAParameters` object populated with values
       /// extracted from a JSON string. The `Modulus` and `Exponent` properties are set based on the
       /// corresponding values in the JSON string after decoding from Base64. The other properties
       /// (`P`, `Q`, `DP`, `DQ`, `InverseQ`, `D`) are currently commented out in
       /// </returns>
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
        /// <summary>
        /// The function RSAParametersToStringAll converts RSAParameters to a JSON string by serializing
        /// the data into a custom object with base64-encoded byte arrays.
        /// </summary>
        /// <param name="RSAParameters">The `RSAParameters` structure in .NET represents the parameters
        /// of an RSA key. Here is a brief explanation of each field in the `RSAParameters`
        /// structure:</param>
        /// <returns>
        /// The `RSAParametersToStringAll` method takes an `RSAParameters` object as input, converts its
        /// byte array fields to Base64 strings, and serializes them into a JSON string using
        /// JsonConvert. The method then returns this JSON string containing the serialized RSA
        /// parameters.
        /// </returns>
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
        /// <summary>
        /// The function `StringToRSAParametersAll` converts a JSON string containing RSA parameters
        /// into an RSAParameters object in C#.
        /// </summary>
        /// <param name="jsonString">The `StringToRSAParametersAll` method you provided is used to
        /// convert a JSON string representation of RSA parameters into an `RSAParameters` object. The
        /// method deserializes the JSON string using
        /// `JsonConvert.DeserializeObject<dynamic>(jsonString)` from the Newtonsoft.Json
        /// library.</param>
        /// <returns>
        /// The `StringToRSAParametersAll` method returns an `RSAParameters` object populated with
        /// values extracted from a JSON string. The method deserializes the JSON string into a dynamic
        /// object, extracts the RSA parameters (Modulus, Exponent, P, Q, DP, DQ, InverseQ, D) from the
        /// dynamic object, and converts them from Base64 strings to byte arrays before
        /// </returns>
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
        /// <summary>
        /// The function `GetAccessToken` sends a POST request to obtain an access token using OAuth
        /// authorization code flow.
        /// </summary>
        /// <param name="authorizationCode">The `GetAccessToken` method you provided is used to exchange
        /// an authorization code for an access token using OAuth 2.0. The `authorizationCode` parameter
        /// is the authorization code that you receive from the OAuth authorization flow. This code is
        /// obtained after the user has authenticated and authorized your application to access</param>
        /// <returns>
        /// The method `GetAccessToken` returns an `OAuthTokenResponse` object, which contains the
        /// access token that can be used in subsequent requests.
        /// </returns>
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

        /* The class `OAuthTokenResponse` in C# represents a response object containing properties for
        access token, bearer, refresh token, expiry, scope, name, ORCID, and potentially other
        fields. */
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

        /// <summary>
        /// This C# function searches for an ORCID identifier based on a given name using the ORCID API.
        /// </summary>
        /// <param name="name">The code you provided is a C# method that searches for an ORCID (Open
        /// Researcher and Contributor ID) based on a given name. The method sends a request to the
        /// ORCID API search endpoint with the provided name as a query parameter, retrieves the
        /// response, and extracts the ORCID i</param>
        /// <returns>
        /// The code is making an asynchronous HTTP GET request to the ORCID API to search for a
        /// specific name. It then extracts the ORCID iD from the response and returns it as a string.
        /// </returns>
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
        /// <summary>
        /// The function `CheckORCIDExistence` asynchronously checks the existence of an ORCID record by
        /// making a request to the ORCID API endpoint.
        /// </summary>
        /// <param name="orcid">The `CheckORCIDExistence` method is an asynchronous method that checks
        /// the existence of an ORCID record by making a GET request to the ORCID API endpoint for a
        /// specific ORCID identifier.</param>
        /// <returns>
        /// The method `CheckORCIDExistence` returns a `Task<bool>`. The method asynchronously checks
        /// the existence of an ORCID record by making a GET request to the ORCID API endpoint and
        /// returns a boolean value indicating whether the ORCID record exists or not.
        /// </returns>
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

        /// <summary>
        /// The function `StartListenerAsync` initiates an HTTP listener, directs the user to an
        /// authorization URL, waits for the authorization response, extracts the authorization code,
        /// and sends an HTTP response to the browser.
        /// </summary>
        /// <returns>
        /// The method `StartListenerAsync` is returning the authorization code obtained from the
        /// authorization response.
        /// </returns>
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
        /// <summary>
        /// The function `OpenUrl` opens a specified URL in the default web browser, handling
        /// platform-specific behavior.
        /// </summary>
        /// <param name="url">The `OpenUrl` method you provided is used to open a URL in the default web
        /// browser. The `url` parameter is a string that represents the URL that you want to open in
        /// the browser. This method first tries to open the URL using `Process.Start(url)`, and if that
        /// fails</param>
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
