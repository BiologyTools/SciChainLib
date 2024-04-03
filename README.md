# SciChainLib - SciChain Blockchain Library
For usage see the example below or check out the [documentation.](https://biologytools.github.io/Documentation/SciChainLib/)
 
[![NuGet version (SciChainLib)](https://img.shields.io/nuget/v/SciChainLib.svg)](https://www.nuget.org/packages/SciChainLib/0.2.1) ![Nuget](https://img.shields.io/nuget/dt/SciChainLib)
# Example Usage
```
//First we create/load our wallet with a password.
Wallet wallet = new Wallet();
string dir = System.IO.Path.GetDirectoryName(Environment.ProcessPath);
if(File.Exists(dir + "/wallet.dat"))
    wallet.Load("YourPassword");
else
    wallet.Save("YourPassword");
//Then we initialize and load the chain.
Blockchain.Initialize(wallet);
Blockchain.Load();
//Here we get our public address based on wallet keys.
string st = RSA.RSAParametersToStringAll(wallet.PrivateKey);
string address = Blockchain.CalculateHash(st);
//Getting the balance of the wallet from the chain.
string balance = Blockchain.GetBalance(address).ToString();
//We create a new transaction
Block.Transaction tr = new Block.Transaction(Block.Transaction.Type.transaction, address, wallet.PublicKey, addrBox.Text, amountBox.Value);
//Then we sign the transaction with our private key. All transactions need to be signed outherwise they will not be processed.
tr.SignTransaction(wallet.PrivateKey);
//Then we add the transaction to the chain's pending transactions. This will also broadcast the transaction to all connected peers.
Blockchain.AddTransaction(tr);
//Next we get the chain height
int h = Blockchain.Chain.Count;
//Next we get a transactions status
Block.Transaction trst = Blockchain.GetTransaction(tr);
if(trst == null)
{
 //If the transaction was not found GetTransaction will return null. Meaning our transaction is still pending.
 Console.WriteLine("Transaction Status: Pending");
}
else
{
 //Transaction was found in the chain meaning it is no longer pending.
 Console.WriteLine("Transaction Status: Completed"); 
}
```
