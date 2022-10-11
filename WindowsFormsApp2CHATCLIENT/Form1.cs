using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Security.Cryptography;
using System.IO;

namespace WindowsFormsApp2CHATCLIENT
{
    public partial class Form1 : Form
    {
        #region variables

        const int MAX_CHUNK_SIZE = (1024 * 5000);
        int LEFTOVER_SIZE;
        int SIZE;
        const int KBitSize = 256;
        const int KBlockSize = 128;
        const int MSG_SIZE = 1024;
        const int PORT = 6666;
        const string IPADD = "127.0.0.1";
        string PROTOCOL = null;
        byte[] confirm = null;

        private static byte[] pubKey;
        ECDiffieHellmanCng user;
        //Dictionary<int, byte[]> map;

        TcpListener server;
        TcpClient client = default;
        NetworkStream ns;

        #endregion
        public Form1()
        {
            InitializeComponent();
        }
        static void SendMsg(NetworkStream sending, byte[] msg)
        {
            try
            {
                sending.Write(msg, 0, msg.Length);
            }
            catch (Exception x)
            {
                MessageBox.Show("Something went wrong " + x.Message);
            }
        }
        static byte[] GetMsg(NetworkStream receiving)
        {

            try
            {
                byte[] msg = new byte[MSG_SIZE];
                MemoryStream incomingData = new MemoryStream();
                int processedBytes = receiving.Read(msg, 0, msg.Length);
                while (processedBytes > 0)
                {
                    incomingData.Write(msg, 0, processedBytes);
                    if (receiving.DataAvailable)
                    {
                        processedBytes = receiving.Read(msg, 0, msg.Length);
                    }
                    else break;
                }

                return incomingData.ToArray();
            }
            catch (Exception x)
            {
                MessageBox.Show("Something went wrong " + x.Message);
                return null;
            }


        }

        #region CryptoFunctions

        public byte[] Encrypt(byte[] key, byte[] iv, byte[] message)
        {
            AesManaged aes = new AesManaged();
            aes.KeySize = KBitSize;
            aes.BlockSize = KBlockSize;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.IV = iv;
            aes.Key = key;

            ICryptoTransform encrypter = aes.CreateEncryptor();
            byte[] encryptedMessage = encrypter.TransformFinalBlock(message, 0, message.Length);
            return encryptedMessage;

        }
        public byte[] Decrypt(byte[] key, byte[] encryptedMessage, byte[] iv)
        {
            AesManaged aes = new AesManaged();
            aes.KeySize = KBitSize;
            aes.BlockSize = KBlockSize;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.IV = iv;
            aes.Key = key;

            ICryptoTransform decryptor = aes.CreateDecryptor();
            byte[] decryptedMessage = decryptor.TransformFinalBlock(encryptedMessage, 0, encryptedMessage.Length);
            return decryptedMessage;
        }
        private void GetPubKey()
        {
            user = new ECDiffieHellmanCng();
            user.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            user.HashAlgorithm = CngAlgorithm.Sha256;
            pubKey = user.PublicKey.ToByteArray();
        }
        private byte[] IV()
        {
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            var byteArray = new byte[16];
            provider.GetBytes(byteArray);
            provider.Dispose();
            return byteArray;
        }

        #endregion

        #region downloader
        private void getMessage()
        {
            while (true)
            {
                client = server.AcceptTcpClient();
                ns = client.GetStream();

                #region KEY_EXCHANGE

                //get protocol type
                byte[] prot = GetMsg(ns);
                PROTOCOL = Encoding.UTF8.GetString(prot);

                //get file name
                byte[] name = GetMsg(ns);
                string nameS = Encoding.UTF8.GetString(name);

                //get file size
                byte[] size = GetMsg(ns);
                SIZE = Convert.ToInt32(Encoding.UTF8.GetString(size));

                // pubkey exchange
                byte[] pbkey = GetMsg(ns);
                listBox1.Items.Add("Client's public key :" + Convert.ToBase64String(pbkey));
                SendMsg(ns, pubKey);
                listBox1.Items.Add("My public key: " + Convert.ToBase64String(pubKey));

                //iv
                byte[] iv = GetMsg(ns);

                //derive key
                byte[] key = user.DeriveKeyMaterial(ECDiffieHellmanCngPublicKey.FromByteArray(pbkey, CngKeyBlobFormat.EccPublicBlob));

                #endregion

                //get enc msg

                if (SIZE < MAX_CHUNK_SIZE)
                {
                    pbkey = GetMsg(ns);

                    //decrypt and write to file
                    byte[] decrypted = Decrypt(key, pbkey, iv);
                    //listBox1.Items.Add("FILE SIZE: " + SIZE / 1024000 + "MB");
                    using (FileStream fsNew = new FileStream("C:\\Users\\Luka\\Desktop\\Downloads\\" + nameS + "TEST" + PROTOCOL,
                    FileMode.Create, FileAccess.Write))
                    {
                        fsNew.Write(decrypted, 0, decrypted.Length);
                    }

                }

                else
                {
                    confirm = Encoding.UTF8.GetBytes("ok");

                    decimal d = (decimal)SIZE / (decimal)MAX_CHUNK_SIZE;
                    int loop = (int)Math.Ceiling(d);
                    listBox1.Items.Add("Must loop " + loop + "many times.");

                    FileStream fsNew = new FileStream("C:\\Users\\Luka\\Desktop\\Downloads\\" + nameS + "TEST" + PROTOCOL,
                           FileMode.Create, FileAccess.Write);

                    for (int i = 0; i < loop; i++)
                    {

                        //get enc msg
                        pbkey = GetMsg(ns);
                        //decrypt and write to file
                        byte[] decrypted = Decrypt(key, pbkey, iv);

                        if (i == loop - 1)
                        {
                            listBox1.Items.Add("Part " + (i + 1) + " out of " + loop);
                            LEFTOVER_SIZE = SIZE - i * MAX_CHUNK_SIZE;
                            listBox1.Items.Add("SIZE: " + SIZE / 1024000 + "MB");
                            listBox1.Items.Add("RECEIVED TOTAL: " + (SIZE / 1024000) + "MB");
                            fsNew.Write(decrypted, 0, LEFTOVER_SIZE);
                            fsNew.Close();
                            SendMsg(ns, confirm);
                            break;
                        }

                        listBox1.Items.Add("Part " + (i + 1) + " out of " + loop);
                        LEFTOVER_SIZE = SIZE - i * MAX_CHUNK_SIZE;
                        listBox1.Items.Add("FILE SIZE: " + SIZE / 1024000 + "MB");
                        listBox1.Items.Add("RECEIVED TOTAL: " + (((i + 1) * MAX_CHUNK_SIZE) / 1024000) + "MB");
                        listBox1.Items.Add("LEFT: " + LEFTOVER_SIZE / 1024000 + "MB");

                        fsNew.Write(decrypted, 0, decrypted.Length);
                        SendMsg(ns, confirm);
                    }
                }

                listBox1.Items.Add("STATUS: File downloaded!");
                client.Dispose();

            }
        }
        private void ReceiveButtonClick(object sender, EventArgs e)
        {
            GetPubKey();

            server = new TcpListener(IPAddress.Parse(IPADD), PORT);
            server.Start();

            listBox1.Items.Add("Started listening");
            listBox1.Items.Add("Waiting for connection");

            Thread ctThread = new Thread(getMessage);
            ctThread.Start();
        }

        #endregion

        #region uploader
        private void Button4_ClickSEND(object sender, EventArgs e)
        {
            string location = null;

            if (PROTOCOL == ".bmp")
            {
                location = textBox2.Text;
            }

            if (PROTOCOL == ".pdf")
            {
                location = textBox3.Text;
            }

            if (PROTOCOL == ".mp3")
            {
                location = textBox4.Text;
            }

            string nameS = location.Substring(0, location.IndexOf("."));
            nameS = nameS.Substring(22);
            byte[] name = Encoding.UTF8.GetBytes(nameS);

            FileStream file = new FileStream(location, FileMode.Open, FileAccess.Read);

            if (file.Length < (long)MAX_CHUNK_SIZE)
            {
                SIZE = (int)file.Length;
                byte[] bytes = new byte[file.Length];
                file.Read(bytes, 0, (int)file.Length);
                SendMessage(bytes, name);
            }

            else
            {
                SIZE = (int)file.Length;
                SendMessage(file, name);
            }
        }
        private void SendButtonClick(object sender, EventArgs e)
        {
            GetPubKey();
        }
        private void SendMessage(byte[] file, byte[] name)
        {
            client = new TcpClient();
            client.Connect(IPADD, PORT);
            ns = client.GetStream();

            byte[] fileSize = Encoding.UTF8.GetBytes(Convert.ToString(SIZE));

            #region KEY_EXCHANGE

                //send protocol
                SendMsg(ns, Encoding.UTF8.GetBytes(PROTOCOL));
                listBox1.Items.Add("Protocol sent");

                //send name
                SendMsg(ns, name);
                listBox1.Items.Add("Connected");

                //send file size
                SendMsg(ns, fileSize);
                listBox1.Items.Add("Sent file size");

                // pubkey exchange
                SendMsg(ns, pubKey);
                listBox1.Items.Add("My public key sent");
                byte[] clientPubKey = GetMsg(ns);
                listBox1.Items.Add("Client's public key is: " + Convert.ToBase64String(clientPubKey));

                //iv
                byte[] iv = IV();
                SendMsg(ns, iv);
                listBox1.Items.Add("IV:" + Convert.ToBase64String(iv));

                //derive key
                byte[] key = user.DeriveKeyMaterial(ECDiffieHellmanCngPublicKey.FromByteArray(clientPubKey, CngKeyBlobFormat.EccPublicBlob));

            #endregion

            //encrypt and send
            byte[] enc = Encrypt(key, iv, file);
            SendMsg(ns, enc);

            client.Dispose();
            listBox1.Items.Add("File uploaded successfully!");

        }
        private void SendMessage(FileStream file, byte[] name)
        {
            client = new TcpClient();
            client.Connect(IPADD, PORT);
            ns = client.GetStream();

            decimal d = (decimal)file.Length / (decimal)MAX_CHUNK_SIZE;
            int iterations = (int)Math.Ceiling(d);
            byte[] fileSize = Encoding.UTF8.GetBytes(Convert.ToString(SIZE));

            #region KEY_EXCHANGE

                //send protocol
                SendMsg(ns, Encoding.UTF8.GetBytes(PROTOCOL));
                listBox1.Items.Add("Protocol sent");

                //send name
                SendMsg(ns, name);
                listBox1.Items.Add("Connected");

                SendMsg(ns, fileSize);
                listBox1.Items.Add("Sent file size");

                // pubkey exchange
                SendMsg(ns, pubKey);
                listBox1.Items.Add("My public key sent");
                byte[] clientPubKey = GetMsg(ns);
                listBox1.Items.Add("Client's public key is: " + Convert.ToBase64String(clientPubKey));

                //iv
                byte[] iv = IV();
                SendMsg(ns, iv);
                listBox1.Items.Add("IV:" + Convert.ToBase64String(iv));

                //derive key
                byte[] key = user.DeriveKeyMaterial(ECDiffieHellmanCngPublicKey.FromByteArray(clientPubKey, CngKeyBlobFormat.EccPublicBlob));

            #endregion

            //split and send
            byte[] enc = new byte[MAX_CHUNK_SIZE];
            byte[] bytes = new byte[MAX_CHUNK_SIZE];

            listBox1.Items.Add("Total iterations: " + iterations);

            for (int i = 0; i < iterations; i++)
            {

                    file.Read(bytes, 0, MAX_CHUNK_SIZE);
                    enc = Encrypt(key, iv, bytes);
                    SendMsg(ns, enc);

                    /*listBox1.Items.Add("Iteration number: " + i);
                    listBox1.Items.Add("SIZE: " + enc.Length);*/

                    confirm = GetMsg(ns);

                    if (Encoding.UTF8.GetString(confirm) != "ok") 
                    {
                        MessageBox.Show("NOT OK!");
                    }
            }

            client.Dispose();
            listBox1.Items.Add("File uploaded successfully!");
        }

        #endregion

        #region set_protocols
        private void textBox1_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                SendButtonClick(this, e);
                e.Handled = true;
                e.SuppressKeyPress = true;
            }
        }
        private void textBox4_TextChanged(object sender, EventArgs e)
        {
            PROTOCOL = ".mp3";
        }
        private void textBox2_TextChanged(object sender, EventArgs e)
        {
            PROTOCOL = ".bmp";
        }
        private void textBox3_TextChanged(object sender, EventArgs e)
        {
            PROTOCOL = ".pdf";
        }
        private void button3_Click(object sender, EventArgs e)
        {
            listBox1.Items.Add(PROTOCOL);
        }
        
        #endregion

        //empty
        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }
        private void pictureBox1_Click(object sender, EventArgs e)
        {

        }

    }
}
/*        private void Button1_ClickConnect(object sender, EventArgs e)
        {

            try
            {
                client.Connect(IPAddress.Parse("127.0.0.1"), 2222);
                networkStream = client.GetStream();
                chatbox.Items.Add("Connected to chatroom!");

                sendEncrypted(networkStream, textBox1.Text + ">$e<");

                textBox1.Clear();
                textBox1.Enabled = false;
                button1.Enabled = false;

                Thread ctThread = new Thread(getMessage);
                ctThread.Start();

            }
            catch (SocketException x)
            {
                MessageBox.Show("Server not available!");

            }


        }
        private void getMessage()
        {
            while (true)
            {

                networkStream = client.GetStream();
                string rec = getEncrypted(networkStream);
                rec = rec.Substring(0, rec.IndexOf(">$e<"));
                chatbox.Items.Add(rec);

            }
        }
        private void button2_Click(object sender, EventArgs e)
        {

            sendEncrypted(networkStream, textBox2.Text + ">$e<");
            byte[] ToSend = Encoding.ASCII.GetBytes(textBox2.Text + ">$e<");
            textBox2.Clear();

        }
*/