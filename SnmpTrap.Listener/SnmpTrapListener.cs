using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using SnmpSharpNet;

namespace SnmpTrap.Listener
{
    public delegate void SnmpTrapPacketHandler(IPEndPoint remoteEP, SnmpPacket pkt);

    public class SnmpTrapListener : IDisposable
    {
        private UdpClient _listener;
        private IPEndPoint _ep;
        public SnmpTrapListener(string ip, int port)
        {
            _ep = new IPEndPoint(String.IsNullOrEmpty(ip) 
                ? IPAddress.Any : IPAddress.Parse(ip), port);
            _listener = new UdpClient(_ep);
        }

        public SnmpTrapListener(string ip)
            : this(ip, 162)
        {

        }

        public SnmpTrapListener() :
            this(null, 162)
        {

        }

        public SnmpTrapPacketHandler OnReceiveSnmpTrapPacket;

        public void Start()
        {
            _listener.BeginReceive(new AsyncCallback(ReceiveCallBack), _listener);
        }

        public void Stop()
        {
            _listener.Close();
        }

        private void ReceiveCallBack(IAsyncResult result)
        {
            UdpClient client = result.AsyncState as UdpClient;
            IPEndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
            byte[] bytes = client.EndReceive(result, ref remoteEP);
            Thread t = new Thread(new ParameterizedThreadStart(DualReceivedData));
            t.Start(new object[2] { remoteEP, bytes });
            client.BeginReceive(new AsyncCallback(ReceiveCallBack), client);
        }

        private void DualReceivedData(object data)
        {
            IPEndPoint remoteEP = (IPEndPoint)(data as object[])[0];
            byte[] buffer = (byte[])(data as object[])[1];
            int pktVersion = SnmpPacket.GetProtocolVersion(buffer, buffer.Length);            
            switch (pktVersion)
            {
                case (int)SnmpVersion.Ver1:
                    SnmpV1TrapPacket v1pkt = new SnmpV1TrapPacket();
                    v1pkt.decode(buffer, buffer.Length);
                    if (OnReceiveSnmpTrapPacket != null)
                    {
                        OnReceiveSnmpTrapPacket(remoteEP, v1pkt);
                    }
                    break;
                case (int)SnmpVersion.Ver2:
                    SnmpV2Packet v2pkt = new SnmpV2Packet();
                    v2pkt.decode(buffer, buffer.Length);
                    if (v2pkt.Pdu.Type == PduType.V2Trap || v2pkt.Pdu.Type == PduType.Inform)
                    {
                        if (v2pkt.Pdu.Type == PduType.Inform)
                        {
                            DualInformRequest(remoteEP, v2pkt);
                        }
                        if (OnReceiveSnmpTrapPacket != null)
                        {
                            OnReceiveSnmpTrapPacket(remoteEP, v2pkt);
                        }
                    }
                    break;
                case (int)SnmpVersion.Ver3:
                    break;
            }
        }

        private void DualInformRequest(IPEndPoint remoteEP, SnmpV2Packet pkt)
        {
            // send ACK back to the INFORM sender
            SnmpV2Packet response = pkt.BuildInformResponse();
            byte[] buffer = response.encode();
            UdpClient sender = new UdpClient();
            sender.Send(buffer, buffer.Length, remoteEP);
        }

        protected void Disposing(bool disposed)
        {
            if (disposed)
            {
                Stop();
            }
        }

        public void Dispose()
        {
            Disposing(true);
        }
    }
}
