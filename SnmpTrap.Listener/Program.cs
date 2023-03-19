using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using SnmpSharpNet;
using SnmpTrap.Lib;

namespace SnmpTrap.Listener
{
    class Program
    {
        static void Main(string[] args)
        {
            using (SnmpTrapListener stl = new SnmpTrapListener())
            {                
                stl.OnReceiveSnmpTrapPacket = 
                    new SnmpTrapPacketHandler((remoteEP, pkt) =>
                    {                        
                        if (pkt.Version == SnmpVersion.Ver1)
                        {
                            SnmpV1TrapPacket v1pkt = pkt as SnmpV1TrapPacket;

                            Console.WriteLine("{0:yyyy-MM-dd HH:mm:ss} receive SNMPv1 TRAP from {1}:{2}",
                                DateTime.Now, remoteEP.Address.ToString(), remoteEP.Port);
                            
                            Console.WriteLine("*** community {0} generic id: {1} specific id: {2}",
                                v1pkt.Community, v1pkt.Pdu.Generic, v1pkt.Pdu.Specific);
                            
                            Console.WriteLine("*** PDU Count: {0}", v1pkt.Pdu.VbCount);
                            
                            foreach (Vb vb in v1pkt.Pdu.VbList)
                            {                                
                                OutputTrapResult(vb);                                
                            }

                            Console.WriteLine("end of SNMPv1 TRAP");
                        }
                        else if (pkt.Version == SnmpVersion.Ver2)
                        {
                            SnmpV2Packet v2pkt = pkt as SnmpV2Packet;
                            
                            if (v2pkt.Pdu.Type == PduType.V2Trap)
                            {
                                Console.WriteLine("{0:yyyy-MM-dd HH:mm:ss} receive SNMPv2 TRAP from {1}:{2}",
                                    DateTime.Now, remoteEP.Address.ToString(), remoteEP.Port);
                            }
                            else if (v2pkt.Pdu.Type == PduType.Inform)
                            {
                                Console.WriteLine("{0:yyyy-MM-dd HH:mm:ss} receive SNMPv2 INFORM from {1}:{2}",
                                    DateTime.Now, remoteEP.Address.ToString(), remoteEP.Port);
                            }

                            Console.WriteLine("*** community {0} sysUpTime: {1} trapObjectID: {2}",
                                v2pkt.Community, v2pkt.Pdu.TrapSysUpTime, v2pkt.Pdu.TrapObjectID);

                            Console.WriteLine("*** PDU Count: {0}", v2pkt.Pdu.VbCount);

                            foreach (Vb vb in v2pkt.Pdu.VbList)
                            {
                                OutputTrapResult(vb);
                            }

                            if (v2pkt.Pdu.Type == PduType.V2Trap)
                            {
                                Console.WriteLine("end of SNMPv2 TRAP");
                            }
                            else if (v2pkt.Pdu.Type == PduType.Inform)
                            {
                                Console.WriteLine("end of SNMPv2 INFORM");
                            }
                        }
                    });
                stl.Start();
                Console.WriteLine("Listening...");
                Console.Read();
            }
        }
        private const string MS_ENTERPRISE_OID = "1.3.6.1.4.1.311.1.13.1";
        private static void OutputTrapResult(Vb vb)
        {
            string valueType = SnmpConstants.GetTypeName(vb.Value.Type);
            string oid = vb.Oid.ToString();
            if (oid.StartsWith(MS_ENTERPRISE_OID) && valueType.Equals("OctetString", StringComparison.OrdinalIgnoreCase) 
                && vb.Value.ToString().StartsWith("EVNTTRAPBEGIN"))
            {
                string eventlogOid = oid.Substring(MS_ENTERPRISE_OID.Length + 1);
                string[] o = eventlogOid.Split('.');
                string eventlog_source = string.Empty;
                for (int i = 1; i < o.Length; i++)
                {
                    int x = Convert.ToInt32(o[i]);
                    eventlog_source += (char)x;
                }
                Console.WriteLine("EventLog Source:{0}", eventlog_source);
                string s = vb.Value.ToString();
                EventLogTrapMessage msg = EventLogTrapMessage.DeSerialize(s);
                Console.WriteLine("ActivityId:{0}", msg.ActivityId);
                Console.WriteLine("ContainerLog:{0}", msg.ContainerLog);
                Console.WriteLine("Id:{0}", msg.Id);
                Console.WriteLine("Level:{0}", msg.Level);
                Console.WriteLine("LevelDisplayName:{0}", msg.LevelDisplayName);
                Console.WriteLine("LogName:{0}", msg.LogName);
                Console.WriteLine("MachineName:{0}", msg.MachineName);
                Console.WriteLine("ProcessId:{0}", msg.ProcessId);
                if (msg.Properites != null && msg.Properites.Count > 0)
                {
                    Console.WriteLine("Properites:{0}", String.Join(",", msg.Properites.Select(p => p)));
                }
                else
                {
                    Console.WriteLine("Properites:Null");
                }
                Console.WriteLine("ProviderId:{0}", msg.ProviderId);
                Console.WriteLine("ProviderName:{0}", msg.ProviderName);
                Console.WriteLine("RecordId:{0}", msg.RecordId);
                Console.WriteLine("RelatedActivityId:{0}", msg.RelatedActivityId);
                Console.WriteLine("TimeCreated:{0:yyyy-MM-dd HH:mm:ss}", msg.TimeCreated);
                Console.WriteLine("Version:{0}", msg.Version);
            }
            else
            {
                Console.WriteLine("*** {0} {1}: {2}", vb.Oid, valueType, vb.Value);
            }
        }
    }
}
