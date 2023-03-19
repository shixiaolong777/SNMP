using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using SnmpSharpNet;

namespace SnmpGet
{
    class Program
    {
        static void Main(string[] args)
        {
            // SNMP community name
            OctetString community = new OctetString("public");

            // Define agent parameters class
            AgentParameters param = new AgentParameters(community);
            // Set SNMP version to 1 (or 2)
            param.Version = SnmpVersion.Ver1;
            // Construct the agent address object
            // IpAddress class is easy to use here because
            //  it will try to resolve constructor parameter if it doesn't
            //  parse to an IP address
            IpAddress agent = new IpAddress("127.0.0.1");

            // Construct target
            UdpTarget target = new UdpTarget((IPAddress)agent, 161, 2000, 1);
            // Pdu class used for all requests
            Pdu pdu = new Pdu(PduType.Get);
            pdu.VbList.Add(".1.3.6.1.2.1.1.1.0"); //sysDescr
            pdu.VbList.Add(".1.3.6.1.2.1.1.2.0"); //sysObjectID
            pdu.VbList.Add(".1.3.6.1.2.1.1.3.0"); //sysUpTime
            pdu.VbList.Add(".1.3.6.1.2.1.1.4.0"); //sysContact
            pdu.VbList.Add(".1.3.6.1.2.1.1.5.0"); //sysName            
            //pdu.VbList.Add(".1.3.6.1.2.1.25.2.3.1.5.1"); //hrStorageSize(Disk: C:\ Label:  Serial Number c1a86f5)
            //pdu.VbList.Add(".1.3.6.1.2.1.25.2.3.1.5.2"); //hrStorageSize(Disk: E:\ Label:  Serial Number 96afb751)
            //pdu.VbList.Add(".1.3.6.1.2.1.25.2.3.1.5.5"); //hrStorageSize(Physical Memory)

            //pdu.VbList.Add(".1.3.6.1.2.1.25.2.3.1.4.1"); //hrStorageAllocationUnits(Disk C:\ Label:  Serial Number c1a86f5)
            //pdu.VbList.Add(".1.3.6.1.2.1.25.2.3.1.4.2"); //hrStorageAllocationUnits(Disk E:\ Label:  Serial Number c1a86f5)
            //pdu.VbList.Add(".1.3.6.1.2.1.25.2.3.1.4.5"); //hrStorageAllocationUnits(Physical Memory)

            //pdu.VbList.Add(".1.3.6.1.2.1.25.2.3.1.6.1"); //hrStorageUsed(Disk: C:\ Label:  Serial Number c1a86f5)
            //pdu.VbList.Add(".1.3.6.1.2.1.25.2.3.1.6.2"); //hrStorageUsed(Disk: E:\ Label:  Serial Number 96afb751)
            //pdu.VbList.Add(".1.3.6.1.2.1.25.2.3.1.6.5"); //hrStorageUsed(Physical Memory)

            // Make SNMP request
            SnmpV1Packet result = (SnmpV1Packet)target.Request(pdu, param);

            // If result is null then agent didn't reply or we couldn't parse the reply.
            if (result != null)
            {
                // ErrorStatus other then 0 is an error returned by 
                // the Agent - see SnmpConstants for error definitions
                if (result.Pdu.ErrorStatus != 0)
                {
                    // agent reported an error with the request
                    Console.WriteLine("Error in SNMP reply. Error {0} index {1}",
                        result.Pdu.ErrorStatus,
                        result.Pdu.ErrorIndex);
                }
                else
                {
                    // Reply variables are returned in the same order as they were added
                    //  to the VbList
                    Console.WriteLine("sysDescr({0}) ({1}): {2}",
                        result.Pdu.VbList[0].Oid.ToString(), SnmpConstants.GetTypeName(result.Pdu.VbList[0].Value.Type),
                        result.Pdu.VbList[0].Value.ToString());
                    Console.WriteLine("sysObjectID({0}) ({1}): {2}",
                        result.Pdu.VbList[1].Oid.ToString(), SnmpConstants.GetTypeName(result.Pdu.VbList[1].Value.Type),
                        result.Pdu.VbList[1].Value.ToString());
                    Console.WriteLine("sysUpTime({0}) ({1}): {2}",
                        result.Pdu.VbList[2].Oid.ToString(), SnmpConstants.GetTypeName(result.Pdu.VbList[2].Value.Type),
                        DateTime.Now.AddMilliseconds(-1 * ((TimeTicks)result.Pdu.VbList[2].Value).Milliseconds));
                    Console.WriteLine("sysContact({0}) ({1}): {2}",
                        result.Pdu.VbList[3].Oid.ToString(), SnmpConstants.GetTypeName(result.Pdu.VbList[3].Value.Type),
                        result.Pdu.VbList[3].Value.ToString());
                    Console.WriteLine("sysName({0}) ({1}): {2}",
                        result.Pdu.VbList[4].Oid.ToString(), SnmpConstants.GetTypeName(result.Pdu.VbList[4].Value.Type),
                        result.Pdu.VbList[4].Value.ToString());

                    //double disk_c_size_total = Convert.ToDouble(result.Pdu.VbList[0].Value.ToString());
                    //double disk_e_size_total = Convert.ToDouble(result.Pdu.VbList[1].Value.ToString());
                    //double ram_size_total = Convert.ToDouble(result.Pdu.VbList[2].Value.ToString()); 

                    //int disk_c_allocate = Convert.ToInt32(result.Pdu.VbList[3].Value.ToString());
                    //int disk_e_allocate = Convert.ToInt32(result.Pdu.VbList[4].Value.ToString());
                    //int ram_allocate = Convert.ToInt32(result.Pdu.VbList[5].Value.ToString());

                    //double disk_c_size_used = Convert.ToDouble(result.Pdu.VbList[6].Value.ToString());
                    //double disk_e_size_used = Convert.ToDouble(result.Pdu.VbList[7].Value.ToString());
                    //double ram_c_size_used = Convert.ToDouble(result.Pdu.VbList[8].Value.ToString());

                    //int disk_size_total = (int)Math.Floor((disk_c_size_total * disk_c_allocate + disk_e_size_total * disk_e_allocate) / Math.Pow(1024, 3));
                    //double ram_size_total_GB = Math.Round((ram_size_total * ram_allocate) / Math.Pow(1024, 3), 2);

                    //int disk_size_used = (int)Math.Floor((disk_c_size_used * disk_c_allocate + disk_e_size_used * disk_e_allocate) / Math.Pow(1024, 3));
                    //double ram_size_used_GB = Math.Round((ram_c_size_used * ram_allocate) / Math.Pow(1024, 3), 2);

                    //double disk_usage = Math.Round(disk_size_used * 100.0 / disk_size_total);
                    //double ram_usage = Math.Round(ram_size_used_GB * 100.0 / ram_size_total_GB);

                    //Console.WriteLine("Disk Total Size: {0}GB", disk_size_total);
                    //Console.WriteLine("Disk Used Size: {0}GB", disk_size_used);
                    //Console.WriteLine("Disk Usage: {0}%", disk_usage);

                    //Console.WriteLine("RAM Total Size: {0}GB", ram_size_total_GB);
                    //Console.WriteLine("RAM Used Size: {0}GB", ram_size_used_GB);
                    //Console.WriteLine("RAM Usage: {0}%", ram_usage);
                }
            }
            else
            {
                Console.WriteLine("No response received from SNMP agent.");
            }

            target.Dispose();
            Console.Read();
        }
    }
}
