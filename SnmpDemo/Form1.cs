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
using System.IO;
using SnmpSharpNet;

namespace SnmpDemo
{
    public partial class frmSnmp : Form
    {
        public frmSnmp()
        {
            InitializeComponent();
        }

        private void WriteLine(string format, params object[] args)
        {
            this.resultBox.AppendText(String.Format(format, args) + Environment.NewLine);
        }

        private string HexToString(string hex, Encoding encoding)
        {
            //以空格分割字符串，并去掉空字符
            string[] chars = hex.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            byte[] b = new byte[chars.Length];
            //逐个字符变为16进制字节数据
            for (int i = 0; i < chars.Length; i++)
            {
                b[i] = Convert.ToByte(chars[i], 16);
            }
            //按照指定编码将字节数组变为字符串
            string str = encoding.GetString(b);
            //去掉字符串结束\0
            str = str.TrimEnd("\0".ToCharArray());
            return str;
        }

        private DateTime HexToDateTime(string hex)
        {
            string[] b = hex.Split(' ');
            //DateAndTime ::= OCTET STRING (SIZE (8 | 11))
            int[] bytes = new int[8];
            for (int i = 0; i< b.Length; i++)
            {
                bytes[i] = int.Parse(b[i], System.Globalization.NumberStyles.HexNumber);
            }
            byte[] format_str = new byte[19];
            int year = bytes[0] * 256 + bytes[1]; //年占2个字节
            int month = bytes[2];
            int day = bytes[3];
            int hour = bytes[4];
            int minute = bytes[5];
            int second = bytes[6];
            int msecond = bytes[7];
            int index = 3;
            int temp = year;
            for (; index >= 0; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));
                temp /= 10;
            }

            format_str[4] = (byte)('-');
            index = 6;
            temp = month;
            for (; index >= 5; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));
                temp /= 10;
            }

            format_str[7] = (byte)('-');
            index = 9;
            temp = day;
            for (; index >= 8; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));
                temp /= 10;
            }

            format_str[10] = (byte)(' ');
            index = 12;
            temp = hour;
            for (; index >= 11; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));
                temp /= 10;
            }

            format_str[13] = (byte)(':');
            index = 15;
            temp = minute;
            for (; index >= 14; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));
                temp /= 10;
            }

            format_str[16] = (byte)(':');
            index = 18;
            temp = second;
            for (; index >= 17; index--)
            {
                format_str[index] = (byte)(48 + (temp - temp / 10 * 10));
                temp /= 10;
            }
            string dateString = Encoding.Default.GetString(format_str);
            return DateTime.Parse(dateString);
        }

        private Dictionary<int, AsnType> GetHrStorageValues(string community, string ip, int port, Oid rootOid, List<int> indexs)
        {
            Dictionary<int, AsnType> dicValues = new Dictionary<int, AsnType>();
            AgentParameters param = new AgentParameters(new OctetString(community));
            param.Version = SnmpVersion.Ver2;
            Pdu pdu = Pdu.GetBulkPdu();
            pdu.NonRepeaters = 0;
            pdu.MaxRepetitions = 5;

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                Oid lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    if (indexs.Contains(i))
                                    {
                                        dicValues[i] = v.Value;
                                    }

                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }

            return dicValues;
        }

        private List<Storage> GetHrStorages(string community, string ip, int port, string hrStorageTypeOid)
        {
            Dictionary<int, Storage> dicStorage = new Dictionary<int, Storage>();

            AgentParameters param = new AgentParameters(new OctetString(community));
            param.Version = SnmpVersion.Ver2;
            Pdu pdu = Pdu.GetBulkPdu();
            pdu.NonRepeaters = 0;
            pdu.MaxRepetitions = 5;
            Oid rootOid = null, lastOid = null;

            #region get all hrStorageType Oid

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                Oid compareOid = new Oid(hrStorageTypeOid);

                rootOid = new Oid(".1.3.6.1.2.1.25.2.3.1.2");
                lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    if ((Oid)v.Value == compareOid)
                                    {
                                        SnmpConstants.GetTypeName(v.Value.Type);
                                        dicStorage[i] = new Storage((Oid)v.Value);
                                    }

                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }
            #endregion

            if (dicStorage.Count == 0)
            {
                return null;
            }

            #region get storage desc

            Dictionary<int, AsnType> descValues = GetHrStorageValues(community, ip, port,
                new Oid(".1.3.6.1.2.1.25.2.3.1.3"), dicStorage.Keys.ToList());
            if (descValues != null && descValues.Count > 0)
            {
                foreach (var dv in descValues)
                {
                    string descr = !(dv.Value as OctetString).IsHex ? dv.Value.ToString()
                        : HexToString((dv.Value as OctetString).ToString(), Encoding.Default);
                    if (!String.IsNullOrEmpty(descr))
                    {
                        dicStorage[dv.Key].descr = descr.Substring(0, 1);
                    }
                }
            }

            #endregion

            #region get storage allocation untis

            Dictionary<int, AsnType> auValues = GetHrStorageValues(community, ip, port,
                new Oid(".1.3.6.1.2.1.25.2.3.1.4"), dicStorage.Keys.ToList());
            if (auValues != null && auValues.Count > 0)
            {
                foreach (var av in auValues)
                {
                    dicStorage[av.Key].allocationUnits = Convert.ToInt32(av.Value.ToString());
                }
            }

            #endregion

            #region get storage size

            Dictionary<int, AsnType> sValues = GetHrStorageValues(community, ip, port,
                new Oid(".1.3.6.1.2.1.25.2.3.1.5"), dicStorage.Keys.ToList());
            if (sValues != null && sValues.Count > 0)
            {
                foreach (var sv in sValues)
                {
                    dicStorage[sv.Key].size = Convert.ToDouble(sv.Value.ToString());
                }
            }

            #endregion

            #region get storage used

            Dictionary<int, AsnType> uValues = GetHrStorageValues(community, ip, port,
                new Oid(".1.3.6.1.2.1.25.2.3.1.6"), dicStorage.Keys.ToList());
            if (auValues != null && auValues.Count > 0)
            {
                foreach (var uv in uValues)
                {
                    dicStorage[uv.Key].used = Convert.ToDouble(uv.Value.ToString());
                }
            }

            #endregion

            return dicStorage.Values.ToList();
        }

        private Dictionary<Oid, int> GetHrProcessorLoad(string community, string ip, int port)
        {
            Dictionary<Oid, int> cpuUsages = new Dictionary<Oid, int>();
            AgentParameters param = new AgentParameters(new OctetString(community));
            param.Version = SnmpVersion.Ver2;
            Pdu pdu = Pdu.GetBulkPdu();
            pdu.NonRepeaters = 0;
            pdu.MaxRepetitions = 5;

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                Oid rootOid = new Oid(".1.3.6.1.2.1.25.3.3.1.2");
                Oid lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    cpuUsages.Add(v.Oid, Convert.ToInt32(v.Value.ToString()));

                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }
            return cpuUsages;
        }

        private List<Interfaces> GetInterfaces(string community, string ip, int port, int ifType, bool ifConnectorPresent)
        {
            Dictionary<int, Interfaces> dicInterfaces = new Dictionary<int, Interfaces>();
            AgentParameters param = new AgentParameters(new OctetString(community));
            param.Version = SnmpVersion.Ver2;
            Pdu pdu = Pdu.GetBulkPdu();
            pdu.NonRepeaters = 0;
            pdu.MaxRepetitions = 5;
            Oid rootOid = null, lastOid = null;

            #region get all ifType interfaces

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                rootOid = new Oid(".1.3.6.1.2.1.2.2.1.3");
                lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    if (Convert.ToInt32(v.Value.ToString()) == ifType)
                                    {
                                        dicInterfaces[i] = new Interfaces
                                        {
                                            ifType = ifType
                                        };
                                    }

                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }

            #endregion

            if (dicInterfaces.Count == 0)
            {
                return null;
            }

            //if the interfaces sublayer has a physical connector
            if (ifConnectorPresent)
            {
                #region filter interfaces

                using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
                {
                    rootOid = new Oid(".1.3.6.1.2.1.31.1.1.1.17");
                    lastOid = (Oid)rootOid.Clone();
                    int i = 0;
                    while (lastOid != null)
                    {
                        if (pdu.RequestId != 0)
                        {
                            pdu.RequestId += 1;
                        }
                        pdu.VbList.Clear();
                        pdu.VbList.Add(lastOid);
                        SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                        if (result != null)
                        {
                            if (result.Pdu.ErrorStatus != 0)
                            {
                                // agent reported an error with the request
                                WriteLine("Error in SNMP reply. Error {0} index {1}",
                                    result.Pdu.ErrorStatus,
                                    result.Pdu.ErrorIndex);
                                lastOid = null;
                                break;
                            }
                            else
                            {
                                foreach (Vb v in result.Pdu.VbList)
                                {
                                    // Check that retrieved Oid is "child" of the root OID
                                    if (rootOid.IsRootOf(v.Oid))
                                    {
                                        if (dicInterfaces.ContainsKey(i))
                                        {
                                            if (Convert.ToInt32(v.Value.ToString()) == 2) //v.Value: false
                                            {
                                                dicInterfaces.Remove(i);
                                            }
                                        }
                                        if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                            lastOid = null;
                                        else
                                            lastOid = v.Oid;
                                    }
                                    else
                                    {
                                        // we have reached the end of the requested
                                        // MIB tree. Set lastOid to null and exit loop
                                        lastOid = null;
                                    }
                                    i++;
                                }
                            }
                        }
                    }
                    target.Close();
                }

                #endregion
            }

            #region get ifDescr

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                rootOid = new Oid(".1.3.6.1.2.1.2.2.1.2");
                lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    if (dicInterfaces.ContainsKey(i))
                                    {
                                        if (!(v.Value as OctetString).IsHex)
                                        {
                                            dicInterfaces[i].descr = v.Value.ToString();
                                        }
                                        else
                                        {
                                            dicInterfaces[i].descr = HexToString((v.Value as OctetString).ToHexString(), Encoding.Default);
                                        }
                                    }
                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }

            #endregion

            #region get ifPhysAddress

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                rootOid = new Oid(".1.3.6.1.2.1.2.2.1.6");
                lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    if (dicInterfaces.ContainsKey(i))
                                    {
                                        dicInterfaces[i].ifPhysAddress = v.Value.ToString();
                                    }
                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }

            #endregion

            #region get ifMtu

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                rootOid = new Oid(".1.3.6.1.2.1.2.2.1.4");
                lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    if (dicInterfaces.ContainsKey(i))
                                    {
                                        dicInterfaces[i].ifMtu = Convert.ToInt32(v.Value.ToString());
                                    }
                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }

            #endregion

            #region get ifSpeed

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                rootOid = new Oid(".1.3.6.1.2.1.2.2.1.5");
                lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    if (dicInterfaces.ContainsKey(i))
                                    {
                                        dicInterfaces[i].ifSpeed = Convert.ToInt32(v.Value.ToString());
                                    }
                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }

            #endregion

            #region get ifInOctets

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                rootOid = new Oid(".1.3.6.1.2.1.2.2.1.10");
                lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    if (dicInterfaces.ContainsKey(i))
                                    {
                                        dicInterfaces[i].ifInOctets = Convert.ToInt64(v.Value.ToString());
                                    }
                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }

            #endregion

            #region get ifOutOctets

            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                rootOid = new Oid(".1.3.6.1.2.1.2.2.1.16");
                lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    if (dicInterfaces.ContainsKey(i))
                                    {
                                        dicInterfaces[i].ifOutOctets = Convert.ToInt64(v.Value.ToString());
                                    }
                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }

            #endregion

            return dicInterfaces.Values.ToList();
        }

        private Dictionary<int, AsnType> GetOidTreeItemValues(string community, string ip, int port, string itemOid)
        {
            Dictionary<int, AsnType> dic = new Dictionary<int, AsnType>();
            AgentParameters param = new AgentParameters(new OctetString(community));
            param.Version = SnmpVersion.Ver2;
            Pdu pdu = Pdu.GetBulkPdu();
            pdu.NonRepeaters = 0;
            pdu.MaxRepetitions = 5;
            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 200, 1))
            {
                Oid rootOid = new Oid(itemOid);
                Oid lastOid = (Oid)rootOid.Clone();
                int i = 0;
                while (lastOid != null)
                {
                    if (pdu.RequestId != 0)
                    {
                        pdu.RequestId += 1;
                    }
                    pdu.VbList.Clear();
                    pdu.VbList.Add(lastOid);
                    SnmpV2Packet result = (SnmpV2Packet)target.Request(pdu, param);
                    if (result != null)
                    {
                        if (result.Pdu.ErrorStatus != 0)
                        {
                            // agent reported an error with the request
                            WriteLine("Error in SNMP reply. Error {0} index {1}",
                                result.Pdu.ErrorStatus,
                                result.Pdu.ErrorIndex);
                            lastOid = null;
                            break;
                        }
                        else
                        {
                            foreach (Vb v in result.Pdu.VbList)
                            {
                                // Check that retrieved Oid is "child" of the root OID
                                if (rootOid.IsRootOf(v.Oid))
                                {
                                    dic[i] = v.Value;

                                    if (v.Value.Type == SnmpConstants.SMI_ENDOFMIBVIEW)
                                        lastOid = null;
                                    else
                                        lastOid = v.Oid;
                                }
                                else
                                {
                                    // we have reached the end of the requested
                                    // MIB tree. Set lastOid to null and exit loop
                                    lastOid = null;
                                }
                                i++;
                            }
                        }
                    }
                }
                target.Close();
            }
            return dic;
        }

        private TcpSummary GetTcpSummary(string community, string ip, int port)
        {
            TcpSummary tcp = new TcpSummary();

            #region get tcp summary
            
            AgentParameters param = new AgentParameters(new OctetString(community));
            param.Version = SnmpVersion.Ver1;
            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                Pdu pdu = new Pdu(PduType.Get);
                pdu.VbList.Add(".1.3.6.1.2.1.6.5.0"); //tcpActiveOpens
                pdu.VbList.Add(".1.3.6.1.2.1.6.6.0"); //tcpPassiveOpens
                pdu.VbList.Add(".1.3.6.1.2.1.6.7.0"); //tcpAttemptFails
                pdu.VbList.Add(".1.3.6.1.2.1.6.8.0"); //tcpEstabResets
                pdu.VbList.Add(".1.3.6.1.2.1.6.9.0"); //tcpCurrEstab
                pdu.VbList.Add(".1.3.6.1.2.1.6.10.0"); //tcpInSegs
                pdu.VbList.Add(".1.3.6.1.2.1.6.11.0"); //tcpOutSegs
                pdu.VbList.Add(".1.3.6.1.2.1.6.12.0"); //tcpRetransSegs

                SnmpV1Packet result = (SnmpV1Packet)target.Request(pdu, param);
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
                        tcp.tcpActiveOpens = Convert.ToInt32(result.Pdu.VbList[0].Value.ToString());
                        tcp.tcpPassiveOpens = Convert.ToInt32(result.Pdu.VbList[1].Value.ToString());
                        tcp.tcpAttemptFails = Convert.ToInt32(result.Pdu.VbList[2].Value.ToString());
                        tcp.tcpEstabResets = Convert.ToInt32(result.Pdu.VbList[3].Value.ToString());
                        tcp.tcpCurrEstab = Convert.ToInt32(result.Pdu.VbList[4].Value.ToString());
                        tcp.tcpInSegs = Convert.ToInt32(result.Pdu.VbList[5].Value.ToString());
                        tcp.tcpOutSegs = Convert.ToInt32(result.Pdu.VbList[6].Value.ToString());
                        tcp.tcpRetransSegs = Convert.ToInt32(result.Pdu.VbList[7].Value.ToString());
                    }
                }
                target.Close();
            }

            #endregion

            Dictionary<int, TcpConnEntry> dicTcpConn = new Dictionary<int, TcpConnEntry>();

            Dictionary<int, AsnType> itemvalues = null;

            #region get tcpConnState

            itemvalues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.6.13.1.1");
            if (itemvalues != null)
            {
                foreach (var itemvalue in itemvalues)
                {
                    if (!dicTcpConn.ContainsKey(itemvalue.Key))
                    {
                        dicTcpConn.Add(itemvalue.Key, new TcpConnEntry());
                    }
                    dicTcpConn[itemvalue.Key].tcpConnState = (TcpConnState)(int)(itemvalue.Value as Integer32);
                }
            }

            #endregion

            #region get tcpConnLocalAddress

            itemvalues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.6.13.1.2");
            if (itemvalues != null)
            {
                foreach (var itemvalue in itemvalues)
                {
                    if (!dicTcpConn.ContainsKey(itemvalue.Key))
                    {
                        dicTcpConn.Add(itemvalue.Key, new TcpConnEntry());
                    }
                    dicTcpConn[itemvalue.Key].tcpConnLocalAddress = itemvalue.Value.ToString();
                }
            }

            #endregion

            #region get tcpConnLocalPort

            itemvalues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.6.13.1.3");
            if (itemvalues != null)
            {
                foreach (var itemvalue in itemvalues)
                {
                    if (!dicTcpConn.ContainsKey(itemvalue.Key))
                    {
                        dicTcpConn.Add(itemvalue.Key, new TcpConnEntry());
                    }
                    dicTcpConn[itemvalue.Key].tcpConnLocalPort = (int)(itemvalue.Value as Integer32);
                }
            }

            #endregion

            #region get tcpConnRemAddress

            itemvalues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.6.13.1.4");
            if (itemvalues != null)
            {
                foreach (var itemvalue in itemvalues)
                {
                    if (!dicTcpConn.ContainsKey(itemvalue.Key))
                    {
                        dicTcpConn.Add(itemvalue.Key, new TcpConnEntry());
                    }
                    dicTcpConn[itemvalue.Key].tcpConnRemAddress = itemvalue.Value.ToString();
                }
            }

            #endregion

            #region get tcpConnRemPort

            itemvalues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.6.13.1.5");
            if (itemvalues != null)
            {
                foreach (var itemvalue in itemvalues)
                {
                    if (!dicTcpConn.ContainsKey(itemvalue.Key))
                    {
                        dicTcpConn.Add(itemvalue.Key, new TcpConnEntry());
                    }
                    dicTcpConn[itemvalue.Key].tcpConnRemPort = (int)(itemvalue.Value as Integer32);
                }
            }

            #endregion

            tcp.tcpConnTable = dicTcpConn.Values.Where(t => t.tcpConnLocalAddress != "0.0.0.0" && t.tcpConnRemAddress != "0.0.0.0").ToList();

            return tcp;
        }

        private UdpSummary GetUdpSummary(string community, string ip, int port)
        {
            UdpSummary udp = new UdpSummary();

            #region get udp summary

            AgentParameters param = new AgentParameters(new OctetString(community));
            param.Version = SnmpVersion.Ver1;
            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                Pdu pdu = new Pdu(PduType.Get);
                pdu.VbList.Add(".1.3.6.1.2.1.7.1.0"); //udpInDatagrams
                pdu.VbList.Add(".1.3.6.1.2.1.7.2.0"); //udpNoPorts
                pdu.VbList.Add(".1.3.6.1.2.1.7.3.0"); //udpInErrors
                pdu.VbList.Add(".1.3.6.1.2.1.7.4.0"); //udpOutDatagrams
                
                SnmpV1Packet result = (SnmpV1Packet)target.Request(pdu, param);
                if (result != null)
                {
                    // ErrorStatus other then 0 is an error returned by 
                    // the Agent - see SnmpConstants for error definitions
                    if (result.Pdu.ErrorStatus != 0)
                    {
                        // agent reported an error with the request
                        WriteLine("Error in SNMP reply. Error {0} index {1}",
                            result.Pdu.ErrorStatus,
                            result.Pdu.ErrorIndex);
                    }
                    else
                    {
                        udp.udpInDatagrams = Convert.ToInt32(result.Pdu.VbList[0].Value.ToString());
                        udp.udpNoPorts = Convert.ToInt32(result.Pdu.VbList[1].Value.ToString());
                        udp.udpInErrors = Convert.ToInt32(result.Pdu.VbList[2].Value.ToString());
                        udp.udpOutDatagrams = Convert.ToInt32(result.Pdu.VbList[3].Value.ToString());
                    }
                }
                target.Close();
            }

            #endregion
            
            Dictionary<int, UdpConnEntry> dicUdpEntry = new Dictionary<int, UdpConnEntry>();
            Dictionary<int, AsnType> itemvalues = null;

            #region get tcpConnLocalAddress

            itemvalues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.7.5.1.1");
            if (itemvalues != null)
            {
                foreach (var itemvalue in itemvalues)
                {
                    if (!dicUdpEntry.ContainsKey(itemvalue.Key))
                    {
                        dicUdpEntry.Add(itemvalue.Key, new UdpConnEntry());
                    }
                    dicUdpEntry[itemvalue.Key].udpLocalAddress = itemvalue.Value.ToString();
                }
            }

            #endregion

            #region get tcpConnLocalPort

            itemvalues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.7.5.1.2");
            if (itemvalues != null)
            {
                foreach (var itemvalue in itemvalues)
                {
                    if (!dicUdpEntry.ContainsKey(itemvalue.Key))
                    {
                        dicUdpEntry.Add(itemvalue.Key, new UdpConnEntry());
                    }
                    dicUdpEntry[itemvalue.Key].udpLocalPort = (int)(itemvalue.Value as Integer32);
                }
            }

            #endregion

            udp.udpConnTable = dicUdpEntry.Values.Where(u => u.udpLocalAddress != "0.0.0.0").ToList();

            return udp;
        }

        private int GetSystemProcessCount(string community, string ip, int port)
        {
            AgentParameters param = new AgentParameters(new OctetString(community));
            param.Version = SnmpVersion.Ver1;
            using (UdpTarget target = new UdpTarget(IPAddress.Parse(ip), port, 2000, 1))
            {
                Pdu pdu = new Pdu(PduType.Get);
                pdu.VbList.Add(new Oid(".1.3.6.1.2.1.25.1.6.0"));
                SnmpV1Packet result = (SnmpV1Packet)target.Request(pdu, param);
                if (result != null)
                {
                    // ErrorStatus other then 0 is an error returned by 
                    // the Agent - see SnmpConstants for error definitions
                    if (result.Pdu.ErrorStatus != 0)
                    {
                        // agent reported an error with the request
                        WriteLine("Error in SNMP reply. Error {0} index {1}",
                            result.Pdu.ErrorStatus,
                            result.Pdu.ErrorIndex);
                    }
                    else
                    {
                        return Convert.ToInt32(result.Pdu.VbList[0].Value.ToString());
                    }
                }
            }
            return 0;
        }        

        private List<SystemProcess> GetSystemProcesses(string community, string ip, int port)
        {
            Dictionary<int, SystemProcess> dicProcess = new Dictionary<int, SystemProcess>();
            Dictionary<int, AsnType> dicValues = null;

            #region get process name

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.4.2.1.2");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicProcess.ContainsKey(v.Key))
                    {
                        dicProcess[v.Key] = new SystemProcess();
                    }
                    dicProcess[v.Key].hrSWRunName = v.Value.ToString();
                }
            }

            #endregion

            #region get process path

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.4.2.1.4");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicProcess.ContainsKey(v.Key))
                    {
                        dicProcess[v.Key] = new SystemProcess();
                    }
                    dicProcess[v.Key].hrSWRunPath = v.Value.ToString();
                }
            }

            #endregion

            #region get process parameters

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.4.2.1.5");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicProcess.ContainsKey(v.Key))
                    {
                        dicProcess[v.Key] = new SystemProcess();
                    }
                    dicProcess[v.Key].hrSWRunParameters = v.Value.ToString();
                }
            }

            #endregion

            #region get process type

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.4.2.1.6");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicProcess.ContainsKey(v.Key))
                    {
                        dicProcess[v.Key] = new SystemProcess();
                    }
                    dicProcess[v.Key].hrSWRunType = (HrSWType)(Convert.ToInt32(v.Value.ToString()));
                }
            }

            #endregion

            #region get process status

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.4.2.1.7");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicProcess.ContainsKey(v.Key))
                    {
                        dicProcess[v.Key] = new SystemProcess();
                    }
                    dicProcess[v.Key].hrSWRunStatus = (HrSWRunStatus)(Convert.ToInt32(v.Value.ToString()));
                }
            }

            #endregion

            #region get the number of centi-seconds of the total system's CPU resources consumed by process

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.5.1.1.1");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicProcess.ContainsKey(v.Key))
                    {
                        dicProcess[v.Key] = new SystemProcess();
                    }
                    dicProcess[v.Key].hrSWRunPerfCPU = Convert.ToInt32(v.Value.ToString());
                }
            }

            #endregion

            #region get The total amount of real system memory allocated to process.

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.5.1.1.2");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicProcess.ContainsKey(v.Key))
                    {
                        dicProcess[v.Key] = new SystemProcess();
                    }
                    dicProcess[v.Key].hrSWRunPerMem = Convert.ToInt32(v.Value.ToString());
                }
            }

            #endregion

            return dicProcess.Values.ToList();
        }

        private List<InstalledSoftWare> GetInstalledSoftWares(string community, string ip, int port)
        {
            Dictionary<int, InstalledSoftWare> dicSW = new Dictionary<int, InstalledSoftWare>();
            Dictionary<int, AsnType> dicValues = null;

            #region get installed sw name

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.6.3.1.2");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicSW.ContainsKey(v.Key))
                    {
                        dicSW[v.Key] = new InstalledSoftWare();
                    }
                    OctetString osValue = v.Value as OctetString;
                    if (osValue.IsHex)
                    {
                        dicSW[v.Key].hrSWInstalledName = HexToString(osValue.ToHexString(), Encoding.Default);
                    }
                    else
                    {
                        dicSW[v.Key].hrSWInstalledName = osValue.ToString();
                    }
                }
            }

            #endregion

            #region get installed sw type

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.6.3.1.4");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicSW.ContainsKey(v.Key))
                    {
                        dicSW[v.Key] = new InstalledSoftWare();
                    }
                    dicSW[v.Key].hrSWInstalledType = (HrSWType)(Convert.ToInt32(v.Value.ToString()));
                }
            }

            #endregion

            #region get installed sw last modify date

            dicValues = GetOidTreeItemValues(community, ip, port, ".1.3.6.1.2.1.25.6.3.1.5");
            if (dicValues != null && dicValues.Count > 0)
            {
                foreach (var v in dicValues)
                {
                    if (!dicSW.ContainsKey(v.Key))
                    {
                        dicSW[v.Key] = new InstalledSoftWare();
                    }                    
                    
                    dicSW[v.Key].hrSWInstalledDate = HexToDateTime(v.Value.ToString());
                }
            }

            #endregion

            return dicSW.Values.ToList();
        }

        private void muFixedDisk_Click(object sender, EventArgs e)
        {
            List<Storage> fixedDiskStorages = GetHrStorages("public", "127.0.0.1", 161, ".1.3.6.1.2.1.25.2.1.4");
            if (fixedDiskStorages == null || fixedDiskStorages.Count == 0)
            {
                WriteLine("No Fixed Disk found.");
            }
            else
            {
                WriteLine("Fixed Disk:");
                foreach (var storage in fixedDiskStorages)
                {
                    WriteLine("     {0}: Size({1}GB), Used({2}GB), Usage({3:0%})",
                        storage.descr,
                        (int)Math.Floor(storage.size * storage.allocationUnits / Math.Pow(1024, 3)),
                        (int)Math.Floor(storage.used * storage.allocationUnits / Math.Pow(1024, 3)),
                        storage.usage);
                }
                double total_size = fixedDiskStorages.Sum(d => d.size * d.allocationUnits);
                double total_used = fixedDiskStorages.Sum(d => d.used * d.allocationUnits);
                WriteLine("     Total Size({0}GB), Used({1}GB), Usage({2:0%})",
                    (int)Math.Floor(total_size / Math.Pow(1024, 3)),
                    (int)Math.Floor(total_used / Math.Pow(1024, 3)),
                    (total_size != 0 ? total_used / total_size : 0));
            }
            WriteLine("---------------------------------------------------------------------------");
        }

        private void muRam_Click(object sender, EventArgs e)
        {
            List<Storage> ramStorages = GetHrStorages("public", "127.0.0.1", 161, ".1.3.6.1.2.1.25.2.1.2");
            if (ramStorages == null || ramStorages.Count == 0)
            {
                WriteLine("No Physic Memory found.");
            }
            else
            {
                double total_size = ramStorages.Sum(d => d.size * d.allocationUnits);
                double total_used = ramStorages.Sum(d => d.used * d.allocationUnits);
                WriteLine("Physic Memory:");
                WriteLine("     Total Size({0}GB), Used({1}GB), Usage({2:0%})",
                    Math.Round(total_size / Math.Pow(1024, 3), 2),
                    Math.Round(total_used / Math.Pow(1024, 3), 2),
                    (total_size != 0 ? total_used / total_size : 0));
            }
            WriteLine("---------------------------------------------------------------------------");
        }

        private void muCpu_Click(object sender, EventArgs e)
        {
            Dictionary<Oid, int> cpuUsages = GetHrProcessorLoad("public", "127.0.0.1", 161);
            if (cpuUsages != null && cpuUsages.Count > 0)
            {
                WriteLine("CPU:");
                foreach (var kv in cpuUsages)
                {
                    WriteLine("     {0}: {1}%", kv.Key, kv.Value);
                }
            }
            else
            {
                WriteLine("No ProcessorLoad found.");
            }
            WriteLine("-------------------------------------------------------------");
        }

        private void muInterfaces_Click(object sender, EventArgs e)
        {
            List<Interfaces> ifObjList = GetInterfaces("public", "127.0.0.1", 161, 6, true); //get ethernet interfaces
            if (ifObjList != null && ifObjList.Count > 0)
            {
                WriteLine("Ethernet Interfaces:");
                foreach (var ifObj in ifObjList)
                {
                    WriteLine("     ifDescr({0}), MAC({1}), ifMtu({2}bytes), ifSpeed({3}bytes), Received({4}bytes), Send({5}bytes)",
                        ifObj.descr, ifObj.ifPhysAddress, ifObj.ifMtu, ifObj.ifSpeed, ifObj.ifInOctets, ifObj.ifOutOctets);
                }
            }
            else
            {
                WriteLine("No Interfaces found.");
            }
            WriteLine("-------------------------------------------------------------");
        }

        private void muTcp_Click(object sender, EventArgs e)
        {
            TcpSummary tcp = GetTcpSummary("public", "127.0.0.1", 161);
            WriteLine("Tcp Connection:");
            WriteLine("     tcpInSegs: {0}", tcp.tcpInSegs);
            WriteLine("     tcpOutSegs: {0}", tcp.tcpOutSegs);
            WriteLine("     tcpRetransSegs: {0}", tcp.tcpRetransSegs);
            WriteLine("     tcpCurrEstab: {0}", tcp.tcpCurrEstab);
            WriteLine("     tcpEstabResets: {0}", tcp.tcpEstabResets);
            WriteLine("     tcpActiveOpens: {0}", tcp.tcpActiveOpens);
            WriteLine("     tcpPassiveOpens: {0}", tcp.tcpPassiveOpens);
            WriteLine("     tcpAttemptFails: {0}", tcp.tcpAttemptFails);
            WriteLine("     tcpConnTable:");
            if (tcp.tcpConnTable != null && tcp.tcpConnTable.Count > 0)
            {
                foreach (var tcpConn in tcp.tcpConnTable)
                {
                    WriteLine("         tcpConnState({0}), tcpConnLocalAddress({1}), tcpConnLocalPort({2}), tcpConnRemAddress({3}), tcpConnRemPort({4})",
                        tcpConn.tcpConnState, tcpConn.tcpConnLocalAddress, tcpConn.tcpConnLocalPort, tcpConn.tcpConnRemAddress, tcpConn.tcpConnRemPort);
                }
            }
            else
            {
                WriteLine("         No tcpConnTable found.");
            }
            WriteLine("------------------------------------------------------------------------");
        }

        private void muUdp_Click(object sender, EventArgs e)
        {
            UdpSummary udp = GetUdpSummary("public", "127.0.0.1", 161);
            WriteLine("Udp Connection:");
            WriteLine("     udpInDatagrams: {0}", udp.udpInDatagrams);
            WriteLine("     udpOutDatagrams: {0}", udp.udpOutDatagrams);
            WriteLine("     udpNoPorts: {0}", udp.udpNoPorts);
            WriteLine("     udpInErrors: {0}", udp.udpInErrors);
            WriteLine("     udpConnTable:");
            if (udp.udpConnTable != null && udp.udpConnTable.Count > 0)
            {
                foreach (var udpConn in udp.udpConnTable)
                {
                    WriteLine("         udpLocalAddress({0}), udpLocalPort({1})",
                        udpConn.udpLocalAddress, udpConn.udpLocalPort);
                }
            }
            else
            {
                WriteLine("         No udpConnTable found.");
            }
            WriteLine("------------------------------------------------------------------------");
        }

        private void muProcess_Click(object sender, EventArgs e)
        {
            WriteLine("System Process:");
            int countProcess = GetSystemProcessCount("public", "127.0.0.1", 161);
            WriteLine("     Count:{0}", countProcess);            
            List<SystemProcess> procList = GetSystemProcesses("public", "127.0.0.1", 161);
            if (procList != null && procList.Count > 0)
            {
                foreach (var proc in procList)
                {
                    WriteLine("");
                    WriteLine("     Process Name:{0}", proc.hrSWRunName);
                    WriteLine("     Process Path:{0}", proc.hrSWRunPath);
                    WriteLine("     Process Parameters:{0}", proc.hrSWRunParameters);
                    WriteLine("     Process Type:{0}", proc.hrSWRunType);
                    WriteLine("     Process Status:{0}", proc.hrSWRunStatus);
                    WriteLine("     Process PerfCPU:{0}cs", proc.hrSWRunPerfCPU);
                    WriteLine("     Process PerfMem:{0}KBytes", proc.hrSWRunPerMem);
                }
            }
            else
            {
                WriteLine("     No process detail found.");
            }
            WriteLine("------------------------------------------------------------------------");
        }

        private void muSWInstalled_Click(object sender, EventArgs e)
        {
            WriteLine("Installed Software:");
            
            List<InstalledSoftWare> swList = GetInstalledSoftWares("public", "127.0.0.1", 161);
            if (swList != null && swList.Count > 0)
            {
                foreach (var sw in swList)
                {
                    WriteLine("");
                    WriteLine("     Software Name:{0}", sw.hrSWInstalledName);
                    WriteLine("     Software Type:{0}", sw.hrSWInstalledType);
                    WriteLine("     Software LastDate:{0:yyyy-MM-dd HH:mm:ss}", sw.hrSWInstalledDate);
                }
            }
            else
            {
                WriteLine("     No installed software found.");
            }
            WriteLine("------------------------------------------------------------------------");
        }
    }

    public abstract class SnmpObject
    {
        public Oid oid { get; set; }
        public string descr { get; set; }
    }

    public class Storage : SnmpObject
    {
        public Storage()
        {

        }

        public Storage(Oid oid)
        {
            this.oid = oid;
        }

        public int allocationUnits { get; set; } //每箸/块的大小
        public double size { get; set; } //箸/块总数
        public double used { get; set; } //已使用的箸/块个数
        public double usage //使用率
        {
            get
            {
                return (this.size != 0 && this.allocationUnits != 0)
                    ? this.used / this.size
                    : 0;
            }
        }
    }

    public class Interfaces : SnmpObject
    {
        public int ifType { get; set; } //端口类型
        public int ifMtu { get; set; } //最大传输包字节数
        public int ifSpeed { get; set; } //端口速度
        public string ifPhysAddress { get; set; } //MAC地址
        public long ifInOctets { get; set; } //输入字节数        
        public long ifOutOctets { get; set; } //输出字节数        
    }

    public enum TcpConnState
    {
        closed = 1,
        listen = 2,
        synSent = 3,
        synReceived = 4,
        established = 5,
        finWait1 = 6,
        finWait2 = 7,
        closeWait = 8,
        lastAck = 9,
        closing = 10,
        timeWait = 11,
        deleteTCB = 12
    }

    public class TcpConnEntry
    {
        public TcpConnState tcpConnState { get; set; }
        public string tcpConnLocalAddress { get; set; }
        public int tcpConnLocalPort { get; set; }
        public string tcpConnRemAddress { get; set; }
        public int tcpConnRemPort { get; set; }
    }

    public class TcpSummary
    {
        public int tcpInSegs { get; set; } //接收的数据段个数
        public int tcpOutSegs { get; set; } //发送的数据段个数
        public int tcpRetransSegs { get; set; } //重新传输的数据段个数
        public int tcpCurrEstab { get; set; } //当前连接数
        public int tcpEstabResets { get; set; } //重置连接数
        public int tcpActiveOpens { get; set; } //主动开放数
        public int tcpPassiveOpens { get; set; } //被动开放数
        public int tcpAttemptFails { get; set; } //失败的连接尝试次数
        public List<TcpConnEntry> tcpConnTable {get;set;}
    }

    public class UdpConnEntry
    {
        public string udpLocalAddress { get; set; }
        public int udpLocalPort { get; set; }
    }

    public class UdpSummary
    {
        public int udpInDatagrams { get; set; } //接收的数据包个数
        public int udpNoPorts { get; set; } //无端口数
        public int udpInErrors { get; set; } //接收错误数
        public int udpOutDatagrams { get; set; } //发送的数据包个数
        public List<UdpConnEntry> udpConnTable { get; set; }
    }

    public enum HrSWType
    {
        unknown = 1,
        operatingSystem = 2,
        deviceDriver = 3,
        application = 4
    }

    public enum HrSWRunStatus
    {
        running = 1,
        runnable = 2,
        notRunnable = 3,
        invalid = 4
    }
    
    public class SystemProcess
    {
        public string hrSWRunName { get; set; }
        public string hrSWRunPath { get; set; }
        public string hrSWRunParameters { get; set; }
        public HrSWType hrSWRunType { get; set; }
        public HrSWRunStatus hrSWRunStatus { get; set; }
        public int hrSWRunPerfCPU { get; set; } //进程从开始运行总共用了多少厘秒(百分之一秒)的CPU
        public int hrSWRunPerMem { get; set; } //进程被分配的内存大小（KBytes）
    }

    public class InstalledSoftWare
    {
        public string hrSWInstalledName { get; set; }
        public HrSWType hrSWInstalledType { get; set; } //The type of this software.
        public DateTime hrSWInstalledDate { get; set; } //The last-modification date of this application as it would appear in a directory listing.
    }
}
