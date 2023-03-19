using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SnmpTrap.Lib
{
    public class EventLogTrapMessage
    {
        public Guid? ActivityId { get; set; }
        public string ContainerLog { get; set; }
        public int Id { get; set; }
        public byte? Level { get; set; }
        public string LevelDisplayName { get; set; }
        public string LogName { get; set; }
        public string MachineName { get; set; }
        public int? ProcessId { get; set; }
        public List<string> Properites { get; set; }
        public Guid? ProviderId { get; set; }
        public string ProviderName { get; set; }
        public long? RecordId { get; set; }
        public Guid? RelatedActivityId { get; set; }
        public DateTime? TimeCreated { get; set; }
        public byte? Version { get; set; }

        public string Serialize()
        {
            string propString = string.Empty;
            if (this.Properites != null && this.Properites.Count > 0)
            {
                foreach (object p in this.Properites)
                {
                    propString += String.Format("{0}|", p);
                }
                propString = propString.TrimEnd('|');
            }
            string msg = String.Format("TRAPEVNTBEGIN;{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10};"
                + "{11};{12};{13};{14};TRAPEVNTEND",
                this.ActivityId.GetValueOrDefault(),
                this.ContainerLog,
                this.Id,
                this.Level.GetValueOrDefault(),
                this.LevelDisplayName,
                this.LogName,
                this.MachineName,
                this.ProcessId,
                propString,
                this.ProviderId.GetValueOrDefault(),
                this.ProviderName,
                this.RecordId.GetValueOrDefault(),
                this.RelatedActivityId.GetValueOrDefault(),
                this.TimeCreated.GetValueOrDefault(),
                this.Version.GetValueOrDefault());

            return msg;
        }

        public static EventLogTrapMessage DeSerialize(string serializeString)
        {
            if (String.IsNullOrEmpty(serializeString))
            {
                return null;
            }
            string[] s = serializeString.Split(';');
            if (s == null || s.Length != 17)
            {
                return null;
            }
            if (!s[0].Equals("TRAPEVNTBEGIN", StringComparison.OrdinalIgnoreCase) 
             && !s[s.Length - 1].Equals("TRAPEVNTEND", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            EventLogTrapMessage msg = new EventLogTrapMessage();
            if (!String.IsNullOrEmpty(s[1]) && !s[1].Equals("Null", StringComparison.OrdinalIgnoreCase))
            {
                msg.ActivityId = Guid.Parse(s[1]);
            }
            if (!String.IsNullOrEmpty(s[2]))
            {
                msg.ContainerLog = s[2];
            }
            if (!String.IsNullOrEmpty(s[3]))
            {
                msg.Id = Convert.ToInt32(s[3]);
            }
            if (!String.IsNullOrEmpty(s[4]) && !s[4].Equals("Null", StringComparison.OrdinalIgnoreCase))
            {
                msg.Level = Convert.ToByte(s[4]);
            }
            if (!String.IsNullOrEmpty(s[5]))
            {
                msg.LevelDisplayName = s[5];
            }
            if (!String.IsNullOrEmpty(s[6]))
            {
                msg.LogName = s[6];
            }
            if (!String.IsNullOrEmpty(s[7]))
            {
                msg.MachineName = s[7];
            }
            if (!String.IsNullOrEmpty(s[8]) && !s[8].Equals("Null", StringComparison.OrdinalIgnoreCase))
            {
                msg.ProcessId = Convert.ToInt32(s[8]);
            }
            if (!String.IsNullOrEmpty(s[9]))
            {
                string[] p = s[9].Split('|');
                msg.Properites = new List<string>();
                foreach (string v in p)
                {
                    msg.Properites.Add(v);
                }
            }
            if (!String.IsNullOrEmpty(s[10]) && !s[10].Equals("Null", StringComparison.OrdinalIgnoreCase))
            {
                msg.ProviderId = Guid.Parse(s[10]);
            }
            if (!String.IsNullOrEmpty(s[11]))
            {
                msg.ProviderName = s[11];
            }
            if (!String.IsNullOrEmpty(s[12]) && !s[12].Equals("Null", StringComparison.OrdinalIgnoreCase))
            {
                msg.RecordId = Convert.ToInt64(s[12]);
            }
            if (!String.IsNullOrEmpty(s[13]) && !s[13].Equals("Null", StringComparison.OrdinalIgnoreCase))
            {
                msg.RelatedActivityId = Guid.Parse(s[13]);
            }
            if (!String.IsNullOrEmpty(s[14]) && !s[14].Equals("Null", StringComparison.OrdinalIgnoreCase))
            {
                msg.TimeCreated = DateTime.Parse(s[14]);
            }
            if (!String.IsNullOrEmpty(s[15]) && !s[15].Equals("Null", StringComparison.OrdinalIgnoreCase))
            {
                msg.Version = Convert.ToByte(s[15]);
            }
            return msg;
        }
    }
}
