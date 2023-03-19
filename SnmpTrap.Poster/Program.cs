using SnmpSharpNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics.Eventing.Reader;
using SnmpTrap.Lib;

namespace SnmpTrap.Poster
{
    class Program
    {
        private const string EVENTLOG_WTS_SOURCE = "Microsoft-Windows-TerminalServices-LocalSessionManager";
        private const string EVENTLOG_WTS_PATH = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

        private const string MS_ENTERPRISE_OID = "1.3.6.1.4.1.311.1.13.1";

        static void Main(string[] args)
        {
            using (EventLogWatcher elw = new EventLogWatcher(EVENTLOG_WTS_PATH))
            {
                elw.EventRecordWritten += elw_EventRecordWritten;
                elw.Enabled = true;
                Console.Read();
            }
        }

        static void elw_EventRecordWritten(object sender, EventRecordWrittenEventArgs e)
        {
            int eventlog_source_length = EVENTLOG_WTS_SOURCE.Length;
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("{0}.{1}", MS_ENTERPRISE_OID, eventlog_source_length);
            foreach (char c in EVENTLOG_WTS_SOURCE)
            {
                sb.AppendFormat(".{0}", (int)c);
            }

            EventLogTrapMessage msg = GetTrapMessage(e.EventRecord);

            TrapAgent agent = new TrapAgent();
            VbCollection col = new VbCollection();
            
            col.Add(new Oid(sb.ToString()), new OctetString(msg.Serialize()));

            agent.SendV2Trap(new IpAddress("127.0.0.1"), 162, "public", 13433,
                new Oid(".1.3.6.1.6.3.1.1.5"), col);
        }

        static EventLogTrapMessage GetTrapMessage(EventRecord rec)
        {
            EventLogRecord elrec = rec as EventLogRecord;
            EventLogTrapMessage msg = new EventLogTrapMessage()
            {
                ActivityId = elrec.ActivityId,
                ContainerLog = elrec.ContainerLog,
                Id = elrec.Id,
                Level = elrec.Level,
                LevelDisplayName = elrec.LevelDisplayName,
                LogName = elrec.LogName,
                MachineName = elrec.MachineName,
                ProcessId = elrec.ProcessId,
                Properites = elrec.Properties != null ? elrec.Properties.Select(p => p.Value.ToString()).ToList() : null,
                ProviderId = elrec.ProviderId,
                ProviderName = elrec.ProviderName,
                RecordId = elrec.RecordId,
                RelatedActivityId = elrec.RelatedActivityId,
                TimeCreated = elrec.TimeCreated,
                Version = elrec.Version
            };
            return msg;
        }
    }
}
