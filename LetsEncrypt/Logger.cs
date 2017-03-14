using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace JayKayDesign.MailEnable.LetsEncrypt
{
    internal class Logger : ILog
    {
        private readonly string eventSource = "LetsEncrypt Mailenable";
        private readonly string logTarget = "Application";
        private readonly Dictionary<LogLevel, EventLogEntryType> levelMap = new Dictionary<LogLevel, EventLogEntryType>() {
            { LogLevel.None, EventLogEntryType.Information },
            { LogLevel.Information, EventLogEntryType.Information },
            { LogLevel.Error, EventLogEntryType.Warning },
            { LogLevel.Fatal, EventLogEntryType.Error },
            };

        private bool logToConsole;

        public Logger(bool logToConsole = false)
        {
            if (!EventLog.SourceExists(eventSource))
            {
                EventLog.CreateEventSource(eventSource, logTarget);
            }
            this.logToConsole = logToConsole;
        }

        public void Log(LogLevel level, object message)
        {
            if (logToConsole)
            {
                Console.WriteLine(level.ToString() + ": " + message.ToString());
            }
            else
            {
                EventLog.WriteEntry(eventSource, message.ToString(), levelMap[level]);
            }
        }
    }
}

