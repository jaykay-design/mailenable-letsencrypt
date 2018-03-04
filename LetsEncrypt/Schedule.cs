namespace JayKayDesign.MailEnable.LetsEncrypt
{
    using Microsoft.Win32.TaskScheduler;
    using NLog;
    using System;
    using System.Linq;
    using System.Reflection;

    internal static class Schedule
    {
        private static Logger logger = LogManager.GetLogger("Schedule");

        internal static void ScheduleTask(string taskName, short dayIntervall)
        {
            using (TaskService ts = new TaskService())
            {
                Task task = ts.AllTasks.FirstOrDefault(t => t.Name == taskName);
                if (task == null)
                {
                    logger.Info("Adding scheduled task to renew certificate every {0} days", dayIntervall);

                    string appPath = Assembly.GetExecutingAssembly().CodeBase.Replace("file:///", string.Empty).Replace("/", "\\");

                    TaskDefinition td = ts.NewTask();
                    td.RegistrationInfo.Description = "Refreshes the SSL certificate from LetsEncrypt for Mailenable";
                    td.Settings.MultipleInstances = TaskInstancesPolicy.IgnoreNew;
                    td.Settings.StartWhenAvailable = true;
                    td.Triggers.Add(new DailyTrigger { DaysInterval = dayIntervall });
                    td.Actions.Add(new ExecAction(appPath));

                    ts.RootFolder.RegisterTaskDefinition(
                        taskName,
                        td,
                         TaskCreation.Create,
                         "SYSTEM",
                         null,
                         TaskLogonType.ServiceAccount);
                }
                else
                {
                    logger.Debug("Updating scheduled task to renew certificate every {0} days", dayIntervall);

                    task.Definition.Triggers.First().StartBoundary = DateTime.Now.AddDays(dayIntervall);
                    task.RegisterChanges();
                }
            }
        }
    }
}
