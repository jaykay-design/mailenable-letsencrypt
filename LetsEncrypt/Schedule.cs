using Microsoft.Win32.TaskScheduler;
using System;
using System.Linq;
using System.Reflection;

namespace JayKayDesign.MailEnable.LetsEncrypt
{
    internal static class Schedule
    {
        internal static void ScheduleTask(string taskName, short dayIntervall)
        {
            using (TaskService ts = new TaskService())
            {
                Task task = ts.AllTasks.FirstOrDefault(t => t.Name == taskName);
                if (task == null)
                {
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
                    task.Definition.Triggers.First().StartBoundary = DateTime.Now.AddDays(dayIntervall);
                    task.RegisterChanges();
                }
            }
        }
    }
}
