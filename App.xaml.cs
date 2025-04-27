using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace TestCryption
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override async void OnStartup(StartupEventArgs e) // Make method async for Task.Delay
        {
            base.OnStartup(e);

            // 1. Create and show the splash screen
            SplashWindow splash = new SplashWindow();
            splash.Show();

            // --- Optional Delay ---
            // Add a small artificial delay if MainWindow loads too fast
            // to ensure the splash screen is visible for a minimum duration.
            // Remove or adjust this value as needed.
            await Task.Delay(1500); // Wait 1.5 seconds (adjust as needed)
            // --------------------

            // 2. Create the main window (this loads its resources, etc.)
            MainWindow main = new MainWindow();

            // 3. Close the splash screen
            splash.Close();

            // --- Alternative Delay (using Thread.Sleep) ---
            // If you don't want to make OnStartup async, use Thread.Sleep
            // but be aware it blocks the UI thread briefly.
            // System.Threading.Thread.Sleep(1500);
            // -------------------------------------------

            // 4. Show the main window
            // Optionally set the MainWindow property for the application
            this.MainWindow = main;
            main.Show();
        }
    }
}
