using System.Threading.Tasks;
using System.Windows;

namespace TestCryption
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            SplashWindow splash = new SplashWindow();
            splash.Show();

            await Task.Delay(2500);

            MainWindow main = new MainWindow();
            splash.Close();
            this.MainWindow = main;
            main.Show();
        }
    }
}
