using System.Windows;
using System.Windows.Media.Imaging;

namespace Opcodex;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnLastWindowClose;
        Resources["AppLogo"] = LoadAppLogo();

        var splash = new SplashWindow();
        splash.Show();
        await Task.Delay(TimeSpan.FromSeconds(2));

        var main = new MainWindow();
        MainWindow = main;
        main.Show();
        splash.Close();
    }

    static BitmapFrame LoadAppLogo()
    {
        var decoder = new IconBitmapDecoder(
            new Uri("pack://application:,,,/newlogo/opcodex.ico", UriKind.Absolute),
            BitmapCreateOptions.PreservePixelFormat,
            BitmapCacheOption.OnLoad);
        var frame = decoder.Frames
            .OrderBy(item => Math.Abs(item.PixelWidth - 48) + Math.Abs(item.PixelHeight - 48))
            .First();
        if (frame.CanFreeze)
            frame.Freeze();
        return frame;
    }
}
