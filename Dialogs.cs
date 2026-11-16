using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Shell;
using WPath = System.Windows.Shapes.Path;

namespace Opcodex;

public class ChromeWindow : Window
{
    readonly Border _root = new();
    readonly ContentPresenter _body = new();
    readonly WPath _maxIcon;
    public bool CloseOnEscape;

    public object Body { get => _body.Content; set => _body.Content = value; }

    static Brush Res(string key) => (Brush)Application.Current.FindResource(key);
    static Style Sty(string key) => (Style)Application.Current.FindResource(key);

    public ChromeWindow(string title, bool resizable = false)
    {
        Title = title;
        Icon = (ImageSource)Application.Current.FindResource("AppLogo");
        WindowStyle = WindowStyle.None;
        ResizeMode = resizable ? ResizeMode.CanResize : ResizeMode.NoResize;
        MinWidth = resizable ? 500 : 320;
        MinHeight = resizable ? 300 : 120;
        ShowInTaskbar = false;
        Background = Res("Bg1");
        Foreground = Res("Fg");
        FontFamily = new FontFamily("Segoe UI");
        FontSize = 12;
        WindowChrome.SetWindowChrome(this, new WindowChrome
        {
            CaptionHeight = 34,
            ResizeBorderThickness = resizable ? new Thickness(6) : new Thickness(0),
            GlassFrameThickness = new Thickness(0),
            CornerRadius = new CornerRadius(0),
            UseAeroCaptionButtons = false,
        });

        var bar = new Grid { Height = 34, Background = Res("Bg1") };
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        bar.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var text = new TextBlock { HorizontalAlignment = HorizontalAlignment.Stretch, VerticalAlignment = VerticalAlignment.Center, TextAlignment = TextAlignment.Center, Foreground = Res("Muted"), IsHitTestVisible = false, TextTrimming = TextTrimming.CharacterEllipsis };
        text.SetBinding(TextBlock.TextProperty, new Binding("Title") { Source = this });
        Grid.SetColumn(text, 0);
        Grid.SetColumnSpan(text, 2);
        bar.Children.Add(text);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal };
        WindowChrome.SetIsHitTestVisibleInChrome(buttons, true);

        if (resizable)
        {
            buttons.Children.Add(CapBtn("CaptionBtn", "M0,5 H10", (_, _) => WindowState = WindowState.Minimized, out _));
            buttons.Children.Add(CapBtn("CaptionBtn", "M0.5,0.5 H9.5 V9.5 H0.5 Z",
                (_, _) => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized, out _maxIcon));
        }

        buttons.Children.Add(CapBtn("CloseBtn", "M0,0 L10,10 M10,0 L0,10", (_, _) => Close(), out _));
        Grid.SetColumn(buttons, 1);
        bar.Children.Add(buttons);

        var dock = new DockPanel();
        DockPanel.SetDock(bar, Dock.Top);
        dock.Children.Add(bar);
        dock.Children.Add(_body);

        _root.BorderThickness = new Thickness(1);
        _root.BorderBrush = Res("Accent");
        _root.Child = dock;
        Content = _root;

        Activated += (_, _) => _root.BorderBrush = Res("Accent");
        Deactivated += (_, _) => _root.BorderBrush = Res("Line");

        StateChanged += (_, _) =>
        {
            bool max = WindowState == WindowState.Maximized;
            BorderThickness = max ? SystemParameters.WindowResizeBorderThickness : new Thickness(0);
            if (_maxIcon != null) _maxIcon.Data = Geometry.Parse(max ? "M2.5,0.5 H9.5 V7.5 M0.5,2.5 H7.5 V9.5 H0.5 Z" : "M0.5,0.5 H9.5 V9.5 H0.5 Z");
        };

        PreviewKeyDown += (_, e) => { if (CloseOnEscape && e.Key == Key.Escape) { e.Handled = true; Close(); } };
    }

    static Button CapBtn(string style, string data, RoutedEventHandler click, out WPath path)
    {
        path = new WPath { Data = Geometry.Parse(data), StrokeThickness = 1, Width = 10, Height = 10, Stretch = Stretch.None, SnapsToDevicePixels = true };
        path.SetBinding(Shape.StrokeProperty, new Binding("Foreground") { RelativeSource = new RelativeSource(RelativeSourceMode.FindAncestor, typeof(Button), 1) });
        var b = new Button { Style = Sty(style), Content = path };
        b.Click += click;
        return b;
    }
}

public static class Dlg
{
    public static MessageBoxResult Show(Window owner, string text, string title,
        MessageBoxButton buttons = MessageBoxButton.OK, MessageBoxImage icon = MessageBoxImage.None)
    {
        var w = new ChromeWindow(title)
        {
            Width = 460, SizeToContent = SizeToContent.Height, WindowStartupLocation = WindowStartupLocation.CenterScreen,
        };
        if (owner != null && owner.IsLoaded) { w.Owner = owner; w.WindowStartupLocation = WindowStartupLocation.CenterOwner; }

        MessageBoxResult result = buttons switch
        {
            MessageBoxButton.OK => MessageBoxResult.OK,
            MessageBoxButton.OKCancel => MessageBoxResult.Cancel,
            MessageBoxButton.YesNo => MessageBoxResult.No,
            _ => MessageBoxResult.Cancel,
        };

        var row = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        void AddBtn(string label, MessageBoxResult r, bool isDefault)
        {
            var b = new Button { Content = label, Width = 80, IsDefault = isDefault, Margin = new Thickness(6, 0, 0, 0) };
            b.Click += (_, _) => { result = r; w.Close(); };
            row.Children.Add(b);
        }
        switch (buttons)
        {
            case MessageBoxButton.OK: AddBtn("OK", MessageBoxResult.OK, true); break;
            case MessageBoxButton.OKCancel: AddBtn("OK", MessageBoxResult.OK, true); AddBtn("Cancel", MessageBoxResult.Cancel, false); break;
            case MessageBoxButton.YesNo: AddBtn("Yes", MessageBoxResult.Yes, true); AddBtn("No", MessageBoxResult.No, false); break;
            default: AddBtn("Yes", MessageBoxResult.Yes, true); AddBtn("No", MessageBoxResult.No, false); AddBtn("Cancel", MessageBoxResult.Cancel, false); break;
        }

        var grid = new Grid { Margin = new Thickness(18) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        string glyph = null, color = null;
        switch (icon)
        {
            case MessageBoxImage.Error: glyph = "\u2715"; color = "#F44747"; break;
            case MessageBoxImage.Warning: glyph = "!"; color = "#CCA700"; break;
            case MessageBoxImage.Question: glyph = "?"; color = "#007ACC"; break;
            case MessageBoxImage.Information: glyph = "i"; color = "#4FC1FF"; break;
        }
        if (glyph != null)
        {
            var badge = new Border
            {
                Width = 30, Height = 30, CornerRadius = new CornerRadius(15), Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Top,
                Background = (Brush)new BrushConverter().ConvertFrom(color),
                Child = new TextBlock { Text = glyph, Foreground = Brushes.White, FontWeight = FontWeights.Bold, FontSize = 16, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
            };
            grid.Children.Add(badge);
        }
        var msg = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center, MinHeight = 30 };
        Grid.SetColumn(msg, 1);
        Grid.SetRow(row, 1); Grid.SetColumnSpan(row, 2);
        grid.Children.Add(msg); grid.Children.Add(row);

        w.Body = grid;
        w.PreviewKeyDown += (_, e) => { if (e.Key == Key.Escape) { e.Handled = true; w.Close(); } };
        w.ShowDialog();
        return result;
    }
}
