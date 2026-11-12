using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;

namespace OpenDrop.Windows;

// Packaged desktop activation, NOT the UWP OnShareTargetActivated override.
public partial class App : Application
{
    private Window? _window;

    public App() { InitializeComponent(); }

    protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
    {
        _window = new Window();
        var panel = new StackPanel { Spacing = 12, Padding = new Thickness(24) };
        panel.Children.Add(new TextBlock
        {
            Text = "OpenDrop Nearby integration is under development.",
            TextWrapping = TextWrapping.Wrap
        });
        _window.Content = panel;
        _window.Activate();

        AppActivationArguments activation = AppInstance.GetCurrent().GetActivatedEventArgs();
        if (activation.Kind == ExtendedActivationKind.ShareTarget &&
            activation.Data is ShareTargetActivatedEventArgs share)
        {
            // No fake transfer success: the native contract is kept alive
            // until real source data has been copied or an error is reported.
            _ = ShareTargetIngress.ReadOneFileAsync(share.ShareOperation, panel);
        }
    }
}
