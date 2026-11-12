using System;
using System.Threading.Tasks;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using Windows.ApplicationModel.DataTransfer.ShareTarget;
using Windows.Storage;

namespace OpenDrop.Windows;

internal static class ShareTargetIngress
{
    // This is only the real OS entry point and source-grant lifetime handler.
    // It does not send to another device or report a peer transfer completed.
    internal static async Task ReadOneFileAsync(ShareOperation operation, StackPanel panel)
    {
        operation.ReportStarted();
        try
        {
            if (!operation.Data.Contains(StandardDataFormats.StorageItems))
            {
                operation.ReportError("OpenDrop requires a file share in this early build.");
                return;
            }

            var items = await operation.Data.GetStorageItemsAsync();
            if (items.Count != 1 || items[0] is not IStorageFile file)
            {
                operation.ReportError("Select one file to share with OpenDrop.");
                return;
            }

            // A real granted file is available here; never treat a displayed
            // name as an arbitrary path. Do not mark DataRetrieved until a
            // later approved persistent outgoing queue owns its bytes.
            var properties = await file.GetBasicPropertiesAsync();
            panel.Children.Add(new TextBlock
            {
                Text = $"Selected: {file.Name} ({properties.Size} bytes)."
            });
            operation.ReportError("OpenDrop transfer service is not connected in P1-A.");
        }
        catch (Exception)
        {
            operation.ReportError("Unable to open the shared file. Please try again.");
        }
    }
}
