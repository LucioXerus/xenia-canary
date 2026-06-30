/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2025 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/ui/file_picker.h"

#include <string>

#include <gtk/gtk.h>

#include "xenia/base/assert.h"
#include "xenia/base/filesystem.h"
#include "xenia/base/logging.h"
#include "xenia/base/platform_linux.h"
#include "xenia/base/string.h"
#include "xenia/ui/window_gtk.h"

namespace xe {
namespace ui {

class GtkFilePicker : public FilePicker {
 public:
  GtkFilePicker();
  ~GtkFilePicker() override;

  bool Show(Window* parent_window) override;

 private:
};

std::unique_ptr<FilePicker> FilePicker::Create() {
  return std::make_unique<GtkFilePicker>();
}

GtkFilePicker::GtkFilePicker() = default;

GtkFilePicker::~GtkFilePicker() = default;

bool GtkFilePicker::Show(Window* parent_window) {
  std::string title;
  GtkFileChooserAction action;
  std::string confirm_button;
  switch (mode()) {
    case Mode::kOpen:
      title = type() == Type::kFile ? "Open File" : "Open Directory";
      action = type() == Type::kFile ? GTK_FILE_CHOOSER_ACTION_OPEN
                                     : GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER;
      confirm_button = "_Open";
      break;
    case Mode::kSave:
      title = "Save File";
      action = GTK_FILE_CHOOSER_ACTION_SAVE;
      confirm_button = "_Save";
      break;
    default:
      XELOGE("GtkFilePicker::Show: Unhandled mode: {}, Type: {}",
             static_cast<int>(mode()), static_cast<int>(type()));
      assert_always();
  }
  GtkWidget* dialog = gtk_file_chooser_dialog_new(
      title.c_str(),
      parent_window
          ? GTK_WINDOW(dynamic_cast<const GTKWindow*>(parent_window)->window())
          : nullptr,
      action, "_Cancel", GTK_RESPONSE_CANCEL, confirm_button.c_str(),
      GTK_RESPONSE_ACCEPT, NULL);

  gtk_file_chooser_set_local_only(GTK_FILE_CHOOSER(dialog), TRUE);
  const gchar* home_dir = g_get_home_dir();
  if (home_dir) {
    gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), home_dir);
  }

  gtk_widget_show(dialog);

  gint res = GTK_RESPONSE_NONE;
  g_signal_connect(dialog, "response",
                   G_CALLBACK(+[](GtkDialog*, gint response, gpointer data) {
                     *(static_cast<gint*>(data)) = response;
                   }),
                   &res);

  while (res == GTK_RESPONSE_NONE) {
    g_main_context_iteration(nullptr, TRUE);
  }

  char* filename;
  if (res == GTK_RESPONSE_ACCEPT) {
    GtkFileChooser* chooser = GTK_FILE_CHOOSER(dialog);
    filename = gtk_file_chooser_get_filename(chooser);
    std::vector<std::filesystem::path> selected_files;
    selected_files.push_back(xe::to_path(std::string(filename)));
    set_selected_files(selected_files);
    gtk_widget_destroy(dialog);
    return true;
  }
  gtk_widget_destroy(dialog);
  return false;
}

}  // namespace ui
}  // namespace xe
