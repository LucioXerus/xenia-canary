/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/ui/surface_gnulinux_wayland.h"

#include <gtk/gtk.h>

namespace xe {
namespace ui {

WaylandWindowSurface::WaylandWindowSurface(wl_display* display,
                                           wl_surface* surface,
                                           GtkWidget* drawing_area)
    : display_(display), surface_(surface), drawing_area_(drawing_area) {
  if (drawing_area_) {
    GtkAllocation allocation;
    gtk_widget_get_allocation(drawing_area_, &allocation);
    width_.store(allocation.width);
    height_.store(allocation.height);
  }
}

void WaylandWindowSurface::OnSizeUpdate(uint32_t width, uint32_t height) {
  width_.store(width);
  height_.store(height);
}

bool WaylandWindowSurface::GetSizeImpl(uint32_t& width_out,
                                       uint32_t& height_out) const {
  uint32_t width = width_.load();
  uint32_t height = height_.load();

  if (!width || !height) {
    return false;
  }

  width_out = width;
  height_out = height;
  return true;
}

}  // namespace ui
}  // namespace xe
