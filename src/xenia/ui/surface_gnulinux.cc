/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/ui/surface_gnulinux.h"

#include <wayland-client.h>
#include <cstdlib>

namespace xe {
namespace ui {

bool XcbWindowSurface::GetSizeImpl(uint32_t& width_out,
                                   uint32_t& height_out) const {
  xcb_get_geometry_reply_t* reply = xcb_get_geometry_reply(
      connection_, xcb_get_geometry(connection_, window_), nullptr);
  if (!reply) {
    return false;
  }
  width_out = reply->width;
  height_out = reply->height;
  std::free(reply);
  return true;
}

bool WaylandSurface::GetSizeImpl(uint32_t& width_out,
                                 uint32_t& height_out) const {
  // The Wayland protocol has no request for querying a surface's size - the
  // size tracked from the GTK drawing area allocation when this surface was
  // opened (and refreshed by reopening the surface on resizes) is
  // authoritative.
  width_out = width_;
  height_out = height_;
  return true;
}

WaylandSurface::~WaylandSurface() {
  // Surface methods are only ever called from the UI thread, which owns the
  // Wayland connection, so destroying the proxies here is safe.
  if (subsurface_) {
    wl_subsurface_destroy(subsurface_);
  }
  if (surface_) {
    wl_surface_destroy(surface_);
  }
}

}  // namespace ui
}  // namespace xe
