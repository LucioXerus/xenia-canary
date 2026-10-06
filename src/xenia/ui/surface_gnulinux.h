/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#ifndef XENIA_UI_SURFACE_GNULINUX_H_
#define XENIA_UI_SURFACE_GNULINUX_H_

#include <xcb/xcb.h>

#include "xenia/ui/surface.h"

// Forward declarations of Wayland types (global namespace, as declared by
// wayland-client.h) to avoid including Wayland headers here - the actual wl_*
// calls are made by the window implementation opening this surface.
struct wl_display;
struct wl_subsurface;
struct wl_surface;

namespace xe {
namespace ui {

class XcbWindowSurface final : public Surface {
 public:
  explicit XcbWindowSurface(xcb_connection_t* connection, xcb_window_t window)
      : connection_(connection), window_(window) {}
  TypeIndex GetType() const override { return kTypeIndex_XcbWindow; }
  xcb_connection_t* connection() const { return connection_; }
  xcb_window_t window() const { return window_; }

 protected:
  bool GetSizeImpl(uint32_t& width_out, uint32_t& height_out) const override;

 private:
  xcb_connection_t* connection_;
  xcb_window_t window_;
};

class WaylandSurface final : public Surface {
 public:
  // Takes ownership of surface and subsurface (both destroyed with this
  // object, on the UI thread). Either may be null if creation failed, in
  // which case this surface is unusable.
  WaylandSurface(wl_display* display, wl_surface* surface,
                 wl_subsurface* subsurface, uint32_t width, uint32_t height)
      : display_(display),
        surface_(surface),
        subsurface_(subsurface),
        width_(width),
        height_(height) {}
  ~WaylandSurface() override;
  TypeIndex GetType() const override { return kTypeIndex_WaylandSurface; }
  wl_display* display() const { return display_; }
  wl_surface* surface() const { return surface_; }

 protected:
  bool GetSizeImpl(uint32_t& width_out, uint32_t& height_out) const override;

 private:
  wl_display* display_;
  wl_surface* surface_;
  wl_subsurface* subsurface_;
  uint32_t width_;
  uint32_t height_;
};

}  // namespace ui
}  // namespace xe

#endif  // XENIA_UI_SURFACE_LINUX_H_
