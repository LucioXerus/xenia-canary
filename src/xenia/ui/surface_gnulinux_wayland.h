/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#ifndef XENIA_UI_SURFACE_GNULINUX_WAYLAND_H_
#define XENIA_UI_SURFACE_GNULINUX_WAYLAND_H_

#include <atomic>
#include <cstdint>

#include <wayland-client.h>

#include "xenia/ui/surface.h"

namespace xe {
namespace ui {

class WaylandWindowSurface final : public Surface {
 public:
  WaylandWindowSurface(wl_display* display, wl_surface* surface,
                       uint32_t initial_width, uint32_t initial_height);
  TypeIndex GetType() const override { return kTypeIndex_WaylandWindow; }
  wl_display* display() const { return display_; }
  wl_surface* surface() const { return surface_; }

  void OnSizeUpdate(uint32_t width, uint32_t height);

 protected:
  bool GetSizeImpl(uint32_t& width_out, uint32_t& height_out) const override;

 private:
  wl_display* display_;
  wl_surface* surface_;
  std::atomic<uint32_t> width_;
  std::atomic<uint32_t> height_;
};

}  // namespace ui
}  // namespace xe

#endif  // XENIA_UI_SURFACE_GNULINUX_WAYLAND_H_
