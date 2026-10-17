// The PNG resources from tools/render-assets.py: flags ("flag:ch") and icons
// ("icon:p2p"), loaded once and cached. Monochrome icons are white masks that
// Tinted() colours (e.g. with the panel text colour); drawing scales them with
// filtering, so the 2x artwork stays sharp at any font size.
#pragma once
#include <GraphicsDefs.h>
#include <Rect.h>
#include <string>

class BBitmap;
class BView;

namespace Icons {

const BBitmap* Get(const char* name);
const BBitmap* Tinted(const char* name, rgb_color color);
const BBitmap* Flag(const std::string& countryCode);

// Draws a bitmap into dest with alpha blending and bilinear filtering.
void Draw(BView* view, const BBitmap* bitmap, BRect dest);
// A flag with rounded corners (or a grey placeholder for unknown codes).
void DrawFlag(BView* view, const std::string& countryCode, BRect dest);
// Secure Core: the exit flag large at the top right, the entry flag small at
// the bottom left, as the GTK app draws them.
void DrawDoubleFlag(BView* view, const std::string& exitCode, const std::string& entryCode,
    BRect dest);

// UI scale relative to a 12-point plain font (1.0 at the default size).
float Scale();
// Lightness of a colour, 0..255.
int Brightness(rgb_color color);
rgb_color Mix(rgb_color a, rgb_color b, float amount);

}  // namespace Icons
