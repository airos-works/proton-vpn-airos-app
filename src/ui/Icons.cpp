#include "Icons.h"
#include <Application.h>
#include <Bitmap.h>
#include <DataIO.h>
#include <Font.h>
#include <Resources.h>
#include <Roster.h>
#include <TranslationUtils.h>
#include <View.h>
#include <map>
#include <mutex>

namespace {

std::mutex sLock;
std::map<std::string, BBitmap*> sBitmaps;     // by resource name
std::map<std::string, BBitmap*> sTinted;      // name + colour

BBitmap* Load(const std::string& name)
{
    BResources* resources = be_app != nullptr ? be_app->AppResources() : nullptr;
    if (resources == nullptr)
        return nullptr;
    size_t size = 0;
    const void* data = resources->LoadResource('PNG ', name.c_str(), &size);
    if (data == nullptr || size == 0)
        return nullptr;
    BMemoryIO io(data, size);
    BBitmap* bitmap = BTranslationUtils::GetBitmap(&io);
    if (bitmap != nullptr && bitmap->ColorSpace() != B_RGBA32) {
        BBitmap* converted = new BBitmap(bitmap->Bounds(), B_RGBA32);
        converted->ImportBits(bitmap);
        delete bitmap;
        bitmap = converted;
    }
    return bitmap;
}

const BBitmap* Cached(const std::string& name)
{
    std::lock_guard<std::mutex> lock(sLock);
    auto it = sBitmaps.find(name);
    if (it != sBitmaps.end())
        return it->second;
    BBitmap* bitmap = Load(name);
    sBitmaps[name] = bitmap;
    return bitmap;
}

}  // namespace


namespace Icons {

const BBitmap* Get(const char* name)
{
    return Cached(std::string("icon:") + name);
}


const BBitmap* Tinted(const char* name, rgb_color color)
{
    char key[96];
    snprintf(key, sizeof(key), "%s/%02x%02x%02x", name, color.red, color.green, color.blue);
    {
        std::lock_guard<std::mutex> lock(sLock);
        auto it = sTinted.find(key);
        if (it != sTinted.end())
            return it->second;
    }
    const BBitmap* mask = Get(name);
    if (mask == nullptr)
        return nullptr;
    BBitmap* tinted = new BBitmap(mask->Bounds(), B_RGBA32);
    const uint8* source = (const uint8*)mask->Bits();
    uint8* target = (uint8*)tinted->Bits();
    int32 length = mask->BitsLength();
    for (int32 i = 0; i + 3 < length; i += 4) {
        // B_RGBA32 is BGRA in memory.
        target[i] = color.blue;
        target[i + 1] = color.green;
        target[i + 2] = color.red;
        target[i + 3] = source[i + 3];
    }
    std::lock_guard<std::mutex> lock(sLock);
    sTinted[key] = tinted;
    return tinted;
}


const BBitmap* Flag(const std::string& countryCode)
{
    std::string code;
    for (char c : countryCode)
        code += (char)tolower((unsigned char)c);
    return Cached("flag:" + code);
}


void Draw(BView* view, const BBitmap* bitmap, BRect dest)
{
    if (bitmap == nullptr)
        return;
    drawing_mode mode = view->DrawingMode();
    view->SetDrawingMode(B_OP_ALPHA);
    view->SetBlendingMode(B_PIXEL_ALPHA, B_ALPHA_OVERLAY);
    view->DrawBitmap(bitmap, bitmap->Bounds(), dest, B_FILTER_BITMAP_BILINEAR);
    view->SetDrawingMode(mode);
}


void DrawFlag(BView* view, const std::string& countryCode, BRect dest)
{
    const BBitmap* flag = Flag(countryCode);
    if (flag != nullptr) {
        Draw(view, flag, dest);
        return;
    }
    rgb_color high = view->HighColor();
    view->SetHighColor(Mix(view->LowColor(), make_color(128, 128, 128), 0.5f));
    view->FillRoundRect(dest, 2, 2);
    view->SetHighColor(high);
}


void DrawDoubleFlag(BView* view, const std::string& exitCode, const std::string& entryCode,
    BRect dest)
{
    // As icons.py: the exit flag 2/3 wide at the top right, the entry flag
    // 1/2 wide at the bottom left, outlined in the background colour.
    float width = dest.Width() + 1, height = dest.Height() + 1;
    BRect exit(dest.right - width * 0.75f + 1, dest.top, dest.right, dest.top + height * 0.75f - 1);
    BRect entry(dest.left, dest.bottom - height * 0.5f + 1, dest.left + width * 0.5f - 1, dest.bottom);
    DrawFlag(view, exitCode, exit);
    rgb_color high = view->HighColor();
    view->SetHighColor(view->LowColor());
    BRect outline = entry.InsetByCopy(-1, -1);
    view->FillRoundRect(outline, 2, 2);
    view->SetHighColor(high);
    DrawFlag(view, entryCode, entry);
}


float Scale()
{
    return be_plain_font->Size() / 12.0f;
}


int Brightness(rgb_color color)
{
    return (color.red * 299 + color.green * 587 + color.blue * 114) / 1000;
}


rgb_color Mix(rgb_color a, rgb_color b, float amount)
{
    rgb_color result;
    result.red = (uint8)(a.red + (b.red - a.red) * amount);
    result.green = (uint8)(a.green + (b.green - a.green) * amount);
    result.blue = (uint8)(a.blue + (b.blue - a.blue) * amount);
    result.alpha = 255;
    return result;
}

}  // namespace Icons
