/*
 * Auto-generated display-mode plists pushed to the guest IOMFB via the
 * setDCPAVPropStart/Chunk/End (D126/D127/D128) DCP->AP property callbacks.
 * Bare XML plists consumed by OSUnserializeXML; a 1024x768@60 TimingElements
 * array (one RGB/8-bit/SDR ColorMode, PreciseSyncRate 60<<16) and a
 * DisplayAttributes dict (physical size mm).  See modern-dcp-iop.c MODES.
 */
#ifndef HW_ARM_APPLE_SILICON_DCP_AV_MODES_H
#define HW_ARM_APPLE_SILICON_DCP_AV_MODES_H

static const char dcp_av_timing_xml[] =
    "<array><dict><key>ID</key><integer>1</integer><key>HorizontalAttributes</key><dict><key>Active</key><integer>1024</integer><key>Total</key><integer>1344</integer><key>FrontPorch</key><integer>24</integer><key>SyncWidth</key><integer>136</integer><key>PreciseSyncRate</key><integer>3169320960</integer></dict><key>VerticalAttributes</key><dict><key>Active</key><integer>768</integer><key>Total</key><integer>806</integer><key>FrontPorch</key><integer>3</integer><key>SyncWidth</key><integer>6</integer><key>PreciseSyncRate</key><integer>3932160</integer></dict><key>ColorModes</key><array><dict><key>ID</key><integer>1</integer><key>EOTF</key><integer>0</integer><key>PixelEncoding</key><integer>0</integer><key>Colorimetry</key><integer>16</integer><key>DynamicRange</key><integer>0</integer><key>Depth</key><integer>8</integer><key>Score</key><integer>100</integer><key>IsVirtual</key><false/></dict></array><key>Score</key><integer>100</integer><key>IsVirtual</key><false/></dict></array>";

static const char dcp_av_display_attrs_xml[] =
    "<dict><key>MaxHorizontalImageSize</key><integer>200</integer><key>MaxVerticalImageSize</key><integer>150</integer></dict>";

/*
 * ProductAttributes dict (DCP copyProductAttributes/retrieveProductAttributes).
 * Keys recovered from BootKC a36b9241 cstrings (ProductName/Name/DeviceName/
 * ProductID/ManufacturerID/LegacyManufacturerID/SerialNumber/Year/Week).
 * CoreDisplay maps Name/ProductName -> kCADisplayName and DeviceName ->
 * kCADisplayDeviceName; +[CADisplay mainDisplay] keeps the reply dict only when
 * BOTH are non-null (Grok mainDisplay predicate 0x1e7025308). The MODES push
 * supplied only DisplayAttributes (physical size), leaving both name keys null,
 * so the display was never minted.  Apple EDID manufacturer id "APP"/0x0610.
 */
static const char dcp_av_product_attrs_xml[] =
    "<dict><key>Name</key><string>Built-in Display</string>"
    "<key>ProductName</key><string>Built-in Display</string>"
    "<key>DeviceName</key><string>Built-in Display</string>"
    "<key>ManufacturerID</key><string>APP</string>"
    "<key>LegacyManufacturerID</key><integer>1552</integer>"
    "<key>ProductID</key><integer>1</integer>"
    "<key>SerialNumber</key><integer>0</integer>"
    "<key>YearOfManufacture</key><integer>2026</integer>"
    "<key>WeekOfManufacture</key><integer>1</integer></dict>";

#endif
