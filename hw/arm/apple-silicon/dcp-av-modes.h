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

#endif
