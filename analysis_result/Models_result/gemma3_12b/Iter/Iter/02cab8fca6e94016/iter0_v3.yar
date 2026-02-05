rule Bypass_Sample_Pattern1
{
    meta:
        description = "Bypass check at 0040E7F6"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 55 8B EC E8 C8 FF FF FF FF 59 FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}