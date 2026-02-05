rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF 59 FF 75 08 }  // Trace 1: Skipping call 0040E7C3h (17 bytes)
        $pattern1 = { 8B FF 55 8B EC FF 75 08 FF 15 AC B0 41 00 } // Trace 2: Skipping call dword ptr [0041B0ACh] (17 bytes)
        $pattern2 = { 8B FF 55 8B EC FF 75 08 FF 15 AC B0 41 00 59 } // Combining parts of both traces (19 bytes)

    condition:
        any of them
}