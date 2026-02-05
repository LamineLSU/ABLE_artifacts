rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 59 FF 75 08 FF 15 AC B0 41 00 }  // 12 bytes
        $pattern1 = { 8B EC FF 75 08 59 FF 75 08 FF 15 AC B0 41 00 5A }  // 13 bytes
        $pattern2 = { 59 FF 75 08 FF 15 AC B0 41 00 5A }  // 6 bytes

    condition:
        any of them
}