rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF 59 FF 75 08 }  // Skip first call (11 bytes)
        $pattern1 = { 8B FF 55 8B EC FF 75 08 59 FF 75 08 FF 15 1C E0 40 00 } // Skip second call (16 bytes)
        $pattern2 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF 59 FF 75 08 FF 75 08 } // Skip push before second call (14 bytes)

    condition:
        any of them
}