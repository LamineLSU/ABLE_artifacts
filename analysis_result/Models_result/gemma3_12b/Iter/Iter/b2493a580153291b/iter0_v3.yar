rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 17 D0 00 00 83 F8 01 74 20 }  // Skip Conditional Jump - 12 bytes
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 50 }  // Skip first function call - 12 bytes
        $pattern2 = { FF 75 08 E8 4F 00 00 00 59 FF 75 08 } // Skip second function call - 12 bytes

    condition:
        any of them
}