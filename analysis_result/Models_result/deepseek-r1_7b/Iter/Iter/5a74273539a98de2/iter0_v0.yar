rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting different code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE 85 C0 0F 84 E8 25 05 00 00 0E 8C 7F }
        $pattern1 = { 6A 5B 8B EC 8B 45 E8 CB 3F 8D E9 B5 FC FF 8E 4B 21 BA 05 68 40 EB 21 D0 7C DD 8C 17 }
        $pattern2 = { FF 15 AC B0 41 00 E8 C8 FF FF 15 AC B0 41 00 }
    condition:
        any of them
}