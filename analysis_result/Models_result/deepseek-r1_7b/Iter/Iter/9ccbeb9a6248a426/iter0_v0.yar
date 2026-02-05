rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 5A 8B CE E8 FF ?? 33 DB BA 21 05 00 00 53 53 68 40 11 F2 00 5D 5D E8 4B 17 00 00 ?? ?? A1 88 85 F2 00 FF FF }
        
        $pattern1 = { 8B EC 5A 8B CE E8 FF 33 DB BA 21 05 00 00 53 6A 40 53 68 40 11 C1 01 ?? ?? E8 4B 17 00 00 ?? ?? A1 88 85 F2 00 FF FF }
        
        $pattern2 = { 8B EC 5A 8B CE E8 FF 33 DB BA 21 05 00 00 53 68 40 11 C1 00 ?? ?? }
    condition:
        any of them
}