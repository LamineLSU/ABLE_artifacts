rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection using specific instruction patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 5A 8B CE E8 25 05 00 04 9D 61 B0 }  // 11 bytes
        $pattern1 = { FF 15 88 A1 8B E5 F0 F7 FB 8C FF 15 2C A1 8B E5 }  // 12 bytes
        $pattern2 = { E8 4B 36 79 FF 15 3C E1 FF ED 6E 2C }  // 11 bytes

    condition:
        any of the patterns match exactly before calling ExitProcess
}