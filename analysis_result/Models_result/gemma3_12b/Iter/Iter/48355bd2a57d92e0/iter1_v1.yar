rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 5D C8 8B 4D C4 8B 7D C0 6A FF 6A 01 51 57 FF 15 50 A0 B8 00 }
        $pattern1 = { 8B 45 C4 8B F3 2B C3 89 45 C0 8B D8 FF 34 1E FF 15 7C A0 B8 00 }
        $pattern2 = { 8B FF 55 8B EC E8 6A 3E 00 00 84 C0 74 20 64 A1 30 00 00 8B 40 68 }

    condition:
        any of them
}