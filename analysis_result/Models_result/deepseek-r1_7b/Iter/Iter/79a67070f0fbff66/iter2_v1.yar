rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific anti-virus checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 FF 15 9C 50 61 00 E8 8D 9A FF FF }
        $pattern1 = { 8B 55 C4 83 C0 01 89 45 C4 C7 45 C4 00 00 00 00 EB CD 8B 4D C4 52 FF 15 F0 50 61 00 }
        $pattern2 = { 83 C4 04 8B 45 E0 50 83 C4 04 FF 15 A4 50 61 00 EB CD 8B 4D C4 52 FF 15 F0 50 61 00 }
    condition:
        any of them
}