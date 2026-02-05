rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - multiple specific test+je/jmp patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B 45 FC }
        $pattern1 = { 85 C0 74 12 6A 5B 5A E8 4B 17 00 00 }
        $pattern2 = { 85 C0 74 12 6A 5B 5A FF 15 2C A1 E2 00 }

    condition:
        any of them
}