rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific test+JE patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 0E E8 43 1C 00 00 }
        $pattern1 = { 85 C0 74 0E E8 EE 82 FF FF }
        $pattern2 = { 85 C0 74 0E E8 B7 F7 FF FF }

    condition:
        any of them
}