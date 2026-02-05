rule Bypass_Sample_Trace1
{
    meta:
        description = "Evasion bypass rule - Trace 1"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 56 50 8B EC 83 EC ?? 53 56 57 33 F6 }
        $pattern2 = { 56 56 56 68 0C 80 E9 00 FF 15 00 50 E9 00 }

    condition:
        any of them
}