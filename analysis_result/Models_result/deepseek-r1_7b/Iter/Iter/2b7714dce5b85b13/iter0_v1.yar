rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules for different function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 8B EC E8 CE FF 75 00 00 00 30 8B 5E 5A }
        $pattern1 = { 6A 5B 8B EC E8 0D 5A 0F 84 8B 45 FF 75 00 00 00 40 5A 8B 5E }
        $pattern2 = { 8B FF EC 8B EC C1 E8 A8 01 FF 75 00 00 00 30 E8 CE FF 75 00 00 00 40 }

    condition:
        any of them
}