rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 8B 4D FC 5F 5E 33 CD E8 57 26 00 00 }
        $pattern2 = { 8B 4D FC 5F 5E 33 CD 5B }

    condition:
        any of them
}