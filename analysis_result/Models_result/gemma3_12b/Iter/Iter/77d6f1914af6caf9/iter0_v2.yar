rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 E8 E8 ?? ?? ?? ?? }
        $pattern1 = { 85 C0 75 07 57 6A 40 57 BE ?? ?? ?? ?? 57 }
        $pattern2 = { 50 FF 15 ?? ?? ?? 85 C0 75 07 57 6A 04 57 }

    condition:
        any of them
}