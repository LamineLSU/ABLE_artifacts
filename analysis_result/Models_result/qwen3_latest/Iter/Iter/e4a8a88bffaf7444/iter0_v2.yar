rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 E8 ?? ?? ?? ?? 33 C0 }
        $pattern1 = { 5A E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? }
        $pattern2 = { BA CC F6 88 ?? E8 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? }

    condition:
        any of them
}