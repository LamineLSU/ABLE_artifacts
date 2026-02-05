rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection rules"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 5A 8B 45 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5B 74 12 E8 CE ?? ?? ?? ?? E8 CE ?? }
        $pattern2 = { 8B E5 5D 40 EB 40 ?? ?? ?? ?? EB 40 ?? }

    condition:
        any of them
}