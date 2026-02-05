rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting exit point E8D1C7"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 E9 ?? ?? ?? ?? }
        $pattern1 = { 74 ?? 0F ??. ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE ?? ?? ?? ?? }

    condition:
        any of them
}