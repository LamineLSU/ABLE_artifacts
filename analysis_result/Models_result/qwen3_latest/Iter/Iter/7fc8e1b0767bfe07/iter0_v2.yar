rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 FF FF 15 ?? ?? ?? ?? 8B C7 }
        $pattern1 = { 74 ?? 6A 5B 5A 8B CE }
        $pattern2 = { 8B 4D ?? E8 ?? ?? ?? ?? 8B 43 ?? }

    condition:
        all of them
}