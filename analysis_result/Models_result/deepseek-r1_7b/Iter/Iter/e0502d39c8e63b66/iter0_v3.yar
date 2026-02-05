rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C4 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83C4 ?? 85C0 0F84 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85C0 }

    condition:
        any of them
}