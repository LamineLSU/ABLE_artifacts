rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        condition = "any of them"

    strings:
        $pattern0 = { 85 C0 0F 84 E8 ?? FF 0C ?? ED ?? }
        $pattern1 = { E8 ?? FF 0C ?? 83 C4 00 00 8B 45 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    action:
        skip
}