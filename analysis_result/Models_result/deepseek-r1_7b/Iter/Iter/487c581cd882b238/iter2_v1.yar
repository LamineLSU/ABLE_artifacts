rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting memory displacement calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 0F84 ?? ?? ?? ?? 8B45 }
        $pattern1 = { E8C8 ?? ?? ?? ?? 15ACB04100 }
        $pattern2 = { A9BE ?? ?? ?? ?? FF1540E1F900 }

    condition:
        any of them
}