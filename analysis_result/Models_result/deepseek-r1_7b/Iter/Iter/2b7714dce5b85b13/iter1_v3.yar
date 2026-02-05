rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting multiple decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8BFF ?? 55 8BEC ?? FF7508 ?? FF15ACB04100 }
        $pattern1 = { E8C8 ?? FF7508 ?? FF153CE13501 FF1540E13501 }
        $pattern2 = { 8BFF ?? 55 8BEC ?? FF7508 ?? FF15ACB04100 }

    condition:
        any of them
}