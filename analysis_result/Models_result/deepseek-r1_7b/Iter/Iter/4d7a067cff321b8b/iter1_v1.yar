rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8BFF E8 ?? ?? ?? ?? 59 FF7508 E8C8FFFFFF 59 FF7508 }
        $pattern1 = { 6A5A 8BEC 00E8 C8F3 FF7508 E8C8FFFFFF 59 FF7508 FF15ACB04100 }
        $pattern2 = { E8EC ?? ?? ?? ?? 8BFF 55 FF7508 E8C8FFFFFF 59 FF7508 FF15ACB04100 }

    condition:
        any of them
}