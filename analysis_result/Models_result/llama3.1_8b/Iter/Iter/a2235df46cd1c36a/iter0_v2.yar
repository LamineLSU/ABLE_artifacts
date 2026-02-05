rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? FF 15 2C A1 06 00 }
        $pattern1 = { E8 C8 FF FF FF E8 ?? ?? ?? ?? 59 FF 75 08 }
        $pattern2 = { FF 15 8C CE 1B 30 00 FF 50 ?? FF 15 40 E1 B3 30 }

    condition:
        any of them
}