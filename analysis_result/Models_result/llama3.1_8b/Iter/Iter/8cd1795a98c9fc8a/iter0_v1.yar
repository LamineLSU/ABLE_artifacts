rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 74 20 85 C0 0F 84 ?? ?? ?? ?? E8 F7 25 00 00 }
        $pattern1 = { 20 FF EE CE A8 01 8B 45 ?? FF 15 A0 F1 42 00 }
        $pattern2 = { 20 FF EE CE FF 15 CF 14 20 00 50 FF 35 C0 F1 42 00 }

    condition:
        any of them
}