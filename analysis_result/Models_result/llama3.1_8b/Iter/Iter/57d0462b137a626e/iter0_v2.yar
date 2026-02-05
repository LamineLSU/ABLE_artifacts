rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? FF 15 2C 11 60 E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 C8 FF FF FF 55 8B EC FF 75 08 E8 ?? ?? ?? ?? FF 15 AC B0 41 00 }
        $pattern2 = { FF 15 8C CE 12 B0 50 E8 ?? ?? ?? ?? 59 FF 75 08 E8 ?? ?? ?? ?? FF 15 8C CE 12 B0 }

    condition:
        any of them
}