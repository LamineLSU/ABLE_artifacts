rule Bypass_Sample
{
    meta:
        description = "Evasion bypass through conditional jumps and calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 0F 85 ?? ?? ?? ?? 6A 5B 5A 8B CE ?? ?? ?? }
        $pattern1 = { E8 FF 0F 85 74 07 0F 85 6A 40 ?? 53 53 ?? ?? ?? FF 15 AC B0 41 00 }
        $pattern2 = { 8B EC 74 12 FF 75 08 8B CE 0F 84 ?? ?? ?? 85 C0 FF 75 08 FF 15 3C E1 2C 00 }

    condition:
        any of them
}