rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } // Bypass Conditional Jump (00413CD1)
        $pattern1 = { FF 15 3C 51 8B CE E8 ?? ?? ?? ?? 85 C0 } // Bypass Function Call (00413D14)
        $pattern2 = { FF 15 48 54 48 8B CE E8 ?? ?? ?? ?? 85 C0 } // Bypass Environment Check (00413D31)

    condition:
        any of them
}