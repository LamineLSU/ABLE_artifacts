rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting memory calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B ?? 5A E8 ?? CE ?? FF FF FF 8B 45 ?? }
        $pattern1 = { E8 C8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 6A 40 ?? 11 ?? BA 21 ?? 00 0D ?? ?? ?? ?? FF 0A 12 }

    condition:
        any of them
}