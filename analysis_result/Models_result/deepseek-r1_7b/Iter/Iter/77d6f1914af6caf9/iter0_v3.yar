rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting memory accesses and calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 24 07 C0 FF 5C ?? ?? ?? ?? ?? }
        $pattern1 = { 8B 15 FC ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { E8 D0 2C 0F ?? ?? ?? ?? 85 C0 ?? ?? ?? }

    condition:
        any of them
}