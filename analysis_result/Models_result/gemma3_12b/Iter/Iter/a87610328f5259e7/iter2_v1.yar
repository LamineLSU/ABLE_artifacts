rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 85 F0 FE FF FF }
        $pattern2 = { 8B CE E8 74 FA FF FF FF 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}