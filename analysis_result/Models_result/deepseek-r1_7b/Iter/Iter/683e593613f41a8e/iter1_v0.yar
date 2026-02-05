rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - checked multiple strategies and specific conditions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? ?? 74 12 01 21 61 90 }
        $pattern1 = { 8B 4D EC DD EB 04 5F ED E8 25 05 00 00 CA 01 21 8C 42 FF 15 88 A0 21 01 CA DD 01 21 A0 88 }
        $pattern2 = { 3D 00 EA 32 74 12 01 21 61 90 }
    condition:
        any of them
}