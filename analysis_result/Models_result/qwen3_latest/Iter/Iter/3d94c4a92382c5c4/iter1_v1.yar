rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? }
        $pattern1 = { FF D3 FE 06 83 FE 1A 0F 8C 79 FF FF FF }
        $pattern2 = { 6A 00 6A 00 6A 00 68 ?? ?? ?? ?? FF D6 }

    condition:
        any of them
}