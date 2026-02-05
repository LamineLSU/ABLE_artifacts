rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit decision logic"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { FF 3A 6E 74 FE ?? C9 A2 0C FF 3A 68 D4 FF 75 C8 00 D9 D9 F7 FF E9 7F 7D CC ?? ?? }
        $pattern2 = { 5A 5E 01 0B FC 8B ED 81 CA FF B3 AE 73 6C 4C 0D FE }

    condition:
        any of them
}