rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using identified trace patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { ?? EC 7C ?? EC 3F ?? EC FF ?? EC 6A ?? EC FF ?? EC CC ?? EC F8 }
        $pattern2 = { E8 0D 01 00 00 ?? ?? 0F 84 }

    condition:
        any of them
}