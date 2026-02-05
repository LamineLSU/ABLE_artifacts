rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted eversion and conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 7C 3F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 8D 85 EC FF FF FF EA EA DD EB 00 00 01 14 5B EB 8D 85 94 FE EE EA EA DD EB 00 00 01 6C }
        $pattern2 = { 3B FB ED EB 74 26 00 40 10 77 }

    condition:
        any of them
}