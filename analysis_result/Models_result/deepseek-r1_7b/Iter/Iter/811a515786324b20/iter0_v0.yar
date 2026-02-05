rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C0 5A 33 C0 4F E8 B6 F9 FF 8D C0 3E FF 87 DD FF EA AA EC DE AC DA AD AC CE CC BE ED BA AC EC }
        $pattern1 = { 5A 4F 8B CA 26 FF E8 F0 FF 8D 85 FF FF FF FF EA AA EC DE AE EA AD AC CE CC BE ED BA AC EC }
        $pattern2 = { 3A 4F 8B CA FF FF E8 C6 FF FF 8D A7 FF FF FF FF EA AA EC DE CA EA ED FB AA DE CA AC }

    condition:
        any of them
}